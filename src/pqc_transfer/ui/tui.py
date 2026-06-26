import curses
import os
import subprocess
import sys
import threading
import queue

class FilePicker:
    """
    터미널 내에서 구동되는 파일 선택기(File Picker) 컴포넌트입니다.
    클라이언트에서 서버로 전송할 파일을 방향키로 찾아 선택할 수 있게 합니다.
    """
    def __init__(self, stdscr):
        self.stdscr = stdscr

    def show(self, start_path="."):
        current_dir = os.path.abspath(start_path)
        current_idx = 0
        
        while True:
            self.stdscr.clear()
            h, w = self.stdscr.getmaxyx()
            
            try:
                items = [".. (Parent Directory)"] + sorted(os.listdir(current_dir))
            except PermissionError:
                items = [".. (Parent Directory)"]
                
            title = f" Select File to Send "
            self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
            self.stdscr.addstr(1, max(0, w//2 - len(title)//2), title)
            self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
            
            path_str = f"Dir: {current_dir}"
            self.stdscr.addstr(3, max(0, w//2 - len(path_str)//2), path_str[:w-1], curses.A_BOLD)
            
            max_rows = h - 8
            start_row = max(0, current_idx - max_rows // 2)
            end_row = min(len(items), start_row + max_rows)
            
            for i, item in enumerate(items[start_row:end_row]):
                y = 5 + i
                full_path = os.path.join(current_dir, item) if item != ".. (Parent Directory)" else os.path.dirname(current_dir)
                
                display = item
                if os.path.isdir(full_path):
                    display = "📁 " + display
                else:
                    display = "📄 " + display
                    
                display = display[:w-4]
                x = max(0, w//2 - 20)
                
                if start_row + i == current_idx:
                    self.stdscr.attron(curses.color_pair(1))
                    self.stdscr.addstr(y, x, display)
                    self.stdscr.attroff(curses.color_pair(1))
                else:
                    self.stdscr.addstr(y, x, display)
                    
            footer = "[ESC] Cancel  [ENTER] Select"
            self.stdscr.addstr(h - 2, max(0, w//2 - len(footer)//2), footer, curses.A_DIM)
            self.stdscr.refresh()
            
            key = self.stdscr.getch()
            if key == curses.KEY_UP and current_idx > 0:
                current_idx -= 1
            elif key == curses.KEY_DOWN and current_idx < len(items) - 1:
                current_idx += 1
            elif key == ord('\n'):
                selected = items[current_idx]
                if selected == ".. (Parent Directory)":
                    current_dir = os.path.dirname(current_dir)
                    current_idx = 0
                else:
                    target = os.path.join(current_dir, selected)
                    if os.path.isdir(target):
                        current_dir = target
                        current_idx = 0
                    else:
                        return target
            elif key == 27: # ESC
                return None


class SubprocessRunner:
    """
    서브프로세스를 실행하고 그 출력 로그를 실시간으로 터미널에 렌더링하는 UI 컴포넌트입니다.
    """
    def __init__(self, stdscr):
        self.stdscr = stdscr

    def run(self, cmd_args, title):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        self.stdscr.attron(curses.color_pair(5) | curses.A_REVERSE | curses.A_BOLD)
        self.stdscr.addstr(0, 0, f" {title} ".ljust(w))
        self.stdscr.attroff(curses.color_pair(5) | curses.A_REVERSE | curses.A_BOLD)
        
        log_window = curses.newwin(h - 3, w, 1, 0)
        log_window.scrollok(True)
        
        self.stdscr.addstr(h - 1, 0, "[Press 'q' or ESC to stop/return]".ljust(w - 1), curses.A_REVERSE)
        self.stdscr.refresh()
        
        q = queue.Queue()
        
        def reader_thread(proc):
            for line in iter(proc.stdout.readline, b''):
                q.put(line.decode('utf-8', errors='replace'))
            proc.stdout.close()
            q.put(None)

        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        env['PYTHONPATH'] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env
        )
        
        t = threading.Thread(target=reader_thread, args=(process,))
        t.daemon = True
        t.start()
        
        self.stdscr.nodelay(True)
        running = True
        logs = []
        
        while running:
            lines_added = False
            while True:
                try:
                    line = q.get_nowait()
                    if line is None:
                        running = False
                        logs.append("\n--- Process Finished ---")
                        lines_added = True
                        break
                    clean_line = ansi_escape.sub('', line).strip()
                    if clean_line:
                        logs.append(clean_line)
                        lines_added = True
                except queue.Empty:
                    break
            
            if lines_added:
                log_window.clear()
                display_logs = logs[-(h-4):]
                for i, log_line in enumerate(display_logs):
                    color = 0
                    if "[PASS]" in log_line or "[RESULT]" in log_line: color = curses.color_pair(2)
                    elif "[ERROR]" in log_line or "[FAIL]" in log_line: color = curses.color_pair(3)
                    elif "[WARN]" in log_line: color = curses.color_pair(4)
                    
                    try:
                        log_window.addstr(i, 0, log_line[:w-1], color)
                    except curses.error:
                        pass
                log_window.refresh()
                
            key = self.stdscr.getch()
            if key in [ord('q'), ord('Q'), 27]:
                if process.poll() is None:
                    process.terminate()
                break
                
            curses.napms(50)
            
        self.stdscr.nodelay(False)
        if process.poll() is None:
            process.terminate()
        process.wait()
        
        self.stdscr.addstr(h - 1, 0, "[Process Ended. Press any key to return]".ljust(w - 1), curses.A_REVERSE)
        self.stdscr.refresh()
        self.stdscr.getch()


# TUI(Terminal User Interface) 메인 컨트롤러 클래스
# 각각 분리된 UI 컴포넌트(FilePicker, SubprocessRunner)를 조합하여 메인 메뉴 이벤트 루프를 관리합니다.
class TUIApp:
    def __init__(self, stdscr):
        """
        TUIApp 객체 초기화
        curses 라이브러리를 사용하여 터미널 UI의 색상 쌍(Color Pair)과 기본 설정을 초기화합니다.
        
        Args:
            stdscr: curses에서 제공하는 표준 스크린 객체
        """
        self.stdscr = stdscr
        # 커서를 화면에서 숨김 처리하여 깔끔한 UI 제공
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        
        # UI 요소에 사용할 색상 조합 정의
        if curses.has_colors():
            try:
                curses.use_default_colors()
                curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN) # 선택된 메뉴 아이템 강조용
                curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK) # 성공 또는 완료 로그용
                curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)   # 에러 또는 실패 로그용
                curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK) # 경고 메시지용
                curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK) # 제목 및 헤더 텍스트용
            except curses.error:
                pass

        # 메인 화면에 표시될 메뉴 항목들
        self.menu_items = [
            "1. Start PQC Server",
            "2. Start PQC Client (Send File)",
            "3. Run Benchmarks",
            "4. Exit"
        ]
        # 현재 선택된 메뉴의 인덱스 (초기값: 0번째 항목)
        self.current_row = 0
        self.run()

    def draw_menu(self):
        """
        터미널 화면에 메인 메뉴 UI를 그립니다.
        화면 크기가 변경되거나 선택 항목이 바뀔 때마다 호출되어 화면을 갱신합니다.
        """
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx() # 현재 터미널의 높이(h)와 너비(w) 구하기
        
        # 메인 타이틀(Title) 출력
        title = " PQC File Transfer - Terminal UI "
        self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(2, max(0, w//2 - len(title)//2), title)
        self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
        
        # 서브 타이틀(Subtitle) 출력 (약간 흐리게)
        subtitle = "Secure Post-Quantum Cryptography File Transfer"
        self.stdscr.addstr(4, max(0, w//2 - len(subtitle)//2), subtitle, curses.A_DIM)

        # 메뉴 항목들 출력
        menu_y = h // 2 - len(self.menu_items) // 2 # 세로 중앙 정렬을 위한 시작 y좌표
        for idx, text in enumerate(self.menu_items):
            x = w // 2 - len(text) // 2 # 가로 중앙 정렬을 위한 x좌표
            y = menu_y + idx
            
            # 현재 선택된 항목일 경우 색상 반전 및 굵게 표시하여 강조
            if idx == self.current_row:
                self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                self.stdscr.addstr(y, x, text)
                self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            else:
                self.stdscr.addstr(y, x, text)
                
        # 하단 조작 안내 문구 (Footer) 출력
        footer = "Use UP/DOWN arrows to navigate and ENTER to select"
        self.stdscr.addstr(h - 2, max(0, w//2 - len(footer)//2), footer, curses.A_DIM)
        # 변경된 내용을 실제 터미널 화면에 반영
        self.stdscr.refresh()



    def run(self):
        """
        메인 메뉴의 이벤트 루프. 
        사용자의 키보드 입력을 처리하고, 선택한 메뉴에 따라 적절한 액션(서버 실행, 파일 전송, 벤치마크, 종료)을 수행합니다.
        """
        while True:
            # 매 루프마다 메뉴 화면 다시 그리기
            self.draw_menu()
            key = self.stdscr.getch()
            
            # 위쪽 방향키: 선택 항목 위로 이동
            if key == curses.KEY_UP and self.current_row > 0:
                self.current_row -= 1
            # 아래쪽 방향키: 선택 항목 아래로 이동
            elif key == curses.KEY_DOWN and self.current_row < len(self.menu_items) - 1:
                self.current_row += 1
            # 엔터키: 현재 항목 실행
            elif key == ord('\n'):
                if self.current_row == 0:
                    SubprocessRunner(self.stdscr).run([sys.executable, "-m", "pqc_transfer", "server"], "PQC Server Logs")
                elif self.current_row == 1:
                    file_to_send = FilePicker(self.stdscr).show()
                    if file_to_send:
                        SubprocessRunner(self.stdscr).run([sys.executable, "-m", "pqc_transfer", "client", file_to_send], "PQC Client Logs")
                elif self.current_row == 2:
                    SubprocessRunner(self.stdscr).run([sys.executable, "benchmarks/benchmark.py"], "Benchmark Logs")
                elif self.current_row == 3:
                    # 4. Exit 선택: 루프를 빠져나가 TUI 종료
                    break

def main():
    """
    TUI 애플리케이션 시작점(Entry Point).
    curses.wrapper를 사용하여 비정상 종료 시에도 터미널 상태를 원상 복구하도록 안전하게 실행합니다.
    """
    try:
        curses.wrapper(lambda stdscr: TUIApp(stdscr))
    except KeyboardInterrupt:
        # Ctrl+C 누름 시 조용히 종료 처리
        pass
    except Exception as e:
        # 그 외 치명적인 오류 발생 시 에러 메시지 출력
        print(f"Error launching TUI: {e}")
