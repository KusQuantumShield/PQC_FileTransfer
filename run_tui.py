import curses
import os
import subprocess
import sys
import threading
import queue

# TUI(Terminal User Interface) 기반 애플리케이션 클래스
# 사용자가 터미널 환경에서 방향키와 엔터를 사용하여 손쉽게 서버/클라이언트를 실행할 수 있게 합니다.
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

    def file_picker(self, start_path="."):
        """
        터미널 내에서 구동되는 간단한 파일 선택기(File Picker) 화면입니다.
        클라이언트에서 서버로 전송할 파일을 방향키로 찾아 선택할 수 있게 합니다.
        
        Args:
            start_path (str): 파일 탐색을 시작할 초기 디렉토리 경로 (기본값: 현재 디렉토리)
            
        Returns:
            str or None: 사용자가 선택한 파일의 절대 경로. 취소(ESC) 시 None 반환.
        """
        current_dir = os.path.abspath(start_path)
        current_idx = 0
        
        while True:
            self.stdscr.clear()
            h, w = self.stdscr.getmaxyx()
            
            # 현재 디렉토리의 파일 및 폴더 목록 가져오기
            try:
                # 상위 디렉토리로 이동하는 항목("..")을 최상단에 추가
                items = [".. (Parent Directory)"] + sorted(os.listdir(current_dir))
            except PermissionError:
                # 권한이 없는 디렉토리 접근 시 상위 이동만 가능하도록 처리
                items = [".. (Parent Directory)"]
                
            # 타이틀 출력
            title = f" Select File to Send "
            self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
            self.stdscr.addstr(1, max(0, w//2 - len(title)//2), title)
            self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
            
            # 현재 탐색 중인 경로 표시
            path_str = f"Dir: {current_dir}"
            self.stdscr.addstr(3, max(0, w//2 - len(path_str)//2), path_str[:w-1], curses.A_BOLD)
            
            # 화면 크기에 맞춰 스크롤 처리 로직 구현 (목록이 화면보다 길 경우 대비)
            max_rows = h - 8
            start_row = max(0, current_idx - max_rows // 2)
            end_row = min(len(items), start_row + max_rows)
            
            # 목록 아이템들 화면에 렌더링
            for i, item in enumerate(items[start_row:end_row]):
                y = 5 + i
                # 실제 시스템 상의 절대 경로 조합
                full_path = os.path.join(current_dir, item) if item != ".. (Parent Directory)" else os.path.dirname(current_dir)
                
                # 디렉토리인지 파일인지 구분하기 위한 아이콘 추가
                display = item
                if os.path.isdir(full_path):
                    display = "📁 " + display
                else:
                    display = "📄 " + display
                    
                display = display[:w-4] # 화면 너비를 초과하지 않도록 자름
                x = max(0, w//2 - 20)
                
                # 현재 커서가 위치한 항목 강조 표시
                if start_row + i == current_idx:
                    self.stdscr.attron(curses.color_pair(1))
                    self.stdscr.addstr(y, x, display)
                    self.stdscr.attroff(curses.color_pair(1))
                else:
                    self.stdscr.addstr(y, x, display)
                    
            # 하단 조작 안내 (ESC 취소, ENTER 선택)
            footer = "[ESC] Cancel  [ENTER] Select"
            self.stdscr.addstr(h - 2, max(0, w//2 - len(footer)//2), footer, curses.A_DIM)
            self.stdscr.refresh()
            
            key = self.stdscr.getch()
            # 위쪽 방향키: 이전 항목으로 이동
            if key == curses.KEY_UP and current_idx > 0:
                current_idx -= 1
            # 아래쪽 방향키: 다음 항목으로 이동
            elif key == curses.KEY_DOWN and current_idx < len(items) - 1:
                current_idx += 1
            # 엔터키: 선택 액션
            elif key == ord('\n'):
                selected = items[current_idx]
                if selected == ".. (Parent Directory)":
                    # 상위 폴더로 이동
                    current_dir = os.path.dirname(current_dir)
                    current_idx = 0
                else:
                    target = os.path.join(current_dir, selected)
                    if os.path.isdir(target):
                        # 선택한 대상이 폴더일 경우 해당 폴더로 진입
                        current_dir = target
                        current_idx = 0
                    else:
                        # 선택한 대상이 일반 파일일 경우 경로 반환
                        return target
            # ESC 키: 취소 및 빠져나가기
            elif key == 27: # ESC
                return None

    def run_subprocess_ui(self, cmd_args, title):
        """
        서브프로세스(서버, 클라이언트 등)를 실행하고 그 출력 로그를 실시간으로 터미널에 렌더링하는 함수입니다.
        별도의 스레드를 사용하여 프로세스의 stdout(표준 출력)을 Non-blocking 방식으로 읽어 화면에 표시합니다.
        
        Args:
            cmd_args (list): 실행할 명령어 및 인자 리스트 (예: [sys.executable, "run_server.py"])
            title (str): 출력 창 상단에 표시될 프로세스 제목
        """
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        # 상단 타이틀 바 렌더링
        self.stdscr.attron(curses.color_pair(5) | curses.A_REVERSE | curses.A_BOLD)
        self.stdscr.addstr(0, 0, f" {title} ".ljust(w))
        self.stdscr.attroff(curses.color_pair(5) | curses.A_REVERSE | curses.A_BOLD)
        
        # 로그가 출력될 스크롤 가능한 새로운 curses 창(window) 생성
        log_window = curses.newwin(h - 3, w, 1, 0)
        log_window.scrollok(True) # 화면 넘침 시 자동 스크롤 허용
        
        # 하단 종료 안내 바 렌더링
        self.stdscr.addstr(h - 1, 0, "[Press 'q' or ESC to stop/return]".ljust(w - 1), curses.A_REVERSE)
        self.stdscr.refresh()
        
        # 스레드와 메인 루프 간 데이터(로그)를 안전하게 전달하기 위한 큐(Queue)
        q = queue.Queue()
        
        # 프로세스 출력을 실시간으로 읽어 큐에 넣는 백그라운드 스레드 함수
        def reader_thread(proc):
            # 프로세스의 표준 출력을 줄 단위로 읽기 (이터레이터 활용)
            for line in iter(proc.stdout.readline, b''):
                q.put(line.decode('utf-8', errors='replace')) # 깨진 문자열 처리(replace)
            proc.stdout.close()
            q.put(None) # 프로세스 종료(EOF)를 알리는 신호 전송

        # 원본 스크립트 출력에 포함된 터미널 색상용 ANSI 이스케이프 문자를 제거하기 위한 정규 표현식 (curses 내 출력 문제 방지)
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        # 서브프로세스의 출력이 버퍼링되지 않도록 환경 변수(PYTHONUNBUFFERED) 강제 설정
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        # 대상 스크립트를 자식 프로세스로 실행 (stderr를 stdout으로 리다이렉트)
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, # 사용자 입력 대기로 인해 프로세스가 멈추는 것 방지
            env=env
        )
        
        # 읽기 스레드 시작 (데몬으로 설정하여 메인 프로그램 종료 시 함께 종료되도록 함)
        t = threading.Thread(target=reader_thread, args=(process,))
        t.daemon = True
        t.start()
        
        # 사용자 입력을 Non-blocking(지연 없음) 모드로 설정
        self.stdscr.nodelay(True)
        running = True
        logs = []
        
        while running:
            lines_added = False
            # [UI 최적화] 큐에 쌓인 로그를 한 번에 모두 읽은 뒤 한 번만 화면을 갱신(Redraw)하도록 Batch 처리
            while True:
                try:
                    line = q.get_nowait()
                    if line is None:
                        # 프로세스가 정상적으로 끝남
                        running = False
                        logs.append("\n--- Process Finished ---")
                        lines_added = True
                        break
                    
                    # 가져온 로그 문자열 정제 (ANSI 코드 제거 및 공백 스트립)
                    clean_line = ansi_escape.sub('', line).strip()
                    if clean_line:
                        logs.append(clean_line)
                        lines_added = True
                except queue.Empty:
                    break
            
            if lines_added:
                # 전체 로그를 유지하면서 화면(창) 크기에 맞게 최근 로그들만 추려내어 표시
                log_window.clear()
                display_logs = logs[-(h-4):]
                for i, log_line in enumerate(display_logs):
                    color = 0
                    # 로그의 키워드에 따라 curses 색상 지정 (패스/결과 -> 녹색, 에러/실패 -> 적색, 경고 -> 황색)
                    if "[PASS]" in log_line or "[RESULT]" in log_line: color = curses.color_pair(2)
                    elif "[ERROR]" in log_line or "[FAIL]" in log_line: color = curses.color_pair(3)
                    elif "[WARN]" in log_line: color = curses.color_pair(4)
                    
                    try:
                        # 너비를 넘어가는 문자로 인해 발생하는 curses 에러 방어
                        log_window.addstr(i, 0, log_line[:w-1], color)
                    except curses.error:
                        pass
                # 변경된 로그 창 업데이트
                log_window.refresh()
                
            # 사용자 키보드 입력 체크
            key = self.stdscr.getch()
            # 'q', 'Q', 또는 ESC(27)를 누르면 강제 종료 진행
            if key in [ord('q'), ord('Q'), 27]:
                if process.poll() is None: # 아직 프로세스가 살아있다면
                    process.terminate()    # 프로세스 종료 요청
                break
                
            curses.napms(50) # CPU 과점유 방지를 위한 짧은 휴식(50ms)
            
        # 프로세스 종료 후 처리 (Blocking 모드로 복구)
        self.stdscr.nodelay(False)
        if process.poll() is None:
            process.terminate()
        process.wait() # 좀비 프로세스가 되지 않도록 완전히 종료될 때까지 대기
        
        # 하단 메시지 변경 및 키 입력 대기 (종료 상태 확인용)
        self.stdscr.addstr(h - 1, 0, "[Process Ended. Press any key to return]".ljust(w - 1), curses.A_REVERSE)
        self.stdscr.refresh()
        self.stdscr.getch()

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
                    # 1. Start PQC Server 선택: 서브프로세스로 run_server.py 실행
                    self.run_subprocess_ui([sys.executable, "run_server.py"], "PQC Server Logs")
                elif self.current_row == 1:
                    # 2. Start PQC Client 선택: 전송할 파일 선택 후 run_client.py 실행
                    file_to_send = self.file_picker()
                    if file_to_send:
                        # 선택된 파일 경로를 인자로 전달
                        self.run_subprocess_ui([sys.executable, "run_client.py", file_to_send], "PQC Client Logs")
                elif self.current_row == 2:
                    # 3. Run Benchmarks 선택: PQC 성능 벤치마크 스크립트 실행
                    self.run_subprocess_ui([sys.executable, "benchmarks/benchmark.py"], "Benchmark Logs")
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

if __name__ == "__main__":
    main()
