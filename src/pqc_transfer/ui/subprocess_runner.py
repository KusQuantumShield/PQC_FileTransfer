import curses
import os
import subprocess
import threading
import queue
import re

class SubprocessRunner:
    """
    서브프로세스를 실행하고 그 출력 로그를 실시간으로 터미널에 렌더링하는 UI 컴포넌트입니다.
    """
    def __init__(self, stdscr):
        """
        SubprocessRunner 인스턴스를 초기화합니다.
        
        Args:
            stdscr: curses에서 제공하는 표준 스크린(window) 객체.
        """
        self.stdscr = stdscr

    def run(self, cmd_args: list[str], title: str) -> None:
        """
        주어진 명령어를 서브프로세스로 실행하고 터미널 UI에 실시간 로그를 렌더링합니다.
        
        백그라운드 스레드를 생성하여 서브프로세스의 stdout/stderr를 큐(Queue)로 읽어오며,
        사용자가 'q' 또는 'ESC' 키를 누르면 프로세스를 안전하게 종료하고 빠져나옵니다.
        
        Args:
            cmd_args (list[str]): 실행할 명령어 리스트 (예: ["python3", "-m", "pqc_transfer", "server"]).
            title (str): UI 상단에 표시될 프로세스 제목.
        """
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
