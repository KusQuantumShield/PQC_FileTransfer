import curses
import os
import subprocess
import threading
import queue

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
