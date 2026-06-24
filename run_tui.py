import curses
import os
import subprocess
import sys
import threading
import queue

class TUIApp:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        curses.curs_set(0)
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN) # Menu highlight
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK) # Success logs
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)   # Error logs
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Warnings
        curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK) # Headers

        self.menu_items = [
            "1. Start PQC Server",
            "2. Start PQC Client (Send File)",
            "3. Run Benchmarks",
            "4. Exit"
        ]
        self.current_row = 0
        self.run()

    def draw_menu(self):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        # Draw Title
        title = " PQC File Transfer - Terminal UI "
        self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(2, max(0, w//2 - len(title)//2), title)
        self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
        
        subtitle = "Secure Post-Quantum Cryptography File Transfer"
        self.stdscr.addstr(4, max(0, w//2 - len(subtitle)//2), subtitle, curses.A_DIM)

        # Draw Menu
        menu_y = h // 2 - len(self.menu_items) // 2
        for idx, text in enumerate(self.menu_items):
            x = w // 2 - len(text) // 2
            y = menu_y + idx
            if idx == self.current_row:
                self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                self.stdscr.addstr(y, x, text)
                self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            else:
                self.stdscr.addstr(y, x, text)
                
        # Draw Footer
        footer = "Use UP/DOWN arrows to navigate and ENTER to select"
        self.stdscr.addstr(h - 2, max(0, w//2 - len(footer)//2), footer, curses.A_DIM)
        self.stdscr.refresh()

    def file_picker(self, start_path="."):
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

    def run_subprocess_ui(self, cmd_args, title):
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
            q.put(None) # EOF

        # ANSI 이스케이프 문자 제거용
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
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
            try:
                line = q.get_nowait()
                if line is None:
                    running = False
                    logs.append("\n--- Process Finished ---")
                    break
                
                clean_line = ansi_escape.sub('', line).strip()
                if clean_line:
                    logs.append(clean_line)
                    # 스크롤을 위해 마지막 화면 줄수만큼만 표시
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
            except queue.Empty:
                pass
                
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

    def run(self):
        while True:
            self.draw_menu()
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and self.current_row > 0:
                self.current_row -= 1
            elif key == curses.KEY_DOWN and self.current_row < len(self.menu_items) - 1:
                self.current_row += 1
            elif key == ord('\n'):
                if self.current_row == 0:
                    self.run_subprocess_ui([sys.executable, "run_server.py"], "PQC Server Logs")
                elif self.current_row == 1:
                    file_to_send = self.file_picker()
                    if file_to_send:
                        self.run_subprocess_ui([sys.executable, "run_client.py", file_to_send], "PQC Client Logs")
                elif self.current_row == 2:
                    self.run_subprocess_ui([sys.executable, "benchmarks/benchmark.py"], "Benchmark Logs")
                elif self.current_row == 3:
                    break

def main():
    try:
        curses.wrapper(lambda stdscr: TUIApp(stdscr))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error launching TUI: {e}")

if __name__ == "__main__":
    main()
