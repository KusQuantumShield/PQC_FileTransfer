import curses
import os

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
