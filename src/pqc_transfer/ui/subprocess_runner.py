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
        try:
            self.stdscr.addstr(0, 0, f" {title} "[:w-1].ljust(w-1))
        except curses.error:
            pass
        self.stdscr.attroff(curses.color_pair(5) | curses.A_REVERSE | curses.A_BOLD)

        log_window = curses.newwin(h - 3, w, 1, 0)
        log_window.scrollok(True)

        try:
            footer = "[Press 'q' or ESC to stop/return | UP/DOWN/PgUp/PgDn to scroll]"
            self.stdscr.addstr(
                h - 1,
                0,
                footer[:w-1].ljust(w-1),
                curses.A_REVERSE,
            )
        except curses.error:
            pass
        self.stdscr.refresh()

        q = queue.Queue()

        def reader_thread(proc):
            for line in iter(proc.stdout.readline, b""):
                q.put(line.decode("utf-8", errors="replace"))
            proc.stdout.close()
            q.put(None)

        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
        )

        t = threading.Thread(target=reader_thread, args=(process,))
        t.daemon = True
        t.start()

        self.stdscr.nodelay(True)
        running = True
        process_alive = True
        logs = []
        scroll_offset = 0

        while running:
            needs_redraw = False
            
            if process_alive:
                while True:
                    try:
                        line = q.get_nowait()
                        if line is None:
                            process_alive = False
                            logs.append("\n--- Process Finished ---")
                            needs_redraw = True
                            
                            try:
                                footer_ended = "[Process Ended. Press 'q' or ESC to return | UP/DOWN/PgUp/PgDn to scroll]"
                                self.stdscr.addstr(
                                    h - 1,
                                    0,
                                    footer_ended[:w-1].ljust(w-1),
                                    curses.A_REVERSE,
                                )
                            except curses.error:
                                pass
                            self.stdscr.refresh()
                            break
                        clean_line = ansi_escape.sub("", line).strip()
                        if clean_line:
                            logs.append(clean_line)
                            needs_redraw = True
                    except queue.Empty:
                        break

            key = self.stdscr.getch()
            if key != -1:
                if key in [ord("q"), ord("Q"), 27]:
                    running = False
                    break
                elif key == curses.KEY_UP:
                    scroll_offset += 1
                    needs_redraw = True
                elif key == curses.KEY_DOWN:
                    scroll_offset -= 1
                    needs_redraw = True
                elif key == curses.KEY_PPAGE:
                    scroll_offset += (h - 4)
                    needs_redraw = True
                elif key == curses.KEY_NPAGE:
                    scroll_offset -= (h - 4)
                    needs_redraw = True
                elif key == curses.KEY_RESIZE:
                    if hasattr(curses, "update_lines_cols"):
                        curses.update_lines_cols()
                    h, w = self.stdscr.getmaxyx()
                    try:
                        if h > 3 and w > 0:
                            log_window.resize(h - 3, w)
                    except curses.error:
                        pass
                    
                    self.stdscr.clear()
                    self.stdscr.attron(curses.color_pair(5) | curses.A_REVERSE | curses.A_BOLD)
                    try:
                        self.stdscr.addstr(0, 0, f" {title} "[:w-1].ljust(w-1))
                    except curses.error:
                        pass
                    self.stdscr.attroff(curses.color_pair(5) | curses.A_REVERSE | curses.A_BOLD)

                    try:
                        if not process_alive:
                            footer_text = "[Process Ended. Press 'q' or ESC to return | UP/DOWN/PgUp/PgDn to scroll]"
                        else:
                            footer_text = "[Press 'q' or ESC to stop/return | UP/DOWN/PgUp/PgDn to scroll]"
                        self.stdscr.addstr(
                            h - 1,
                            0,
                            footer_text[:w-1].ljust(w-1),
                            curses.A_REVERSE,
                        )
                    except curses.error:
                        pass
                    self.stdscr.refresh()
                    needs_redraw = True

            max_scroll = max(0, len(logs) - (h - 4))
            if scroll_offset > max_scroll:
                scroll_offset = max_scroll
            if scroll_offset < 0:
                scroll_offset = 0

            if needs_redraw:
                log_window.clear()
                visible_lines = h - 4
                if scroll_offset == 0:
                    display_logs = logs[-visible_lines:] if logs else []
                else:
                    start_idx = max(0, len(logs) - visible_lines - scroll_offset)
                    end_idx = start_idx + visible_lines
                    display_logs = logs[start_idx:end_idx]

                for i, log_line in enumerate(display_logs):
                    color = 0
                    if "[PASS]" in log_line or "[RESULT]" in log_line:
                        color = curses.color_pair(2)
                    elif "[ERROR]" in log_line or "[FAIL]" in log_line:
                        color = curses.color_pair(3)
                    elif "[WARN]" in log_line:
                        color = curses.color_pair(4)

                    try:
                        log_window.addstr(i, 0, log_line[: w - 1], color)
                    except curses.error:
                        pass
                log_window.refresh()

            curses.napms(50)


        self.stdscr.nodelay(False)
        if process.poll() is None:
            process.terminate()
        process.wait()
