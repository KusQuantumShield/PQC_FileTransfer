import curses
import sys
import os

from .file_picker import FilePicker
from .subprocess_runner import SubprocessRunner


class TUIApp:
    """
    TUI(Terminal User Interface) 메인 이벤트 컨트롤러 클래스입니다.

    각각 분리된 UI 컴포넌트(FilePicker, SubprocessRunner)를 조합하여
    메인 메뉴의 이벤트 루프(Event Loop)를 관리합니다.
    """

    def __init__(self, stdscr):
        """
        TUIApp 객체를 초기화하고 curses 색상 쌍(Color Pair) 등 터미널 기본 설정을 구성합니다.

        Args:
            stdscr: curses에서 제공하는 표준 스크린(window) 객체.
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
                curses.init_pair(
                    1, curses.COLOR_BLACK, curses.COLOR_CYAN
                )  # 선택된 메뉴 아이템 강조용
                curses.init_pair(
                    2, curses.COLOR_GREEN, curses.COLOR_BLACK
                )  # 성공 또는 완료 로그용
                curses.init_pair(
                    3, curses.COLOR_RED, curses.COLOR_BLACK
                )  # 에러 또는 실패 로그용
                curses.init_pair(
                    4, curses.COLOR_YELLOW, curses.COLOR_BLACK
                )  # 경고 메시지용
                curses.init_pair(
                    5, curses.COLOR_CYAN, curses.COLOR_BLACK
                )  # 제목 및 헤더 텍스트용
            except curses.error:
                pass

        # 메인 화면에 표시될 메뉴 항목들
        self.menu_items = [
            "1. Start PQC Server",
            "2. Start PQC Client (Send File)",
            "3. Run Benchmarks",
            "4. Exit",
        ]
        # 현재 선택된 메뉴의 인덱스 (초기값: 0번째 항목)
        self.current_row = 0
        self.run()

    def draw_menu(self) -> None:
        """
        터미널 화면에 메인 메뉴 UI 위젯을 렌더링합니다.

        화면 크기가 변경(Resize)되거나 사용자가 선택 항목을 바꿀 때마다 호출되어 화면을 갱신합니다.
        """
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()  # 현재 터미널의 높이(h)와 너비(w) 구하기

        # 메인 타이틀(Title) 출력
        title = " PQC File Transfer - Terminal UI "
        self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(2, max(0, w // 2 - len(title) // 2), title)
        self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD | curses.A_REVERSE)

        # 서브 타이틀(Subtitle) 출력 (약간 흐리게)
        subtitle = "Secure Post-Quantum Cryptography File Transfer"
        self.stdscr.addstr(
            4, max(0, w // 2 - len(subtitle) // 2), subtitle, curses.A_DIM
        )

        # 메뉴 항목들 출력
        menu_y = h // 2 - len(self.menu_items) // 2  # 세로 중앙 정렬을 위한 시작 y좌표
        for idx, text in enumerate(self.menu_items):
            x = w // 2 - len(text) // 2  # 가로 중앙 정렬을 위한 x좌표
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
        self.stdscr.addstr(
            h - 2, max(0, w // 2 - len(footer) // 2), footer, curses.A_DIM
        )
        # 변경된 내용을 실제 터미널 화면에 반영
        self.stdscr.refresh()

    def run(self) -> None:
        """
        TUI 메인 메뉴의 무한 이벤트 루프를 실행합니다.

        사용자의 키보드 입력(방향키, 엔터 등)을 처리하고 선택한 메뉴에 따라
        서버 실행, 파일 전송, 벤치마크, 종료 등의 적절한 액션을 트리거합니다.
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
            elif key == ord("\n"):
                if self.current_row == 0:
                    SubprocessRunner(self.stdscr).run(
                        [sys.executable, "-m", "pqc_transfer", "server"],
                        "PQC Server Logs",
                    )
                elif self.current_row == 1:
                    file_to_send = FilePicker(self.stdscr).show()
                    if file_to_send:
                        SubprocessRunner(self.stdscr).run(
                            [
                                sys.executable,
                                "-m",
                                "pqc_transfer",
                                "client",
                                file_to_send,
                            ],
                            "PQC Client Logs",
                        )
                elif self.current_row == 2:
                    project_root = os.path.abspath(
                        os.path.join(os.path.dirname(__file__), "..", "..", "..")
                    )
                    benchmark_path = os.path.join(
                        project_root, "benchmarks", "benchmark.py"
                    )
                    SubprocessRunner(self.stdscr).run(
                        [sys.executable, benchmark_path], "Benchmark Logs"
                    )
                elif self.current_row == 3:
                    # 4. Exit 선택: 루프를 빠져나가 TUI 종료
                    break


def main() -> None:
    """
    TUI 애플리케이션의 시작점(Entry Point) 함수입니다.

    `curses.wrapper`를 사용하여 비정상 종료 시에도 터미널 상태를 원상 복구하도록 안전하게 보호합니다.
    """
    try:
        curses.wrapper(lambda stdscr: TUIApp(stdscr))
    except KeyboardInterrupt:
        # Ctrl+C 누름 시 조용히 종료 처리
        pass
    except Exception as e:
        # 그 외 치명적인 오류 발생 시 에러 메시지 출력
        print(f"Error launching TUI: {e}")
