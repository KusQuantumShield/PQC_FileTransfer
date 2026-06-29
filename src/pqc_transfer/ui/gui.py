import os
import sys

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox

    HAS_TKINTER = (
        "PYTEST_CURRENT_TEST" not in os.environ
    )  # 자동화 테스트 멈춤 현상을 방지하기 위해 테스트 중에는 GUI 팝업 비활성화
except ImportError:
    HAS_TKINTER = False

from ..utils.logger import log


def _get_tk_root():
    """
    tkinter 기본 창(root)을 화면 최상단에 띄우되 투명하게 숨기는 유틸리티 함수입니다.

    메인 윈도우 없이 팝업 다이얼로그(파일 선택창, 메시지 박스 등)만 깔끔하게 노출하기 위해 사용합니다.

    Returns:
        tk.Tk: 설정이 완료된 tkinter 루트 인스턴스.
    """
    root = tk.Tk()
    root.withdraw()  # 메인 윈도우 숨기기
    root.attributes(
        "-topmost", True
    )  # 생성되는 다이얼로그가 항상 다른 창 위에 표시되도록 설정
    return root


def _can_use_gui() -> bool:
    """
    현재 실행 환경에서 GUI(tkinter)를 렌더링할 수 있는지 판별합니다.

    Returns:
        bool: 사용 가능하면 True, 불가능(Headless 등)하면 False.
    """
    return HAS_TKINTER and (sys.platform == "win32" or bool(os.environ.get("DISPLAY")))


def select_file() -> str:
    """
    사용자가 전송할 파일을 OS 탐색기 다이얼로그를 통해 직접 선택할 수 있게 합니다.

    Returns:
        str: 사용자가 선택한 파일의 절대 경로. 취소했거나 GUI가 지원되지 않으면 빈 문자열("")을 반환합니다.
    """
    if not _can_use_gui():
        log(
            "ERROR",
            "GUI",
            "GUI 환경(tkinter)을 사용할 수 없습니다. 명령줄 인자를 사용하세요 (예: python3 client.py <파일명>)",
        )
        return ""

    root = _get_tk_root()
    file_path = filedialog.askopenfilename(
        title="전송할 파일 선택", filetypes=[("All Files", "*.*")]
    )
    root.destroy()
    return file_path


def select_save_directory(filename: str) -> str:
    """
    서버 측에서 수신된 파일을 저장할 폴더를 선택하는 탐색기 다이얼로그를 띄웁니다.

    GUI 환경이 아닌 경우(Headless 리눅스 서버 등)를 대비하여 예외 처리 로직이 내장되어 있습니다.

    Args:
        filename (str): 수신할 대상 파일의 이름 (사용자 안내용).

    Returns:
        str: 선택된 디렉토리의 경로. 취소했거나 GUI가 지원되지 않으면 빈 문자열("")을 반환합니다.
    """
    if not _can_use_gui():
        log("WARN", "GUI", "GUI 없음 모드: 기본 수신 폴더에 저장합니다.")
        return ""

    root = _get_tk_root()
    messagebox.showinfo(
        "저장 위치 선택", f"수신된 파일: {filename}\n저장할 폴더를 선택해 주세요."
    )
    folder = filedialog.askdirectory(title="파일 저장 폴더 선택")
    root.destroy()
    return folder


def show_info(title: str, message: str) -> None:
    """
    정보 전달용 알림 팝업(Info MessageBox)을 띄웁니다.

    Args:
        title (str): 팝업 창의 제목.
        message (str): 팝업 창에 표시될 본문 메시지.
    """
    if not _can_use_gui():
        log("INFO", "POPUP", f"{title} - {message.replace(chr(10), ' ')}")
        return
    root = _get_tk_root()
    messagebox.showinfo(title, message)
    root.destroy()


def show_error(title: str, message: str) -> None:
    """
    오류 발생 시 에러 팝업(Error MessageBox)을 띄웁니다.

    Args:
        title (str): 팝업 창의 제목.
        message (str): 팝업 창에 표시될 본문 에러 메시지.
    """
    if not _can_use_gui():
        log("ERROR", "POPUP", f"{title} - {message.replace(chr(10), ' ')}")
        return
    root = _get_tk_root()
    messagebox.showerror(title, message)
    root.destroy()
