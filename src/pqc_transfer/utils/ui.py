import os
import sys
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

from .config import CHUNK_SIZE
from .logger import log

def sha256_file(file_path: str) -> str:
    """
    지정된 경로의 파일에 대해 SHA-256 해시를 계산하여 16진수 문자열로 반환합니다.
    대용량 파일(예: 수 GB)을 한 번에 메모리에 올리면 MemoryError(OOM)가 발생할 수 있으므로,
    CHUNK_SIZE(보통 1MB) 단위로 나누어 점진적으로 읽고 해시 상태를 업데이트합니다.
    """
    # hashlib 라이브러리의 sha256 해시 객체 초기화
    h = hashlib.sha256()
    # 파일을 바이너리 읽기 모드("rb")로 엽니다.
    with open(file_path, "rb") as f:
        # 파일에서 CHUNK_SIZE 만큼 읽은 데이터를 chunk 변수에 할당하고,
        # 해당 chunk가 비어있지 않은 동안(즉, 파일 끝에 도달할 때까지) 루프를 반복합니다.
        while chunk := f.read(CHUNK_SIZE):
            # 읽어온 조각(chunk)을 해시 객체에 누적(update)합니다.
            h.update(chunk)
    # 최종적으로 누적 계산된 해시값을 16진수 문자열 형식으로 반환합니다.
    return h.hexdigest()

def _get_tk_root():
    """
    tkinter 창을 화면의 최상단에 띄우되 기본 빈 창(root)은 숨기는 유틸리티 함수
    팝업 메시지나 파일 선택 다이얼로그만을 깔끔하게 보여주기 위해 사용
    """
    root = tk.Tk()
    root.withdraw()                   # 메인 윈도우 숨기기
    root.attributes("-topmost", True) # 생성되는 다이얼로그가 항상 다른 창 위에 표시되도록 설정
    return root

def select_file() -> str:
    """사용자가 전송할 파일을 탐색기를 통해 직접 선택할 수 있도록 다이얼로그를 띄움"""
    if sys.platform != "win32" and not os.environ.get("DISPLAY"):
        log("ERROR", "GUI", "Headless 모드에서는 파일 선택창을 띄울 수 없습니다. 명령줄 인자를 사용하세요 (예: python3 client.py <파일명>)")
        return ""
        
    root = _get_tk_root()
    file_path = filedialog.askopenfilename(
        title="전송할 파일 선택",
        filetypes=[("All Files", "*.*")]
    )
    root.destroy()
    return file_path

def select_save_directory(filename: str) -> str:
    """
    서버 측에서 수신된 파일을 저장할 폴더를 선택하는 다이얼로그를 띄움
    GUI 환경이 아닌 경우(Headless 서버 등)를 대비한 예외 처리도 포함되어 있음
    """
    if sys.platform != "win32" and not os.environ.get("DISPLAY"):
        log("WARN", "GUI", "Headless(GUI 없음) 모드: 기본 수신 폴더에 저장합니다.")
        return ""
    
    root = _get_tk_root()
    messagebox.showinfo("저장 위치 선택", f"수신된 파일: {filename}\n저장할 폴더를 선택해 주세요.")
    folder = filedialog.askdirectory(title="파일 저장 폴더 선택")
    root.destroy()
    return folder

def show_info(title: str, message: str) -> None:
    """정보 전달용 알림 팝업(Info MessageBox)을 띄움. GUI가 없으면 콘솔에 출력"""
    if sys.platform != "win32" and not os.environ.get("DISPLAY"):
        log("INFO", "POPUP", f"{title} - {message.replace(chr(10), ' ')}")
        return
    root = _get_tk_root()
    messagebox.showinfo(title, message)
    root.destroy()

def show_error(title: str, message: str) -> None:
    """오류 발생 시 에러 팝업(Error MessageBox)을 띄움. GUI가 없으면 콘솔에 출력"""
    if sys.platform != "win32" and not os.environ.get("DISPLAY"):
        log("ERROR", "POPUP", f"{title} - {message.replace(chr(10), ' ')}")
        return
    root = _get_tk_root()
    messagebox.showerror(title, message)
    root.destroy()
