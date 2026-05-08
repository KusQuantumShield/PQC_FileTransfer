import os
import socket
import struct
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import logging
import sys

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# =====================================================================
# 설정 상수 (Configuration Constants)
# =====================================================================
SERVER_IP = "127.0.0.1"  # 클라이언트가 접속할 서버의 IP 주소
HOST = "0.0.0.0"         # 서버가 모든 네트워크 인터페이스에서 수신 대기하도록 설정
PORT = 9999              # 서버와 클라이언트가 통신에 사용할 포트 번호
CHUNK_SIZE = 1024 * 1024 # 1MB 크기. 대용량 파일을 메모리 효율적으로 전송하기 위해 이 크기로 분할

# 양자 내성 암호(PQC) 알고리즘 설정 (FIPS 204/203 표준 이름 사용)
KEM_ALG = "ML-KEM-768"   # 키 캡슐화 메커니즘. 대칭키(공유 비밀키)를 안전하게 교환하기 위해 사용합니다.
SIG_ALG = "ML-DSA-65"    # 디지털 서명 알고리즘. 데이터의 무결성과 송신자의 인증을 위해 사용합니다.


# =====================================================================
# 로깅 유틸리티 (Logging Utilities)
# =====================================================================
# 터미널 출력을 위한 ANSI 색상 코드 정의
_COLORS = {
    "INFO": "\033[94m",    # 파란색 (일반적인 진행 상태)
    "PASS": "\033[92m",    # 녹색 (검증 성공, 완료)
    "RESULT": "\033[96m",  # 청록색 (최종 결과)
    "WARN": "\033[93m",    # 노란색 (경고)
    "FAIL": "\033[91m",    # 빨간색 (검증 실패, 차단)
    "ERROR": "\033[91m",   # 빨간색 (시스템 에러, 예외)
    "RESET": "\033[0m"     # 색상 초기화
}

# 기본 로거 인스턴스 생성
_logger = logging.getLogger("PQC_APP")
_logger.setLevel(logging.DEBUG)

# 중복 핸들러 추가 방지를 위한 체크
if not _logger.handlers:
    # 1. 터미널(Console) 출력 핸들러: 색상을 적용한 직관적인 포맷
    class ColorFormatter(logging.Formatter):
        def format(self, record):
            level_name = getattr(record, 'custom_level', 'INFO')
            module_name = getattr(record, 'module_name', 'SYSTEM')
            color = _COLORS.get(level_name, _COLORS["RESET"])
            reset = _COLORS["RESET"]
            # 예: [INFO][KEM] Public key sent
            return f"{color}[{level_name}][{module_name}]{reset} {record.getMessage()}"

    _console_handler = logging.StreamHandler(sys.stdout)
    _console_handler.setFormatter(ColorFormatter())
    _logger.addHandler(_console_handler)

    # 2. 파일 출력 핸들러: 파일에는 색상 코드를 빼고 타임스탬프를 추가하여 기록
    # 파일명: pqc_transfer.log (스크립트 실행 위치에 생성됨)
    _file_handler = logging.FileHandler("pqc_transfer.log", encoding="utf-8")
    _file_formatter = logging.Formatter('%(asctime)s [%(custom_level)s][%(module_name)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    _file_handler.setFormatter(_file_formatter)
    _logger.addHandler(_file_handler)


def log(level: str, module: str, message: str):
    """
    구조화된 로그를 터미널에 출력하고 로그 파일에 저장
    기존의 print 기반 코드를 수정하지 않고 호환성을 유지하기 위해 래퍼 함수로 사용
    
    :param level: "INFO", "PASS", "ERROR", "FAIL", "RESULT" 등 상태
    :param module: "KEM", "FILE", "SIGN", "CONNECT", "CHUNK" 등 모듈 태그
    :param message: 실제 로그 내용
    """
    # 내부적으로 에러와 일반 정보를 구분하여 파이썬 표준 로거에 전달
    log_level = logging.ERROR if level in ["ERROR", "FAIL"] else logging.INFO
    _logger.log(log_level, message, extra={"custom_level": level, "module_name": module})


# =====================================================================
# 암호화 유틸리티 (Cryptography Utilities)
# =====================================================================
def hash_ss(shared_secret: bytes) -> str:
    """
    공유 비밀키(Shared Secret)의 SHA-256 해시값을 문자열로 반환
    주로 콘솔 로그에 출력하여 클라이언트와 서버가 동일한 키를 도출했는지 확인하는 용도로 사용
    보안상 실제 키를 직접 출력하지 않고 해시값만 출력
    """
    return hashlib.sha256(shared_secret).hexdigest()

def derive_key(shared_secret: bytes) -> bytes:
    """
    KEM을 통해 교환된 공유 비밀키 원본을 그대로 암호화 키로 사용하는 대신
    HKDF (HMAC-based Key Derivation Function)를 거쳐 안전한 32바이트(256비트) 세션 키로 도출
    이렇게 하면 키의 난수성이 향상되어 AES-GCM 같은 대칭키 암호화에 사용하기 적합해짐
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                  # AES-256-GCM에 사용할 32바이트 길이
        salt=None,                  # 별도의 salt는 사용하지 않음
        info=b"handshake data",     # 키 도출 목적을 나타내는 컨텍스트 정보
    )
    return hkdf.derive(shared_secret)

# =====================================================================
# 네트워크 통신 유틸리티 (Networking Utilities)
# =====================================================================
# TCP 소켓은 데이터가 한 번에 모두 전송되거나 수신된다고 보장하지 않으므로
# 정확한 길이만큼 데이터를 반복해서 읽어오는 로직이 필수적임

def recv_exact(sock: socket.socket, length: int) -> bytes:
    """
    소켓 버퍼에서 정확히 지정된 length 바이트만큼의 데이터를 읽어올 때까지 대기하며 수신
    스트림 기반인 TCP 소켓 특성상 데이터가 잘려서 도착할 수 있으므로 이 함수가 필요
    """
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            # 상대방이 연결을 정상적으로 종료했거나 네트워크가 끊어진 경우 예외 발생
            raise ConnectionError("네트워크 연결이 예기치 않게 종료되었습니다.")
        data += packet
    return data

def recv_with_length(sock: socket.socket) -> bytes:
    """
    가변 길이의 데이터를 수신하기 위한 래퍼 함수
    데이터의 첫 4바이트에는 이후 수신할 데이터의 실제 길이가 부호 없는 정수 형태로 들어있음
    먼저 4바이트를 읽어 전체 길이를 파악한 후 그 길이만큼 정확히 데이터를 더 읽어옴
    """
    # 1. 4바이트 길이 정보(헤더) 먼저 수신
    data_len_bytes = recv_exact(sock, 4)
    # 2. 바이트 배열을 파이썬 정수형으로 변환 (!I = Network byte order, Unsigned Integer)
    data_len = struct.unpack("!I", data_len_bytes)[0]
    
    # 3. 비정상적으로 큰 데이터(예: 100MB 초과)가 요청된 경우 메모리 초과 공격(OOM)을 방지
    if data_len <= 0 or data_len > 100 * 1024 * 1024:
        raise ValueError(f"유효하지 않은 수신 데이터 길이입니다: {data_len} bytes")
        
    # 4. 파악된 길이만큼 실제 데이터 페이로드 수신
    return recv_exact(sock, data_len)

def send_with_length(sock: socket.socket, data: bytes) -> None:
    """
    가변 길이의 데이터를 전송하기 위한 래퍼 함수
    데이터 본문을 보내기 직전에, 해당 데이터의 길이(바이트 수)를 4바이트 헤더로 먼저 전송
    """
    # 1. 전송할 데이터의 길이를 4바이트 네트워크 바이트 순서의 바이너리로 패킹하여 전송
    sock.sendall(struct.pack("!I", len(data)))
    # 2. 실제 데이터 전송
    sock.sendall(data)

# =====================================================================
# UI 및 파일 입출력 유틸리티 (UI Utilities)
# =====================================================================
def sha256_file(file_path: str) -> str:
    """
    지정된 경로의 파일에 대해 SHA-256 해시를 계산
    메모리 부족을 방지하기 위해 파일을 CHUNK_SIZE 단위로 나누어 점진적으로 읽고 해시를 업데이트
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
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
    if not os.environ.get("DISPLAY"):
        log("WARN", "GUI", "Headless(GUI 없음) 모드: 파일을 현재 작업 디렉토리에 저장합니다.")
        return os.getcwd()
    
    root = _get_tk_root()
    messagebox.showinfo("저장 위치 선택", f"수신된 파일: {filename}\n저장할 폴더를 선택해 주세요.")
    folder = filedialog.askdirectory(title="파일 저장 폴더 선택")
    root.destroy()
    return folder

def show_info(title: str, message: str) -> None:
    """정보 전달용 알림 팝업(Info MessageBox)을 띄움. GUI가 없으면 콘솔에 출력"""
    if not os.environ.get("DISPLAY"):
        log("INFO", "POPUP", f"{title} - {message.replace(chr(10), ' ')}")
        return
    root = _get_tk_root()
    messagebox.showinfo(title, message)
    root.destroy()

def show_error(title: str, message: str) -> None:
    """오류 발생 시 에러 팝업(Error MessageBox)을 띄움. GUI가 없으면 콘솔에 출력"""
    if not os.environ.get("DISPLAY"):
        log("ERROR", "POPUP", f"{title} - {message.replace(chr(10), ' ')}")
        return
    root = _get_tk_root()
    messagebox.showerror(title, message)
    root.destroy()
