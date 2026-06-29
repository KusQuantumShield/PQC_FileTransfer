import logging
import sys
import queue
import atexit
import threading
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener

_COLORS = {
    "INFO": "\033[94m",
    "PASS": "\033[92m",
    "RESULT": "\033[96m",
    "WARN": "\033[93m",
    "FAIL": "\033[91m",
    "ERROR": "\033[91m",
    "RESET": "\033[0m"
}

class ColorFormatter(logging.Formatter):
    def format(self, record):
        level_name = getattr(record, 'custom_level', 'INFO')
        module_name = getattr(record, 'module_name', 'SYSTEM')
        color = _COLORS.get(level_name, _COLORS["RESET"])
        reset = _COLORS["RESET"]
        return f"{color}[{level_name}][{module_name}]{reset} {record.getMessage()}"

# ---------------------------------------------------------
# PQC File Transfer 앱을 위한 전역 로거 설정
# 싱글톤 클래스 패턴 대신 Python 기본 logging의 
# getLogger() 싱글톤 특성을 활용하여 구조를 단순화했습니다.
# ---------------------------------------------------------

_logger = logging.getLogger("PQC_APP")
_logger.setLevel(logging.DEBUG)
_log_queue = queue.Queue(-1)

def setup_logger() -> None:
    """
    PQC 앱을 위한 비동기 큐(Queue) 기반의 로거 핸들러와 포맷터를 초기화합니다.
    
    콘솔(stdout) 출력과 파일 회전(RotatingFileHandler)을 동시에 지원하며,
    스레드 안정성(Thread-Safety)을 위해 QueueListener를 백그라운드에서 실행합니다.
    """
    if _logger.handlers:
        return
        
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColorFormatter())
    
    file_handler = RotatingFileHandler(
        "pqc_transfer.log", 
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    file_formatter = logging.Formatter(
        '%(asctime)s [%(custom_level)s][%(module_name)s] %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    queue_handler = QueueHandler(_log_queue)
    _logger.addHandler(queue_handler)
    
    listener = QueueListener(_log_queue, console_handler, file_handler)
    listener.start()
    
    atexit.register(listener.stop)

# 모듈 로드 시 로거 초기화
setup_logger()

def log(level: str, module: str, message: str, exc_info: bool = False) -> None:
    """
    모든 PQC 모듈에서 공통으로 사용할 로깅 래퍼(Wrapper) 함수입니다.
    
    Args:
        level (str): 로그 레벨 문자열 ("INFO", "PASS", "RESULT", "WARN", "FAIL", "ERROR").
        module (str): 로그가 발생한 모듈이나 컨텍스트 이름 (예: "CONNECT", "KEM").
        message (str): 출력할 로그 메시지 내용.
        exc_info (bool): 예외 발생 시 트레이스백(Traceback)을 함께 출력할지 여부. 기본값은 False.
    """
    log_level = logging.ERROR if level in ["ERROR", "FAIL"] else logging.INFO
    _logger.log(
        log_level, 
        message, 
        extra={"custom_level": level, "module_name": module}, 
        exc_info=exc_info
    )
