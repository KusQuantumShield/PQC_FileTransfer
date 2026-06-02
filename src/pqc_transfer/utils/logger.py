import logging
import sys
from logging.handlers import RotatingFileHandler

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
    # 악의적인 다량 접속으로 인한 디스크 고갈(Log Flooding DoS)을 막기 위해 롤링 파일 핸들러 적용
    _file_handler = RotatingFileHandler(
        "pqc_transfer.log", 
        maxBytes=10 * 1024 * 1024, # 최대 10MB
        backupCount=5,             # 백업 파일 최대 5개 유지
        encoding="utf-8"
    )
    _file_formatter = logging.Formatter('%(asctime)s [%(custom_level)s][%(module_name)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    _file_handler.setFormatter(_file_formatter)
    _logger.addHandler(_file_handler)


def log(level: str, module: str, message: str, exc_info: bool = False):
    """
    구조화된 로그를 터미널에 컬러로 출력하고 동시에 파일(pqc_transfer.log)에 안전하게 저장합니다.
    기존의 단순한 print 기반 코드를 수정하지 않고도, 모듈별/수준별 로깅을 지원하기 위해 설계된 래퍼 함수입니다.
    
    Args:
        level (str): "INFO", "PASS", "ERROR", "FAIL", "RESULT" 등 현재 로그의 상태
        module (str): "KEM", "FILE", "SIGN", "CONNECT", "CHUNK" 등 작업이 발생한 논리적 모듈 태그
        message (str): 실제 출력/저장할 핵심 로그 내용
        exc_info (bool): True일 경우 파이썬 Exception의 Traceback(스택 트레이스) 정보도 함께 출력/기록 (디버깅용)
    """
    # 내부적으로 에러 관련 로그("ERROR", "FAIL")와 일반 정보성 로그를 구분하여 파이썬 표준 로거에 전달합니다.
    log_level = logging.ERROR if level in ["ERROR", "FAIL"] else logging.INFO
    
    # extra 인자를 통해 custom_level과 module_name을 전달하여, 위에서 정의한 ColorFormatter와 
    # _file_formatter가 해당 값을 추출해 포맷팅(예: [INFO][KEM] 메세지)할 수 있도록 합니다.
    _logger.log(log_level, message, extra={"custom_level": level, "module_name": module}, exc_info=exc_info)
