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

class PQCLogger:
    """
    PQC 전송 앱용 로거를 객체 지향적으로 관리합니다.
    """
    _instance = None
    _instance_lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._instance_lock:
                if not cls._instance:
                    cls._instance = super(PQCLogger, cls).__new__(cls)
        return cls._instance
        
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._logger = logging.getLogger("PQC_APP")
            self._logger.setLevel(logging.DEBUG)
            
            if not self._logger.handlers:
                self._console_handler = logging.StreamHandler(sys.stdout)
                self._console_handler.setFormatter(ColorFormatter())
                
                self._file_handler = RotatingFileHandler(
                    "pqc_transfer.log", 
                    maxBytes=10 * 1024 * 1024,
                    backupCount=5,
                    encoding="utf-8"
                )
                self._file_formatter = logging.Formatter('%(asctime)s [%(custom_level)s][%(module_name)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
                self._file_handler.setFormatter(self._file_formatter)
                
                self._log_queue = queue.Queue(-1)
                self._queue_handler = QueueHandler(self._log_queue)
                self._logger.addHandler(self._queue_handler)
                
                self._listener = QueueListener(self._log_queue, self._console_handler, self._file_handler)
                self._listener.start()
                
                atexit.register(self._listener.stop)
            self._initialized = True
            
    def log(self, level: str, module: str, message: str, exc_info: bool = False):
        log_level = logging.ERROR if level in ["ERROR", "FAIL"] else logging.INFO
        self._logger.log(log_level, message, extra={"custom_level": level, "module_name": module}, exc_info=exc_info)

_logger_instance = PQCLogger()
log = _logger_instance.log
