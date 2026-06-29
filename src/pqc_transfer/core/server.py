import socket
import threading

from ..protocol import constants
from ..utils import logger
from .handler import PQCServerHandler

class PQCServer:
    """
    PQC 파일 전송 서버의 전체 라이프사이클을 관리하는 클래스
    소켓 바인딩, 리스닝, 스레드 풀 할당 및 PQCServerHandler 생성을 담당합니다.
    """
    
    @classmethod
    def from_config(cls, host: str | None = None, port: int | None = None):
        """
        환경 변수 및 기본 설정(config.py)을 기반으로 서버를 손쉽게 생성하는 팩토리 메서드입니다.
        이를 통해 DI 구조를 유지하면서도 호출부의 복잡도를 낮추어 유지보수성을 향상시킵니다.
        """
        from ..utils import config
        from ..utils.key_manager import KeyManager
        
        km = KeyManager(key_dir=config.default_config.key_dir, sig_alg=config.default_config.sig_alg)
        
        return cls(
            host=config.default_config.host,
            port=config.default_config.port,
            save_dir=config.default_config.save_dir,
            chunk_size=config.default_config.chunk_size,
            kem_alg=config.default_config.kem_alg,
            sig_alg=config.default_config.sig_alg,
            key_manager=km
        )
        
    def __init__(self, host: str, port: int, save_dir: str, chunk_size: int, kem_alg: str, sig_alg: str, key_manager, max_concurrent_clients: int = 100):
        self.host = host
        self.port = port
        self.save_dir = save_dir
        self.chunk_size = chunk_size
        self.kem_alg = kem_alg
        self.sig_alg = sig_alg
        self.key_manager = key_manager
        self.max_concurrent_clients = max_concurrent_clients
        self.file_save_lock = threading.Lock()
        
    def start(self):
        """서버 소켓을 열고 클라이언트의 연결을 대기합니다."""
        from concurrent.futures import ThreadPoolExecutor

        connection_semaphore = threading.Semaphore(self.max_concurrent_clients)
        executor = ThreadPoolExecutor(max_workers=self.max_concurrent_clients)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(constants.SERVER_LISTEN_BACKLOG)
            
            logger.log("INFO", "SYSTEM", f"PQC 보안 서버 데몬이 시작되었습니다 (최대 동시 접속: {self.max_concurrent_clients}명)")
            logger.log("INFO", "CONNECT", f"{self.port} 포트에서 수신 대기 중")

            while True:
                try:
                    conn, addr = s.accept()
                    
                    if not connection_semaphore.acquire(blocking=False):
                        logger.log("ERROR", "SYSTEM", f"최대 동시 접속자 수({self.max_concurrent_clients})를 초과했습니다. 연결을 거부합니다: {addr}")
                        conn.close()
                        continue
                    
                    conn.settimeout(constants.DEFAULT_SOCKET_TIMEOUT)
                    
                    handler = PQCServerHandler(conn, addr, self.file_save_lock, self.save_dir, self.chunk_size, self.kem_alg, self.sig_alg, self.key_manager)
                    
                    def handle_client(h):
                        try:
                            if h.handle():
                                logger.log("RESULT", "TRANSFER", "파일 전송이 완료되었습니다")
                        finally:
                            connection_semaphore.release()
                    
                    executor.submit(handle_client, handler)
                except KeyboardInterrupt:
                    logger.log("INFO", "SYSTEM", "서버를 종료합니다.")
                    executor.shutdown(wait=False)
                    break
                except Exception as e:
                    logger.log("ERROR", "SYSTEM", f"서버 수신 오류: {e}")


