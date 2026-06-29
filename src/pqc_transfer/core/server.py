import socket
import threading

from ..protocol import constants
from ..utils import logger, config
from ..utils.config import AppConfig
from ..utils.key_manager import KeyManager
from concurrent.futures import ThreadPoolExecutor
from .handler import PQCServerHandler


class PQCServer:
    """
    PQC 파일 전송 서버의 전체 라이프사이클을 관리하는 클래스입니다.

    소켓 바인딩, 리스닝, 스레드 풀 할당 및 PQCServerHandler 생성을 담당합니다.
    """

    @classmethod
    def from_config(cls, host: str | None = None, port: int | None = None):
        """
        환경 변수 및 기본 설정(config.py)을 기반으로 서버를 손쉽게 생성하는 팩토리 메서드입니다.
        이를 통해 DI 구조를 유지하면서도 호출부의 복잡도를 낮추어 유지보수성을 향상시킵니다.

        Args:
            host (str | None): 서버 호스트 주소.
            port (int | None): 서버 포트 번호.

        Returns:
            PQCServer: 설정된 PQCServer 인스턴스.
        """
        app_config = config.default_config
        if host is not None:
            app_config.host = host
        if port is not None:
            app_config.port = port

        km = KeyManager(key_dir=app_config.key_dir, sig_alg=app_config.sig_alg)

        return cls(app_config=app_config, key_manager=km)

    def __init__(
        self,
        app_config: AppConfig,
        key_manager: KeyManager,
        max_concurrent_clients: int = 100,
    ) -> None:
        """
        PQCServer 객체를 생성합니다.

        Args:
            app_config (AppConfig): 애플리케이션 설정 객체 (의존성 주입).
            key_manager (KeyManager): 키 관리자 객체 (의존성 주입).
            max_concurrent_clients (int): 최대 허용 동시 접속 클라이언트 수.
        """
        self.config = app_config
        self.key_manager = key_manager
        self.max_concurrent_clients = max_concurrent_clients
        self.file_save_lock = threading.Lock()

    def start(self) -> None:
        """
        서버 소켓을 열고 클라이언트의 연결을 대기합니다.

        멀티스레딩(ThreadPoolExecutor)과 세마포어(Semaphore)를 활용하여
        정의된 최대 동시 접속자 수(`max_concurrent_clients`)까지만 안전하게 요청을 처리합니다.
        """
        connection_semaphore = threading.Semaphore(self.max_concurrent_clients)
        executor = ThreadPoolExecutor(max_workers=self.max_concurrent_clients)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.config.host, self.config.port))
            s.listen(constants.SERVER_LISTEN_BACKLOG)

            logger.log(
                "INFO",
                "SYSTEM",
                f"PQC 보안 서버 데몬이 시작되었습니다 (최대 동시 접속: {self.max_concurrent_clients}명)",
            )
            logger.log("INFO", "CONNECT", f"{self.config.port} 포트에서 수신 대기 중")

            while True:
                try:
                    conn, addr = s.accept()

                    if not connection_semaphore.acquire(blocking=False):
                        logger.log(
                            "ERROR",
                            "SYSTEM",
                            f"최대 동시 접속자 수({self.max_concurrent_clients})를 초과했습니다. 연결을 거부합니다: {addr}",
                        )
                        conn.close()
                        continue

                    conn.settimeout(constants.DEFAULT_SOCKET_TIMEOUT)

                    handler = PQCServerHandler(
                        conn, addr, self.file_save_lock, self.config, self.key_manager
                    )

                    def handle_client(h):
                        try:
                            if h.handle():
                                logger.log(
                                    "RESULT", "TRANSFER", "파일 전송이 완료되었습니다"
                                )
                        finally:
                            connection_semaphore.release()

                    executor.submit(handle_client, handler)
                except KeyboardInterrupt:
                    logger.log("INFO", "SYSTEM", "서버를 종료합니다.")
                    executor.shutdown(wait=False)
                    break
                except Exception as e:
                    logger.log("ERROR", "SYSTEM", f"서버 수신 오류: {e}")
