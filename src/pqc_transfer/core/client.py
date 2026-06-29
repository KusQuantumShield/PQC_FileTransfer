import os
import socket
import hashlib

from ..protocol import chunk_sender, handshake, signature, metadata
from .. import exceptions
from ..utils import logger, network, config
from ..utils.config import AppConfig
from ..utils.key_manager import KeyManager


class PQCClient:
    """
    서버와 파일 송수신을 담당하는 클라이언트 클래스입니다.

    유지보수성 향상을 위해 의존성 주입(DI)을 적용하고, 내부 상태 변수를 제거하여 Stateless한 구조로 개선했습니다.
    """

    @classmethod
    def from_config(cls, file_path: str):
        """
        환경 변수 및 기본 설정(config.py)을 기반으로 클라이언트를 손쉽게 생성하는 팩토리 메서드입니다.
        이를 통해 DI 구조를 유지하면서도 호출부의 복잡도를 낮추어 유지보수성을 향상시킵니다.
        """
        km = KeyManager(
            key_dir=config.default_config.key_dir, sig_alg=config.default_config.sig_alg
        )

        return cls(
            file_path=file_path, app_config=config.default_config, key_manager=km
        )

    def __init__(
        self, file_path: str, app_config: AppConfig, key_manager: KeyManager
    ) -> None:
        """
        PQCClient 객체 생성 및 파일 정보를 초기화합니다.

        Args:
            file_path (str): 전송할 파일의 절대 또는 상대 경로.
            app_config (AppConfig): 애플리케이션 설정 객체 (의존성 주입).
            key_manager (KeyManager): 키 관리자 객체 (의존성 주입).
        """
        self.file_path: str = file_path
        self.filename: str = os.path.basename(file_path)
        self.filesize: int = os.path.getsize(file_path)
        self.config = app_config
        self.client_id: str = key_manager.get_client_id()
        self.key_manager = key_manager

    def transfer(self) -> None:
        """
        클라이언트의 전체 파일 전송 프로세스를 수행합니다.

        네트워크 소켓 연결 후 핸드셰이크, 메타데이터 전송, 파일 청크 전송,
        전자서명 송신, 종료 처리까지 순차적으로 진행합니다.

        Raises:
            exceptions.PQCNetworkError: 네트워크 연결 실패 또는 통신 차단 시 발생.
            Exception: 기타 전송 과정 중 발생한 예외.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
                with network.SecureConnection(raw_sock, is_server=False) as conn:
                    conn.sock.connect((self.config.server_ip, self.config.port))
                    logger.log(
                        "INFO",
                        "CONNECT",
                        f"서버 {self.config.server_ip}:{self.config.port}에 연결되었습니다",
                    )

                    session_key = self.perform_handshake(conn)
                    self.send_metadata(conn)
                    sent_size, file_hash = self.transfer_file_chunks(conn, session_key)
                    self.create_and_send_signature(
                        conn, file_hash, sent_size, session_key
                    )
                    self.finalize_transfer(conn)

        except ConnectionRefusedError as e:
            logger.log(
                "ERROR",
                "CLIENT",
                f"서버 {self.config.server_ip}:{self.config.port} 에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.",
            )
            raise exceptions.PQCNetworkError(
                "서버에 연결할 수 없습니다. 서버가 실행 중인지 확인해 주세요."
            ) from e
        except (ConnectionResetError, BrokenPipeError, ConnectionError) as e:
            # 에러 발생 시점에서도 sock이 사용 가능하도록 except 블록 내에서 별도의 소켓 처리 생략 또는 수정 필요
            logger.log(
                "ERROR",
                "CLIENT",
                "서버와의 연결이 끊어졌습니다. (서버 측 무결성/인증 검증 실패로 인한 통신 차단)",
            )
            raise exceptions.PQCNetworkError(
                "서버와의 연결이 끊어졌습니다.\n\n서버 측 보안 검증(무결성/송신자 인증) 실패로 인해 통신이 차단되었을 수 있습니다."
            ) from e
        except Exception as e:
            logger.log("ERROR", "CLIENT", str(e), exc_info=True)
            raise

    def perform_handshake(self, conn: network.SecureConnection) -> bytes:
        """
        [단계 1] KEM 키 생성 및 서버와의 교환을 수행하여 세션 키를 생성합니다.

        Args:
            conn (network.SecureConnection): 보안이 설정된 소켓 연결 객체.

        Returns:
            bytes: 생성된 32바이트 세션 키.
        """
        return handshake.perform_client_handshake(
            conn,
            self.config.server_ip,
            self.config.kem_alg,
            self.config.sig_alg,
            self.key_manager,
        )

    def send_metadata(self, conn: network.SecureConnection):
        """
        파일 전송 전, 파일 이름과 파일 크기 등 초기 메타데이터를 서버로 전송합니다.

        Args:
            conn (network.SecureConnection): 보안이 설정된 소켓 연결 객체.
        """
        metadata.send_metadata(conn, self.client_id, self.filename, self.filesize)

    def transfer_file_chunks(
        self, conn: network.SecureConnection, session_key: bytes
    ) -> tuple[int, str]:
        """
        [단계 3] 파일을 청크 단위로 나누어 압축 및 AES-GCM 암호화 후 서버로 전송합니다.

        Args:
            conn (network.SecureConnection): 보안이 설정된 소켓 연결 객체.
            session_key (bytes): 통신에 사용할 대칭키(세션 키).

        Returns:
            tuple[int, str]: 총 전송된 바이트 수, 파일의 최종 원본 SHA-256 해시값.
        """
        file_hasher = hashlib.sha256()
        sender = chunk_sender.ChunkSender(
            conn, session_key, file_hasher, self.config.chunk_size
        )
        sent_size, file_hash = sender.send(self.file_path, self.filename, self.filesize)
        return sent_size, file_hash

    def create_and_send_signature(
        self,
        conn: network.SecureConnection,
        file_hash: str,
        sent_size: int,
        session_key: bytes,
    ):
        signature.create_and_send_signature(
            conn,
            file_hash,
            self.client_id,
            self.filename,
            sent_size,
            session_key,
            self.config.sig_alg,
            self.key_manager,
        )

    def finalize_transfer(self, conn: network.SecureConnection):
        """
        [단계 6] 전송 완료 및 종료를 처리합니다.

        Args:
            conn (network.SecureConnection): 보안이 설정된 소켓 연결 객체.

        Raises:
            exceptions.PQCProtocolError: 서버 측에서 수신을 거부하거나 오류를 반환한 경우.
        """
        conn.send_with_length(b"CLIENT_DONE")
        logger.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")

        response = conn.recv_with_length(max_len=1024).decode("utf-8")
        if response.startswith("ERROR:"):
            raise exceptions.PQCProtocolError(f"서버 거부: {response[6:]}")
        elif response == "SERVER_OK":
            logger.log("PASS", "TRANSFER", "서버가 정상적으로 수신을 완료했습니다")
