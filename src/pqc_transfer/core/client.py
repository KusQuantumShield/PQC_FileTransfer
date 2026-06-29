import os
import socket
import hashlib

from ..protocol import chunk_sender, handshake, signature, metadata
from .. import exceptions
from ..utils import logger, connection



class PQCClient:
    """
    서버와 파일 송수신을 담당하는 클라이언트 클래스
    유지보수성 향상을 위해 의존성 주입(DI)을 적용하고, 내부 상태 변수를 제거하여 Stateless한 구조로 개선했습니다.
    """
    
    @classmethod
    def from_config(cls, file_path: str):
        """
        환경 변수 및 기본 설정(config.py)을 기반으로 클라이언트를 손쉽게 생성하는 팩토리 메서드입니다.
        이를 통해 DI 구조를 유지하면서도 호출부의 복잡도를 낮추어 유지보수성을 향상시킵니다.
        """
        from ..utils import config
        from ..utils.key_manager import KeyManager
        
        km = KeyManager(key_dir=config.default_config.key_dir, sig_alg=config.default_config.sig_alg)
        client_id = km.get_client_id()
        
        return cls(
            file_path=file_path,
            server_ip=config.default_config.server_ip,
            port=config.default_config.port,
            client_id=client_id,
            chunk_size=config.default_config.chunk_size,
            kem_alg=config.default_config.kem_alg,
            sig_alg=config.default_config.sig_alg,
            key_manager=km
        )

    def __init__(self, file_path: str, server_ip: str, port: int, client_id: str, chunk_size: int, kem_alg: str, sig_alg: str, key_manager) -> None:
        """
        PQCClient 객체 생성 및 파일 정보 초기화
        
        Args:
            file_path (str): 전송할 파일의 절대 경로 또는 상대 경로
            server_ip (str): 접속할 서버의 IP 주소 (의존성 주입)
            port (int): 접속할 서버의 포트 번호 (의존성 주입)
            client_id (str): 클라이언트 고유 식별자 (의존성 주입)
            chunk_size (int): 파일 전송 시 사용할 청크 단위 크기 (의존성 주입)
        """
        self.file_path: str = file_path
        self.filename: str = os.path.basename(file_path)
        self.filesize: int = os.path.getsize(file_path)
        self.server_ip: str = server_ip
        self.port: int = port
        self.client_id: str = client_id
        self.chunk_size: int = chunk_size
        self.kem_alg: str = kem_alg
        self.sig_alg: str = sig_alg
        self.key_manager = key_manager

    def transfer(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
                conn = connection.SecureConnection(raw_sock, is_server=False)
                conn.sock.connect((self.server_ip, self.port))
                logger.log("INFO", "CONNECT", f"서버 {self.server_ip}:{self.port}에 연결되었습니다")

                session_key = self.perform_handshake(conn)
                self.send_metadata(conn)
                sent_size, file_hash = self.transfer_file_chunks(conn, session_key)
                self.create_and_send_signature(conn, file_hash, sent_size, session_key)
                self.finalize_transfer(conn)

        except ConnectionRefusedError as e:
            logger.log("ERROR", "CLIENT", f"서버 {self.server_ip}:{self.port} 에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.")
            raise exceptions.PQCNetworkError("서버에 연결할 수 없습니다. 서버가 실행 중인지 확인해 주세요.") from e
        except (ConnectionResetError, BrokenPipeError, ConnectionError) as e:
            # 에러 발생 시점에서도 sock이 사용 가능하도록 except 블록 내에서 별도의 소켓 처리 생략 또는 수정 필요
            logger.log("ERROR", "CLIENT", "서버와의 연결이 끊어졌습니다. (서버 측 무결성/인증 검증 실패로 인한 통신 차단)")
            raise exceptions.PQCNetworkError("서버와의 연결이 끊어졌습니다.\n\n서버 측 보안 검증(무결성/송신자 인증) 실패로 인해 통신이 차단되었을 수 있습니다.") from e
        except Exception as e:
            logger.log("ERROR", "CLIENT", str(e), exc_info=True)
            raise

    def perform_handshake(self, conn: connection.SecureConnection) -> bytes:
        return handshake.perform_client_handshake(conn, self.server_ip, self.kem_alg, self.sig_alg, self.key_manager)

    def send_metadata(self, conn: connection.SecureConnection):
        """
        파일 전송 전, 파일 이름과 파일 크기(메타데이터)를 서버로 전송합니다.
        """
        metadata.send_metadata(conn, self.client_id, self.filename, self.filesize)

    def transfer_file_chunks(self, conn: connection.SecureConnection, session_key: bytes) -> tuple[int, str]:
        file_hasher = hashlib.sha256()
        sender = chunk_sender.ChunkSender(conn, session_key, file_hasher, self.chunk_size)
        sent_size, file_hash = sender.send(
            self.file_path,
            self.filename,
            self.filesize
        )
        return sent_size, file_hash

    def create_and_send_signature(self, conn: connection.SecureConnection, file_hash: str, sent_size: int, session_key: bytes):
        signature.create_and_send_signature(
            conn,
            file_hash,
            self.client_id,
            self.filename,
            sent_size,
            session_key,
            self.sig_alg,
            self.key_manager
        )

    def finalize_transfer(self, conn: connection.SecureConnection):
        """
        [단계 6] 전송 완료 및 종료 처리
        """
        conn.send_with_length(b"CLIENT_DONE")
        logger.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")
        
        response = conn.recv_with_length(max_len=1024).decode("utf-8")
        if response.startswith("ERROR:"):
            raise exceptions.PQCProtocolError(f"서버 거부: {response[6:]}")
        elif response == "SERVER_OK":
            logger.log("PASS", "TRANSFER", "서버가 정상적으로 수신을 완료했습니다")


