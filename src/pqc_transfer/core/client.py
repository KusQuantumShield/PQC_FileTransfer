import os
import socket
import hashlib

from ..protocol import chunk_stream, handshake, signature, metadata
from .. import exceptions
from ..utils import config, crypto, key_manager, logger, network



class PQCClient:
    """
    서버와 파일 송수신을 담당하는 클라이언트 클래스
    """
    def __init__(self, file_path: str, server_ip: str | None = None, port: int | None = None) -> None:
        """
        PQCClient 객체 생성 및 파일 정보 초기화
        
        Args:
            file_path (str): 전송할 파일의 절대 경로 또는 상대 경로
            server_ip (str, optional): 접속할 서버의 IP 주소. 지정하지 않으면 config의 기본값을 사용.
            port (int, optional): 접속할 서버의 포트 번호. 지정하지 않으면 config의 기본값을 사용.
            
        초기화되는 주요 속성:
            - filename: 전송할 파일의 이름 (경로 제외)
            - filesize: 파일의 총 크기 (바이트 단위)
            - session_key: 서버와 교환하여 생성된 대칭키 (AES-GCM 암호화에 사용)
            - file_hasher: 전송할 원본 데이터의 실시간 무결성 검증을 위한 SHA-256 객체
        """
        self.file_path: str = file_path
        self.filename: str = os.path.basename(file_path)
        self.filesize: int = os.path.getsize(file_path)
        self.server_ip: str = server_ip if server_ip is not None else config.SERVER_IP
        self.port: int = port if port is not None else config.PORT
        self.socket: socket.socket | None = None
        self.session_key: bytes | None = None
        self.file_hasher = hashlib.sha256()
        self.sent_size: int = 0
        self.file_hash: str | None = None
        self.client_id: str = key_manager.get_client_id()

    def transfer(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            network.configure_socket(self.socket, is_server=False)
            self.socket.connect((self.server_ip, self.port))
            logger.log("INFO", "CONNECT", f"서버 {self.server_ip}:{self.port}에 연결되었습니다")

            self.perform_handshake()
            self.send_metadata()
            self.transfer_file_chunks()
            self.create_and_send_signature()
            self.finalize_transfer()

        except ConnectionRefusedError as e:
            logger.log("ERROR", "CLIENT", f"서버 {self.server_ip}:{self.port} 에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.")
            raise exceptions.PQCNetworkError("서버에 연결할 수 없습니다. 서버가 실행 중인지 확인해 주세요.") from e
        except (ConnectionResetError, BrokenPipeError, ConnectionError) as e:
            try:
                if self.socket:
                    self.socket.settimeout(1.0)
                    err_bytes = network.recv_with_length(self.socket, max_len=1024)
                    err_msg = err_bytes.decode("utf-8")
                    if err_msg.startswith("ERROR:"):
                        logger.log("ERROR", "CLIENT", f"서버가 통신을 차단했습니다: {err_msg[6:]}")
                        raise exceptions.PQCAuthenticationError(f"서버에서 보안 검증 실패로 통신을 차단했습니다.\n\n사유: {err_msg[6:]}")
            except Exception:
                pass
            logger.log("ERROR", "CLIENT", "서버와의 연결이 끊어졌습니다. (서버 측 무결성/인증 검증 실패로 인한 통신 차단)")
            raise exceptions.PQCNetworkError("서버와의 연결이 끊어졌습니다.\n\n서버 측 보안 검증(무결성/송신자 인증) 실패로 인해 통신이 차단되었을 수 있습니다.") from e
        except Exception as e:
            logger.log("ERROR", "CLIENT", str(e), exc_info=True)
            raise
        finally:
            if self.socket:
                self.socket.close()

    def perform_handshake(self):
        self.session_key = handshake.perform_client_handshake(self.socket, self.server_ip)

    def send_metadata(self):
        """
        파일 전송 전, 파일 이름과 파일 크기(메타데이터)를 서버로 전송합니다.
        
        이 정보는 서버가 수신할 파일의 예상 크기와 저장할 파일명을 결정하는 데 사용됩니다.
        """
        metadata.send_metadata(self.socket, self.client_id, self.filename, self.filesize)

    def transfer_file_chunks(self):
        sender = chunk_stream.ChunkSender(self.socket, self.session_key, self.file_hasher)
        self.sent_size, self.file_hash = sender.send(
            self.file_path,
            self.filename,
            self.filesize
        )

    def create_and_send_signature(self):
        signature.create_and_send_signature(
            self.socket,
            self.file_hash,
            self.client_id,
            self.filename,
            self.sent_size,
            self.session_key
        )

    def finalize_transfer(self):
        """
        [단계 6] 전송 완료 및 종료 처리
        
        서버에게 전송이 모두 완료되었음을 알리는 'CLIENT_DONE' 신호를 전송하고,
        서버의 최종 수신 확인 응답을 대기한 뒤, 사용자에게 결과를 표시합니다.
        """
        network.send_with_length(self.socket, b"CLIENT_DONE")
        logger.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")
        
        response = network.recv_with_length(self.socket, max_len=1024).decode("utf-8")
        if response.startswith("ERROR:"):
            raise exceptions.PQCProtocolError(f"서버 거부: {response[6:]}")
        elif response == "SERVER_OK":
            logger.log("PASS", "TRANSFER", "서버가 정상적으로 수신을 완료했습니다")


