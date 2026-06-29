import os
import socket
import struct
import shutil
import hashlib
import threading
import re

from ..protocol import constants, chunk_receiver, handshake, signature, metadata
from .. import exceptions
from ..utils import logger, network
from ..utils.config import AppConfig
from ..utils.key_manager import KeyManager

CLIENT_ID_PATTERN = re.compile(r"^[\w-]+$")


class PQCServerHandler:
    """
    클라이언트 연결을 1:1로 처리하는 서버 프로토콜 핸들러 클래스입니다.

    각 단계(핸드셰이크, 메타데이터 수신, 파일 수신, 서명 검증 등)를 독립적인 메서드로
    분리하고 예외 버블링 패턴을 통해 유지보수성과 가독성을 극대화했습니다.
    """

    def __init__(
        self,
        raw_conn: socket.socket,
        addr,
        file_save_lock: threading.Lock,
        app_config: AppConfig,
        key_manager: KeyManager,
    ):
        self.conn = network.SecureConnection(raw_conn, is_server=True)
        self.addr = addr
        self.file_save_lock = file_save_lock
        self.config = app_config
        self.key_manager = key_manager
        self.temp_path = None
        self.file_hasher = hashlib.sha256()

    def handle(self) -> bool:
        """
        단일 클라이언트와의 모든 통신 과정을 순차적으로 관리하는 메인 제어 메서드입니다.

        예외 버블링(Exception Bubbling) 패턴을 적용하여 각 단계별 에러 코드 반환을 제거하고,
        선형적인 제어 흐름(Happy Path)을 유지합니다.

        Returns:
            bool: 모든 과정이 성공적으로 완료되면 True, 중간에 실패/예외가 발생하면 False.
        """
        logger.log("INFO", "CONNECT", f"클라이언트가 연결되었습니다: {self.addr}")
        try:
            session_key = self.perform_handshake()
            client_id, filename, original_filesize = self.receive_metadata()
            temp_path, received_size = self.receive_file_chunks(
                session_key, original_filesize
            )
            self.verify_signature(
                client_id, filename, original_filesize, received_size, session_key
            )
            self.finalize_transfer(filename, temp_path)
            return True
        except exceptions.PQCBaseError as e:
            # 프로토콜 및 비즈니스 로직 예외
            logger.log("ERROR", "SERVER", f"전송 실패: {e}")
            return False
        except (ConnectionError, ConnectionResetError, BrokenPipeError) as e:
            logger.log("ERROR", "SERVER", f"클라이언트 연결 끊김: {e}")
            return False
        except Exception as e:
            logger.log("ERROR", "SERVER", str(e), exc_info=True)
            return False
        finally:
            self.cleanup()

    def abort(self, reason: str) -> None:
        """
        클라이언트에게 상세한 에러 사유를 전달하고 연결을 안전하게 종료하기 위한 예외를 발생시킵니다.

        Args:
            reason (str): 클라이언트에게 전송할 에러의 상세 사유.

        Raises:
            exceptions.PQCProtocolError: 전달받은 사유를 포함한 프로토콜 예외 발생.
        """
        try:
            self.conn.send_with_length(f"ERROR:{reason}".encode("utf-8"))
            self.conn.sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, constants.SOCKET_LINGER_TIMEOUT),
            )
            self.conn.sock.shutdown(socket.SHUT_WR)
            self.conn.sock.settimeout(1.0)
            bytes_drained = 0
            while bytes_drained < constants.MAX_DRAIN_BYTES:
                chunk = self.conn.sock.recv(1024)
                if not chunk:
                    break
                bytes_drained += len(chunk)
        except Exception:
            pass
        raise exceptions.PQCProtocolError(reason)

    def perform_handshake(self) -> bytes:
        """
        [단계 1] 핸드셰이크 과정으로 KEM 키 생성 및 교환을 수행합니다.

        Returns:
            bytes: 클라이언트와 공유하게 될 최종 세션 키(Shared Secret).

        Raises:
            exceptions.PQCHandshakeError: 핸드셰이크 과정 중 오류가 발생한 경우.
        """
        try:
            return handshake.perform_server_handshake(
                self.conn, self.config.kem_alg, self.config.sig_alg, self.key_manager
            )
        except Exception as e:
            logger.log("ERROR", "HANDSHAKE", str(e), exc_info=True)
            raise exceptions.PQCHandshakeError(f"핸드셰이크 실패: {e}") from e

    def receive_metadata(self) -> tuple[str, str, int]:
        """
        [단계 2] 전송될 파일의 초기 메타데이터를 클라이언트로부터 수신합니다.

        Returns:
            tuple[str, str, int]: 클라이언트 ID, 파일명, 원본 파일 크기(바이트).

        Raises:
            exceptions.PQCProtocolError: 메타데이터 수신 중 형식이 맞지 않거나 에러 발생 시.
        """
        try:
            return metadata.receive_metadata(self.conn)
        except Exception as e:
            logger.log("ERROR", "METADATA", str(e))
            self.abort(str(e))

    def receive_file_chunks(
        self, session_key: bytes, original_filesize: int
    ) -> tuple[str, int]:
        """
        [단계 3] AES-GCM 복호화 및 실시간 압축 해제를 통해 청크 단위로 파일을 수신합니다.

        Args:
            session_key (bytes): 핸드셰이크를 통해 교환된 세션 키.
            original_filesize (int): 수신할 파일의 원본 크기(기대값).

        Returns:
            tuple[str, int]: 디스크에 저장된 임시 파일의 경로, 실제 수신 및 복호화된 데이터의 바이트 수.

        Raises:
            exceptions.PQCProtocolError: 청크 수신 중 통신 오류나 복호화 실패 시.
        """
        try:
            receiver = chunk_receiver.ChunkReceiver(
                self.conn, session_key, self.file_hasher, self.config.chunk_size
            )
            temp_path, received_size = receiver.receive(
                original_filesize, self.config.save_dir
            )
            self.temp_path = temp_path
            return temp_path, received_size
        except exceptions.PQCBaseError as e:
            self.abort(str(e))

    def verify_signature(
        self,
        client_id: str,
        filename: str,
        original_filesize: int,
        received_size: int,
        session_key: bytes,
    ) -> None:
        """
        [단계 4 & 5] 클라이언트로부터 파일 해시 및 전자서명을 수신하여 무결성과 송신자를 검증합니다.

        재전송(Replay) 공격 방지를 위해 생성된 Nonce를 챌린지로 사용합니다.

        Args:
            client_id (str): 수신된 클라이언트 고유 ID.
            filename (str): 전송받은 파일명.
            original_filesize (int): 메타데이터로 선언된 원본 파일 크기.
            received_size (int): 실제로 수신된 파일 크기.
            session_key (bytes): 통신에 사용된 대칭키.

        Raises:
            exceptions.PQCProtocolError: 크기 불일치, 서명 불일치, 해시 변조 등 검증 실패 시.
        """
        challenge_nonce = "CHALLENGE_" + os.urandom(16).hex()

        if not CLIENT_ID_PATTERN.match(client_id):
            logger.log("FAIL", "VERIFY", "유효하지 않은 클라이언트 ID 포맷입니다.")
            self.abort("유효하지 않은 클라이언트 ID 포맷")

        if received_size != original_filesize:
            logger.log(
                "FAIL",
                "FILE",
                f"파일 크기 불일치: 선언됨={original_filesize}, 수신됨={received_size}",
            )
            self.abort("불완전한 파일 전송 (크기 불일치)")

        is_valid = signature.verify_signature(
            self.conn,
            client_id,
            filename,
            received_size,
            session_key,
            self.file_hasher.hexdigest(),
            challenge_nonce,
            self.config.sig_alg,
            self.key_manager,
        )
        if not is_valid:
            self.abort("전자서명/해시 검증 실패")

        logger.log("PASS", "VERIFY", "파일 무결성: 통과")
        logger.log("PASS", "VERIFY", "송신자 인증: 통과")

    def finalize_transfer(self, filename: str, temp_path: str) -> None:
        """
        [단계 6] 클라이언트로부터 정상 종료 신호를 대기하고 임시 파일을 최종 저장소로 이동합니다.

        파일 이름이 이미 존재하는 경우 이름 끝에 숫자를 붙여 덮어쓰기를 방지합니다.

        Args:
            filename (str): 원본 파일명.
            temp_path (str): 수신 완료된 임시 파일의 경로.

        Raises:
            exceptions.PQCProtocolError: 종료 신호(CLIENT_DONE)를 정상적으로 받지 못한 경우.
        """
        client_signal = self.conn.recv_with_length(max_len=1000)
        if client_signal != b"CLIENT_DONE":
            logger.log(
                "ERROR", "TRANSFER", f"예상치 못한 클라이언트 신호: {client_signal}"
            )
            self.abort("정상적인 종료 신호(CLIENT_DONE)를 수신하지 못했습니다")

        logger.log("INFO", "TRANSFER", "CLIENT_DONE 신호 수신 완료")

        target_dir = self.config.save_dir
        base_name, ext = os.path.splitext(filename)

        with self.file_save_lock:
            save_path = os.path.join(target_dir, filename)
            counter = 1
            while os.path.exists(save_path):
                save_path = os.path.join(target_dir, f"{base_name}({counter}){ext}")
                counter += 1
            open(save_path, "a").close()

        shutil.move(temp_path, save_path)
        self.temp_path = None

        logger.log("RESULT", "TRANSFER", f"파일이 자동으로 저장됨: {save_path}")
        try:
            self.conn.send_with_length(b"SERVER_OK")
        except Exception:
            pass

    def cleanup(self):
        """
        에러 발생 또는 전송 완료 후 소켓 연결을 종료하고,
        불완전하게 남은 임시 파일(.tmp)을 안전하게 삭제하여 디스크 용량 누수를 방지합니다.
        """
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

        if self.temp_path and os.path.exists(self.temp_path):
            try:
                os.remove(self.temp_path)
                logger.log("INFO", "FILE", "임시 파일이 삭제되었습니다")
            except Exception as e:
                logger.log("ERROR", "FILE", f"임시 파일 삭제 실패: {e}")

        try:
            if self.conn:
                self.conn.close()
                logger.log("INFO", "CONNECT", "연결이 종료되었습니다")
        except Exception:
            pass
