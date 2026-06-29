import os
import socket
import struct
import shutil
import hashlib
import threading
import re

CLIENT_ID_PATTERN = re.compile(r'^[\w-]+$')

from ..protocol import constants, chunk_receiver, handshake, signature, metadata
from .. import exceptions
from ..utils import logger, connection

class PQCServerHandler:
    """
    클라이언트 연결을 1:1로 처리하는 서버 프로토콜 핸들러
    각 단계(핸드셰이크, 파일 수신, 서명 검증 등)를 독립적인 메서드로 분리하여 유지보수성을 높였습니다.
    """
    def __init__(self, raw_conn: socket.socket, addr, file_save_lock: threading.Lock, save_dir: str, chunk_size: int, kem_alg: str, sig_alg: str, key_manager):
        self.conn = connection.SecureConnection(raw_conn, is_server=True)
        self.addr = addr
        self.file_save_lock = file_save_lock
        self.save_dir = save_dir
        self.chunk_size = chunk_size
        self.kem_alg = kem_alg
        self.sig_alg = sig_alg
        self.key_manager = key_manager
        self.temp_path = None
        self.file_hasher = hashlib.sha256()

    def handle(self) -> bool:
        """
        단일 클라이언트와의 모든 통신 과정을 순차적으로 관리하는 메인 제어 메서드입니다.
        
        [처리 순서]
        1. 핸드셰이크 (KEM 공개키 송신 및 암호문 수신을 통한 세션 키 교환)
        2. 메타데이터 수신 (파일명 및 크기)
        3. 파일 데이터 청크 수신 (AES-GCM 복호화 및 실시간 압축 해제, 파일 저장)
        4. 서명 및 무결성 검증 (해시 대조 및 PQC 전자서명 검증)
        5. 전송 마무리 (임시 파일을 실제 파일로 이동 및 정리)
        
        Returns:
            bool: 모든 과정이 성공적으로 완료되면 True, 예외가 발생하거나 실패하면 False
        """
        logger.log("INFO", "CONNECT", f"클라이언트가 연결되었습니다: {self.addr}")
        try:
            session_key = self.perform_handshake()
            if not session_key: return False
            
            meta = self.receive_metadata()
            if not meta: return False
            client_id, filename, original_filesize = meta
            
            chunks_info = self.receive_file_chunks(session_key, original_filesize)
            if not chunks_info: return False
            temp_path, received_size = chunks_info
            
            if not self.verify_signature(client_id, filename, original_filesize, received_size, session_key): 
                return False
                
            if not self.finalize_transfer(filename, temp_path): 
                return False
                
            return True
        except (ConnectionError, ConnectionResetError, BrokenPipeError) as e:
            logger.log("ERROR", "SERVER", f"클라이언트 연결 끊김: {e}")
            return False
        except Exception as e:
            logger.log("ERROR", "SERVER", str(e), exc_info=True)
            return False
        finally:
            self.cleanup()

    def abort(self, reason: str) -> bool:
        """클라이언트에게 상세한 에러 사유를 전달하고 연결을 안전하게 종료합니다 (Graceful Shutdown)"""
        try:
            self.conn.send_with_length(f"ERROR:{reason}".encode('utf-8'))
            self.conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, constants.SOCKET_LINGER_TIMEOUT))
            self.conn.sock.shutdown(socket.SHUT_WR)
            self.conn.sock.settimeout(1.0)
            bytes_drained = 0
            while bytes_drained < constants.MAX_DRAIN_BYTES:  # 최대 설정값까지만 버퍼를 비우고 강제 종료
                chunk = self.conn.sock.recv(1024)
                if not chunk:
                    break
                bytes_drained += len(chunk)
        except Exception:
            pass
        return False

    def perform_handshake(self) -> bytes | None:
        """[단계 1] 핸드셰이크: KEM 키 생성 및 교환"""
        try:
            return handshake.perform_server_handshake(self.conn, self.kem_alg, self.sig_alg, self.key_manager)
        except Exception as e:
            logger.log("ERROR", "HANDSHAKE", str(e), exc_info=True)
            return None

    def receive_metadata(self) -> tuple[str, str, int] | None:
        """
        [단계 2] 전송될 파일의 초기 메타데이터 수신
        """
        try:
            return metadata.receive_metadata(self.conn)
        except Exception as e:
            logger.log("ERROR", "METADATA", str(e))
            self.abort(str(e))
            return None

    def receive_file_chunks(self, session_key: bytes, original_filesize: int) -> tuple[str, int] | None:
        try:
            # chunk_stream module might need to be imported differently if we split it too.
            receiver = chunk_receiver.ChunkReceiver(self.conn, session_key, self.file_hasher, self.chunk_size)
            temp_path, received_size = receiver.receive(original_filesize, self.save_dir)
            self.temp_path = temp_path # cleanup에서 삭제할 수 있도록 저장
            return temp_path, received_size
        except exceptions.PQCBaseError as e:
            self.abort(str(e))
            return None

    def verify_signature(self, client_id: str, filename: str, original_filesize: int, received_size: int, session_key: bytes) -> bool:
        """[단계 4 & 5] 후반 메타데이터(해시) 수신 및 서명/무결성 검증"""
        challenge_nonce = "CHALLENGE_" + os.urandom(16).hex()
        
        if not CLIENT_ID_PATTERN.match(client_id):
            logger.log("FAIL", "VERIFY", "유효하지 않은 클라이언트 ID 포맷입니다.")
            return self.abort("유효하지 않은 클라이언트 ID 포맷")
            
        if received_size != original_filesize:
            logger.log("FAIL", "FILE", f"파일 크기 불일치: 선언됨={original_filesize}, 수신됨={received_size}")
            return self.abort("불완전한 파일 전송 (크기 불일치)")

        is_valid = signature.verify_signature(
            self.conn,
            client_id,
            filename,
            received_size,
            session_key,
            self.file_hasher.hexdigest(),
            challenge_nonce,
            self.sig_alg,
            self.key_manager
        )
        if not is_valid:
            return self.abort("전자서명/해시 검증 실패")
            
        logger.log("PASS", "VERIFY", "파일 무결성: 통과")
        logger.log("PASS", "VERIFY", "송신자 인증: 통과")
        return True

    def finalize_transfer(self, filename: str, temp_path: str) -> bool:
        """
        [단계 6] 클라이언트 종료 신호 대기 및 파일 자동 저장
        클라이언트로부터 'CLIENT_DONE' 신호를 수신한 후, 
        안전하게 임시 파일(.tmp)을 실제 저장 경로(received_files 폴더)로 이동합니다.
        이름이 겹칠 경우 (1), (2) 등 숫자를 붙여 파일 덮어쓰기를 방지합니다.
        """
        client_signal = self.conn.recv_with_length(max_len=1000)
        if client_signal != b"CLIENT_DONE":
            logger.log("ERROR", "TRANSFER", f"예상치 못한 클라이언트 신호: {client_signal}")
            return self.abort("정상적인 종료 신호(CLIENT_DONE)를 수신하지 못했습니다")

        logger.log("INFO", "TRANSFER", "CLIENT_DONE 신호 수신 완료")

        target_dir = self.save_dir
        base_name, ext = os.path.splitext(filename)
        
        with self.file_save_lock:
            save_path = os.path.join(target_dir, filename)
            counter = 1
            while os.path.exists(save_path):
                save_path = os.path.join(target_dir, f"{base_name}({counter}){ext}")
                counter += 1
            open(save_path, 'a').close()
            
        shutil.move(temp_path, save_path)
        self.temp_path = None

        logger.log("RESULT", "TRANSFER", f"파일이 자동으로 저장됨: {save_path}")
        try:
            self.conn.send_with_length(b"SERVER_OK")
        except Exception:
            pass
        return True

    def cleanup(self):
        """
        소켓 연결을 종료하고, 파일 전송이 비정상적으로 종료되었을 경우
        남아있는 임시 파일을 안전하게 삭제하여 디스크 용량 누수를 방지합니다.
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
