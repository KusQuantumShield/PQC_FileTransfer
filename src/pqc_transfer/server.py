import os
import socket
import struct
import zlib
import tempfile
import shutil
import hashlib
import time

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import utils

# 자동으로 저장될 디렉토리 이름 지정
SAVE_DIR = "received_files"

class PQCServerHandler:
    """
    클라이언트 연결을 1:1로 처리하는 서버 프로토콜 핸들러
    각 단계(핸드셰이크, 파일 수신, 서명 검증 등)를 독립적인 메서드로 분리하여 유지보수성을 높였습니다.
    """
    def __init__(self, conn: socket.socket, addr):
        self.conn = conn
        self.addr = addr
        self.session_key = None
        self.temp_path = None
        self.temp_file = None
        self.filename = None
        self.original_filesize = 0
        self.received_size = 0
        self.file_hasher = hashlib.sha256()

    def handle(self) -> bool:
        utils.log("INFO", "CONNECT", f"클라이언트가 연결되었습니다: {self.addr}")
        try:
            if not self.perform_handshake(): return False
            if not self.receive_metadata(): return False
            if not self.receive_file_chunks(): return False
            if not self.verify_signature(): return False
            if not self.finalize_transfer(): return False
            return True
        except Exception as e:
            utils.log("ERROR", "SERVER", str(e), exc_info=True)
            return False
        finally:
            self.cleanup()

    def perform_handshake(self) -> bool:
        """[단계 1] 핸드셰이크: KEM 키 생성 및 교환"""
        kem_start_time = time.perf_counter()
        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            public_key = kem.generate_keypair()
            utils.log("INFO", "KEM", "ML-KEM 키쌍 생성 완료")

            utils.send_with_length(self.conn, public_key)
            utils.log("INFO", "KEM", f"공개키 전송 완료 ({len(public_key)} 바이트)")

            kem_ciphertext = utils.recv_with_length(self.conn)
            utils.log("INFO", "KEM", f"암호문 수신 완료 ({len(kem_ciphertext)} 바이트)")

            try:
                shared_secret = kem.decap_secret(kem_ciphertext)
                utils.log("PASS", "KEM", "캡슐화 해제 완료")
            except Exception as e:
                utils.log("ERROR", "KEM", f"캡슐화 해제 실패: {e}", exc_info=True)
                return False

        utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")
        self.session_key = utils.derive_key(shared_secret)
        kem_end_time = time.perf_counter()
        utils.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
        utils.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")
        return True

    def receive_metadata(self) -> bool:
        """[단계 2] 전송될 파일의 초기 메타데이터 수신"""
        filename_bytes = utils.recv_with_length(self.conn)
        raw_filename = filename_bytes.decode("utf-8").replace("\\", "/")
        self.filename = os.path.basename(raw_filename)

        if not self.filename or len(self.filename) > 255 or self.filename in (".", ".."):
            utils.log("FAIL", "FILE", "유효하지 않은 파일명")
            raise ValueError("Invalid filename")

        self.original_filesize = struct.unpack("!Q", utils.recv_exact(self.conn, 8))[0]
        utils.log("INFO", "FILE", f"파일명 수신 완료: {self.filename}")
        utils.log("INFO", "FILE", f"예상 파일 크기: {self.original_filesize} 바이트")
        return True

    def receive_file_chunks(self) -> bool:
        """[단계 3] 대용량 파일 청크(Chunk) 수신 및 복호화"""
        os.makedirs(SAVE_DIR, exist_ok=True)
        self.temp_file = tempfile.NamedTemporaryFile(dir=SAVE_DIR, delete=False)
        self.temp_path = self.temp_file.name
        utils.log("INFO", "FILE", f"임시 파일 생성됨: {self.temp_path}")

        aesgcm = AESGCM(self.session_key)
        decompressor = zlib.decompressobj()

        MAX_PAYLOAD_SIZE = utils.CHUNK_SIZE + 1024 * 10
        recv_buffer = bytearray(MAX_PAYLOAD_SIZE)
        recv_view = memoryview(recv_buffer)

        expected_chunk_index = 0
        transfer_start_time = time.perf_counter()

        while True:
            header = utils.recv_exact(self.conn, 13)
            flags, chunk_index, payload_len = struct.unpack("!BQI", header)

            if chunk_index != expected_chunk_index:
                utils.log("ERROR", "CHUNK", f"청크 인덱스 불일치: 예상됨={expected_chunk_index}, 수신됨={chunk_index}")
                raise ValueError(f"Chunk index mismatch")

            if payload_len <= 0 or payload_len > MAX_PAYLOAD_SIZE:
                utils.log("ERROR", "CHUNK", "유효하지 않은 페이로드 길이")
                raise ValueError(f"Invalid payload length: {payload_len}")

            utils.recv_exact_into(self.conn, recv_view, payload_len)
            nonce = bytes(recv_view[:12])
            encrypted_chunk = recv_view[12:payload_len]

            try:
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, associated_data=header)
            except Exception as e:
                utils.log("ERROR", "CHUNK", f"인덱스 {chunk_index}에서 청크 복호화 실패: {e}", exc_info=True)
                return False

            if flags & 0x01:
                try:
                    decrypted_chunk = decompressor.decompress(decrypted_chunk, max_length=utils.CHUNK_SIZE * 2)
                    if decompressor.unconsumed_tail:
                        utils.log("ERROR", "COMPRESS", "Zip Bomb 공격 감지: 허용된 압축 해제 크기 초과")
                        return False
                except Exception as e:
                    utils.log("ERROR", "COMPRESS", f"청크 {chunk_index} 압축 해제 실패: {e}")
                    return False

            self.temp_file.write(decrypted_chunk)
            self.file_hasher.update(decrypted_chunk)
            self.received_size += len(decrypted_chunk)

            utils.log("INFO", "CHUNK", f"청크 {chunk_index} 수신 완료 ({self.received_size}/{self.original_filesize} 바이트)")
            expected_chunk_index += 1

            if flags & 0x02:
                utils.log("INFO", "CHUNK", "모든 청크 데이터 수신 완료 (EOF 플래그 감지)")
                break

        transfer_end_time = time.perf_counter()
        self.temp_file.close()
        utils.log("PASS", "CHUNK", f"모든 청크 수신 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")
        return True

    def verify_signature(self) -> bool:
        """[단계 4 & 5] 후반 메타데이터(해시) 수신 및 서명/무결성 검증"""
        expected_hash = utils.recv_exact(self.conn, 64).decode("utf-8")
        utils.log("INFO", "HASH", f"클라이언트가 전송한 원본 SHA-256: {expected_hash}")

        sig_public_key = utils.recv_with_length(self.conn)
        utils.log("INFO", "SIGN", f"서명 공개키 수신 완료 ({len(sig_public_key)} 바이트)")

        signature = utils.recv_with_length(self.conn)
        utils.log("INFO", "SIGN", f"서명 수신 완료 ({len(signature)} 바이트)")

        utils.log("PASS", "FILE", "파일 크기 동적 동기화 성공")

        received_hash = self.file_hasher.hexdigest()
        if received_hash != expected_hash:
            utils.log("FAIL", "HASH", "파일 해시 불일치")
            utils.log("INFO", "HASH", f"예상됨: {expected_hash}, 계산됨: {received_hash}")
            utils.log("FAIL", "VERIFY", "파일 무결성 검증 실패")
            return False
            
        utils.log("PASS", "HASH", "파일 해시 검증 성공")
        utils.log("INFO", "HASH", f"계산된 SHA-256: {received_hash}")

        metadata_for_verify = f"{self.filename}|{self.received_size}|{received_hash}".encode("utf-8")

        try:
            sign_verify_start_time = time.perf_counter()
            with oqs.Signature(utils.SIG_ALG) as verifier:
                is_valid = verifier.verify(metadata_for_verify, signature, sig_public_key)
            sign_verify_end_time = time.perf_counter()

            if not is_valid:
                utils.log("FAIL", "SIGN", "서명 검증 실패")
                utils.log("FAIL", "VERIFY", "송신자 인증 실패")
                return False

            utils.log("PASS", "SIGN", f"서명 검증 성공 (소요 시간: {sign_verify_end_time - sign_verify_start_time:.4f} 초)")
            utils.log("PASS", "VERIFY", "송신자 인증 성공")
        except Exception as e:
            utils.log("ERROR", "SIGN", f"서명 검증 오류: {e}", exc_info=True)
            return False

        utils.log("PASS", "VERIFY", "파일 무결성: 통과")
        utils.log("PASS", "VERIFY", "송신자 인증: 통과")
        return True

    def finalize_transfer(self) -> bool:
        """[단계 6] 클라이언트 종료 신호 대기 및 파일 자동 저장"""
        client_signal = utils.recv_with_length(self.conn)
        if client_signal != b"CLIENT_DONE":
            utils.log("ERROR", "TRANSFER", f"예상치 못한 클라이언트 신호: {client_signal}")
            return False

        utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 수신 완료")

        target_dir = SAVE_DIR
        base_name, ext = os.path.splitext(self.filename)
        save_path = os.path.join(target_dir, self.filename)
        counter = 1
        while os.path.exists(save_path):
            save_path = os.path.join(target_dir, f"{base_name}({counter}){ext}")
            counter += 1
            
        if not self.temp_file.closed:
            self.temp_file.close()

        shutil.move(self.temp_path, save_path)
        self.temp_path = None

        utils.log("RESULT", "TRANSFER", f"파일이 자동으로 저장됨: {save_path}")
        return True

    def cleanup(self):
        """소켓 자원 및 임시 파일 정리"""
        self.conn.close()
        utils.log("INFO", "CONNECT", "연결이 종료되었습니다")
        
        try:
            if self.temp_file and not self.temp_file.closed:
                self.temp_file.close()
        except Exception:
            pass
            
        if self.temp_path and os.path.exists(self.temp_path):
            try:
                os.remove(self.temp_path)
                utils.log("INFO", "FILE", "임시 파일이 삭제되었습니다")
            except Exception as e:
                utils.log("ERROR", "FILE", f"임시 파일 삭제 실패: {e}")


def main():
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 서버 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.bind((utils.HOST, utils.PORT))
        s.listen(1)
        
        utils.log("INFO", "SYSTEM", f"PQC 보안 서버 데몬이 시작되었습니다")
        utils.log("INFO", "CONNECT", f"{utils.PORT} 포트에서 수신 대기 중")

        while True:
            utils.log("INFO", "CONNECT", "연결 대기 중")
            conn, addr = s.accept()
            
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            conn.settimeout(15.0)
            
            handler = PQCServerHandler(conn, addr)
            if handler.handle():
                utils.log("RESULT", "TRANSFER", "파일 전송이 완료되었습니다")

if __name__ == "__main__":
    main()
