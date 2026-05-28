import os
import socket
import struct
import zlib
import time
import hashlib
import sys

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import utils

class PQCClient:
    """
    서버와 파일 송수신을 담당하는 클라이언트 클래스
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.filename = os.path.basename(file_path)
        self.filesize = os.path.getsize(file_path)
        self.socket = None
        self.session_key = None
        self.file_hasher = hashlib.sha256()
        self.sent_size = 0
        self.file_hash = None

    def transfer(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self.socket = s
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            
            try:
                self.socket.connect((utils.SERVER_IP, utils.PORT))
                utils.log("INFO", "CONNECT", f"서버 {utils.SERVER_IP}:{utils.PORT}에 연결되었습니다")

                self.perform_handshake()
                self.send_metadata()
                self.transfer_file_chunks()
                self.create_and_send_signature()
                self.finalize_transfer()

            except Exception as e:
                utils.log("ERROR", "CLIENT", str(e), exc_info=True)
                utils.show_error("전송 실패", str(e))

    def perform_handshake(self):
        kem_start_time = time.perf_counter()
        
        pk_len_bytes = utils.recv_exact(self.socket, 4)
        pk_len = struct.unpack("!I", pk_len_bytes)[0]
        
        if pk_len <= 0 or pk_len > 10000:
            utils.log("FAIL", "KEM", f"유효하지 않은 공개키 길이: {pk_len}")
            raise ValueError("Invalid public key length")

        public_key = utils.recv_exact(self.socket, pk_len)
        utils.log("INFO", "KEM", f"서버 공개키를 수신했습니다 ({len(public_key)} 바이트)")

        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        utils.log("PASS", "KEM", "캡슐화 완료")
        utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")

        utils.send_with_length(self.socket, kem_ciphertext)
        utils.log("INFO", "KEM", f"암호문 전송 완료 ({len(kem_ciphertext)} 바이트)")

        self.session_key = utils.derive_key(shared_secret)
        kem_end_time = time.perf_counter()
        utils.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
        utils.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")

    def send_metadata(self):
        utils.log("INFO", "FILE", f"선택된 파일: {self.filename}")
        utils.log("INFO", "FILE", f"파일 크기: {self.filesize} 바이트")

        filename_bytes = self.filename.encode("utf-8")
        utils.send_with_length(self.socket, filename_bytes)
        self.socket.sendall(struct.pack("!Q", self.filesize))

        utils.log("INFO", "FILE", "초기 파일 메타데이터 전송 완료")

    def transfer_file_chunks(self):
        aesgcm = AESGCM(self.session_key)
        
        uncompressible_exts = {'.zip', '.rar', '.7z', '.gz', '.mp4', '.avi', '.mkv', '.jpg', '.jpeg', '.png', '.pdf', '.gif', '.webp'}
        ext = os.path.splitext(self.filename)[1].lower()
        use_compression = ext not in uncompressible_exts
        
        if not use_compression:
            utils.log("INFO", "COMPRESS", f"'{ext}' 파일은 이미 압축/암호화되어 있어 Zlib 스트리밍 압축을 생략합니다.")
            
        chunk_index = 0
        compressor = zlib.compressobj(level=1) if use_compression else None

        utils.log("INFO", "CHUNK", f"청크 크기: {utils.CHUNK_SIZE} 바이트")
        utils.log("INFO", "CHUNK", "청크 전송 시작")

        transfer_start_time = time.perf_counter()
        base_nonce_suffix = os.urandom(4)

        buffer = bytearray(utils.CHUNK_SIZE)
        with open(self.file_path, "rb") as f:
            while True:
                bytes_read = f.readinto(buffer)
                
                if bytes_read == 0:
                    flags = 0x03 if use_compression else 0x02
                    chunk_data = compressor.flush(zlib.Z_FINISH) if use_compression else b""
                    
                    nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                    temp_payload_len = len(nonce) + len(chunk_data) + 16
                    header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                    
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                    payload_len = len(nonce) + len(encrypted_chunk)
                    header = struct.pack("!BQI", flags, chunk_index, payload_len)
                    
                    self.socket.sendall(header + nonce)
                    self.socket.sendall(encrypted_chunk)
                    break
                    
                chunk_view = memoryview(buffer)[:bytes_read]
                self.file_hasher.update(chunk_view)
                
                flags = 0x01 if use_compression else 0x00
                chunk_data = compressor.compress(chunk_view) if use_compression else chunk_view

                nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                temp_payload_len = len(nonce) + len(chunk_data) + 16
                header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                
                encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                payload_len = len(nonce) + len(encrypted_chunk)
                header = struct.pack("!BQI", flags, chunk_index, payload_len)
                
                self.socket.sendall(header + nonce)
                self.socket.sendall(encrypted_chunk)
                
                self.sent_size += bytes_read
                utils.log("INFO", "CHUNK", f"청크 {chunk_index} 전송 완료 ({self.sent_size}/{self.filesize} 바이트)")
                chunk_index += 1

        transfer_end_time = time.perf_counter()
        self.file_hash = self.file_hasher.hexdigest()
        
        utils.log("PASS", "CHUNK", "모든 청크 전송 완료")
        utils.log("RESULT", "TRANSFER", f"파일 데이터 전송 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")
        utils.log("INFO", "HASH", f"최종 파일 SHA-256: {self.file_hash}")

    def create_and_send_signature(self):
        self.socket.sendall(self.file_hash.encode("utf-8"))
        metadata_for_sign = f"{self.filename}|{self.sent_size}|{self.file_hash}".encode("utf-8")

        sign_start_time = time.perf_counter()
        with oqs.Signature(utils.SIG_ALG) as signer:
            sig_public_key = signer.generate_keypair()
            signature = signer.sign(metadata_for_sign)
        sign_end_time = time.perf_counter()

        utils.log("PASS", "SIGN", f"ML-DSA 서명 생성 완료 (소요 시간: {sign_end_time - sign_start_time:.4f} 초)")
        utils.log("INFO", "SIGN", f"서명 공개키 크기: {len(sig_public_key)} 바이트")
        utils.log("INFO", "SIGN", f"서명 크기: {len(signature)} 바이트")

        utils.send_with_length(self.socket, sig_public_key)
        utils.log("INFO", "SIGN", "서명 공개키 전송 완료")

        utils.send_with_length(self.socket, signature)
        utils.log("INFO", "SIGN", "서명 전송 완료")

    def finalize_transfer(self):
        utils.send_with_length(self.socket, b"CLIENT_DONE")
        utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")
        utils.show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{self.filename}")


def main():
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 클라이언트 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = utils.select_file()

    if not file_path:
        utils.log("INFO", "FILE", "사용자가 파일 선택을 취소했습니다")
        return

    if not os.path.exists(file_path):
        utils.log("ERROR", "FILE", f"파일을 찾을 수 없습니다: {file_path}")
        utils.show_error("파일 오류", f"파일을 찾을 수 없습니다.\n\n{file_path}")
        return

    client = PQCClient(file_path)
    client.transfer()

if __name__ == "__main__":
    main()
