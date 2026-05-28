import os
import socket
import struct
import zlib
import time
import hashlib

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqc_transfer import utils

def run_attack_client(file_path: str):
    print(f"\n[ATTACK] === 해시 변조 공격(Hash Manipulation Attack) ===")
    
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        
        try:
            s.connect((utils.SERVER_IP, utils.PORT))
            print(f"[ATTACK] 서버({utils.SERVER_IP}:{utils.PORT})에 연결되었습니다.")

            pk_len_bytes = utils.recv_exact(s, 4)
            pk_len = struct.unpack("!I", pk_len_bytes)[0]
            public_key = utils.recv_exact(s, pk_len)

            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            utils.send_with_length(s, kem_ciphertext)
            session_key = utils.derive_key(shared_secret)

            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)

            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))

            aesgcm = AESGCM(session_key)
            use_compression = True
            compressor = zlib.compressobj(level=1) if use_compression else None

            file_hasher = hashlib.sha256()

            base_nonce_suffix = os.urandom(4)
            chunk_index = 0
            sent_size = 0

            buffer = bytearray(utils.CHUNK_SIZE)
            with open(file_path, "rb") as f:
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
                        s.sendall(header + nonce)
                        s.sendall(encrypted_chunk)
                        break
                        
                    chunk_view = memoryview(buffer)[:bytes_read]
                    original_chunk_size = bytes_read
                    sent_size += original_chunk_size
                    is_last_chunk = (sent_size == filesize)
                    
                    file_hasher.update(chunk_view)
                    
                    chunk_data = chunk_view

                    
                    if use_compression:
                        chunk_data = compressor.compress(chunk_data)

                    nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                    flags = 0x01 if use_compression else 0x00
                    temp_payload_len = len(nonce) + len(chunk_data) + 16
                    header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                    
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                    payload_len = len(nonce) + len(encrypted_chunk)

                    header = struct.pack("!BQI", flags, chunk_index, payload_len)
                    s.sendall(header + nonce)
                    s.sendall(encrypted_chunk)
                    chunk_index += 1

            file_hash = file_hasher.hexdigest()
            
            sent_hash = file_hash
            print("[ATTACK] 파일 해시를 모두 '0'으로 채워진 가짜 해시로 변조합니다!")
            sent_hash = '0' * 64
            
            s.sendall(sent_hash.encode("utf-8"))
            
            metadata_for_sign = f"{filename}|{sent_size}|{sent_hash}".encode("utf-8")
            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)



            utils.send_with_length(s, sig_public_key)
            utils.send_with_length(s, signature)

            utils.send_with_length(s, b"CLIENT_DONE")
            print("[ATTACK] 공격 시나리오 전송 완료")
            
        except Exception as e:
            print(f"[ATTACK] 전송 중 예외 발생 (서버에서 통신을 중단했을 수 있습니다): {e}")

if __name__ == "__main__":
    test_file = "test_hash_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for attack." * 100)
    run_attack_client(test_file)
