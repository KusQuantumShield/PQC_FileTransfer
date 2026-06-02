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
    """
    이 스크립트는 파일 전송 도중 악의적인 공격자가 원본 데이터는 정상적으로 보내되,
    최종 무결성 검증을 위한 파일 해시값을 변조하여 전송하는 '해시 변조 공격'을 시뮬레이션합니다.
    """
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

            # 1. 서버의 KEM 공개키 수신
            pk_len_bytes = utils.recv_exact(s, 4)
            pk_len = struct.unpack("!I", pk_len_bytes)[0]
            public_key = utils.recv_exact(s, pk_len)

            # 2. 양자 내성 암호(PQC)를 사용하여 공유 비밀키와 암호문 생성
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            # 3. 암호문을 서버로 전송하고 세션 키 도출
            utils.send_with_length(s, kem_ciphertext)
            session_key = utils.derive_key(shared_secret)

            # 4. 파일 메타데이터(파일명, 크기) 전송
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)

            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))

            # 5. 파일 암호화(AES-GCM) 및 압축 준비
            aesgcm = AESGCM(session_key)
            use_compression = True
            compressor = zlib.compressobj(level=1) if use_compression else None

            # 실시간 해시 계산을 위한 SHA-256 초기화
            file_hasher = hashlib.sha256()

            # Nonce 구성에 사용할 고정 난수 4바이트
            base_nonce_suffix = os.urandom(4)
            chunk_index = 0
            sent_size = 0

            # 6. 파일을 청크 단위로 읽어 암호화 및 전송
            buffer = bytearray(utils.CHUNK_SIZE)
            with open(file_path, "rb") as f:
                while True:
                    bytes_read = f.readinto(buffer)
                    if bytes_read == 0: # 파일의 끝(EOF)
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
                    
                    # 파일 데이터의 실시간 해시 업데이트
                    file_hasher.update(chunk_view)
                    
                    chunk_data = chunk_view

                    # 데이터 압축
                    if use_compression:
                        chunk_data = compressor.compress(chunk_data) + compressor.flush(zlib.Z_SYNC_FLUSH)

                    # Nonce 및 헤더 구성
                    nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                    flags = 0x01 if use_compression else 0x00
                    temp_payload_len = len(nonce) + len(chunk_data) + 16
                    header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                    
                    # AES-GCM으로 데이터 암호화
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                    payload_len = len(nonce) + len(encrypted_chunk)

                    header = struct.pack("!BQI", flags, chunk_index, payload_len)
                    s.sendall(header + nonce)
                    s.sendall(encrypted_chunk)
                    chunk_index += 1

            file_hash = file_hasher.hexdigest()
            
            # --- 공격 핵심 로직 시작 ---
            # 원본 파일의 실제 해시(file_hash) 대신 가짜 해시(sent_hash)를 강제로 할당
            print("[ATTACK] 파일 해시를 모두 '0'으로 채워진 가짜 해시로 변조합니다!")
            sent_hash = '0' * 64
            
            # 변조된 해시값을 서버로 전송
            s.sendall(sent_hash.encode("utf-8"))
            # --- 공격 핵심 로직 끝 ---
            
            # 7. 서명할 메타데이터 구성 (변조된 해시 사용)
            metadata_for_sign = f"{filename}|{sent_size}|{sent_hash}".encode("utf-8")
            
            # PQC 전자서명(ML-DSA 등) 생성
            sig_sec_file = "client_sig_sec.bin"
            sig_pub_file = "client_sig_pub.bin"
            if os.path.exists(sig_sec_file) and os.path.exists(sig_pub_file):
                with open(sig_sec_file, "rb") as f:
                    secret_key = f.read()
                with open(sig_pub_file, "rb") as f:
                    sig_public_key = f.read()
                with oqs.Signature(utils.SIG_ALG, secret_key=secret_key) as signer:
                    signature = signer.sign(metadata_for_sign)
            else:
                with oqs.Signature(utils.SIG_ALG) as signer:
                    sig_public_key = signer.generate_keypair()
                    signature = signer.sign(metadata_for_sign)
                    secret_key = signer.export_secret_key()
                with open(sig_sec_file, "wb") as f:
                    f.write(secret_key)
                with open(sig_pub_file, "wb") as f:
                    f.write(sig_public_key)

            # 8. 서명 공개키와 서명 전송
            utils.send_with_length(s, sig_public_key)
            utils.send_with_length(s, signature)

            utils.send_with_length(s, b"CLIENT_DONE")
            
            # 서버 응답 대기
            try:
                s.settimeout(1.0)
                response = utils.recv_with_length(s).decode("utf-8")
                if response.startswith("ERROR:"):
                    print(f"[ATTACK] 서버가 공격을 정상적으로 차단했습니다: {response[6:]}")
                else:
                    print(f"[ATTACK] 서버 응답: {response}")
            except Exception as e:
                print(f"[ATTACK] 서버가 연결을 종료했습니다 (정상 방어).")
                
            print("[ATTACK] 공격 시나리오 전송 완료")
            
        except Exception as e:
            print(f"[ATTACK] 전송 중 예외 발생 (서버에서 통신을 중단했을 수 있습니다): {e}")

if __name__ == "__main__":
    test_file = "test_hash_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for attack." * 100)
    run_attack_client(test_file)
