import os
import socket
import struct
import zlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils

def main():
    # 1. 사용자에게 전송할 파일을 선택받음
    file_path = utils.select_file()

    if not file_path:
        utils.log("INFO", "FILE", "File selection cancelled by user")
        return

    if not os.path.exists(file_path):
        utils.log("ERROR", "FILE", f"File not found: {file_path}")
        utils.show_error("파일 오류", f"파일을 찾을 수 없습니다.\n\n{file_path}")
        return

    # TCP IPv4 소켓 생성
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # =========================================================
            # [단계 1] 서버 접속 및 핸드셰이크 (KEM을 이용한 키 교환)
            # =========================================================
            s.connect((utils.SERVER_IP, utils.PORT))
            utils.log("INFO", "CONNECT", f"Connected to server {utils.SERVER_IP}:{utils.PORT}")

            # 서버가 보낸 양자 내성 공개키(Public Key)를 수신
            pk_len_bytes = utils.recv_exact(s, 4)
            pk_len = struct.unpack("!I", pk_len_bytes)[0]
            
            if pk_len <= 0 or pk_len > 10000:
                utils.log("FAIL", "KEM", f"Invalid public key length: {pk_len}")
                raise ValueError("Invalid public key length")

            public_key = utils.recv_exact(s, pk_len)
            utils.log("INFO", "KEM", f"Server public key received ({len(public_key)} bytes)")

            # KEM 알고리즘을 사용하여 서버의 공개키로 공유 비밀키를 캡슐화
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            utils.log("PASS", "KEM", "Encapsulation completed")
            utils.log("INFO", "KEY", f"Shared Secret Hash: {utils.hash_ss(shared_secret)}")

            # === 테스트 시나리오: KEM ciphertext 변조 === 
            utils.log("WARN", "TEST", "Simulated invalid KEM ciphertext")
            kem_ciphertext = bytearray(kem_ciphertext)
            kem_ciphertext[0] ^= 0xFF
            kem_ciphertext = bytes(kem_ciphertext)
            # ==========================================

            # 생성된 KEM 암호문을 서버로 전송
            utils.send_with_length(s, kem_ciphertext)
            utils.log("INFO", "KEM", f"Ciphertext sent ({len(kem_ciphertext)} bytes)")

            # 교환된 공유 비밀키(shared_secret)를 HKDF를 통해 안전한 32바이트 세션 키로 도출
            session_key = utils.derive_key(shared_secret)
            utils.log("PASS", "KEY", "Session key derived by HKDF")
            utils.log("PASS", "KEM", "Handshake complete")

            # =========================================================
            # [단계 2] 전송할 파일의 메타데이터 생성 및 전송
            # =========================================================
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)
            file_hash = utils.sha256_file(file_path)

            utils.log("INFO", "FILE", f"Selected file: {filename}")
            utils.log("INFO", "FILE", f"File size: {filesize} bytes")
            utils.log("INFO", "HASH", f"File SHA-256: {file_hash}")

            # 파일명, 파일 크기, 파일 해시를 차례대로 서버에 전송
            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))
            s.sendall(file_hash.encode("utf-8"))

            utils.log("INFO", "FILE", "File metadata sent")

            # =========================================================
            # [단계 3] 메타데이터에 대한 전자서명 생성 (데이터 인증)
            # =========================================================
            metadata_for_sign = (filename + str(filesize) + file_hash).encode("utf-8")

            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)

            utils.log("PASS", "SIGN", "ML-DSA signature generated")
            utils.log("INFO", "SIGN", f"Signature public key size: {len(sig_public_key)} bytes")
            utils.log("INFO", "SIGN", f"Signature size: {len(signature)} bytes")

            # 서버가 서명을 검증할 수 있도록 클라이언트가 생성한 서명 검증용 공개키를 전송
            utils.send_with_length(s, sig_public_key)
            utils.log("INFO", "SIGN", "Signature public key sent")

            # 생성된 서명 데이터를 전송
            utils.send_with_length(s, signature)
            utils.log("INFO", "SIGN", "Signature sent")

            # =========================================================
            # [단계 4] 대칭키 암호화(AES-GCM) 기반 대용량 파일 전송
            # =========================================================
            aesgcm = AESGCM(session_key)
            use_compression = True
            chunk_index = 0
            sent_size = 0

            utils.log("INFO", "CHUNK", f"Chunk size: {utils.CHUNK_SIZE} bytes")
            utils.log("INFO", "CHUNK", "Chunk transfer started")

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(utils.CHUNK_SIZE)
                    if not chunk:
                        break

                    original_chunk_size = len(chunk)
                    flags = 0x01 if use_compression else 0x00

                    if use_compression:
                        chunk = zlib.compress(chunk)

                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    payload = nonce + encrypted_chunk

                    # [청크 헤더 구조: 총 13바이트]
                    s.sendall(struct.pack("!BQI", flags, chunk_index, len(payload)))
                    # [청크 데이터 전송]
                    s.sendall(payload)

                    sent_size += original_chunk_size
                    utils.log("INFO", "CHUNK", f"Sent chunk {chunk_index} ({sent_size}/{filesize} bytes)")
                    chunk_index += 1

            utils.log("PASS", "CHUNK", "All chunks sent successfully")
            utils.log("RESULT", "TRANSFER", "File data transfer completed")

            # =========================================================
            # [단계 5] 마무리 및 종료 신호 전송
            # =========================================================
            utils.show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{filename}")

            utils.send_with_length(s, b"CLIENT_DONE")
            utils.log("INFO", "TRANSFER", "CLIENT_DONE signal sent")

        except Exception as e:
            utils.log("ERROR", "CLIENT", str(e))
            utils.show_error("전송 실패", str(e))


if __name__ == "__main__":
    main()
