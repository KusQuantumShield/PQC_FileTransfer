<<<<<<< HEAD
import os
import socket
import struct
import zlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils


def main():
    # 1. 전송할 파일 선택
    file_path = utils.select_file()

    if not file_path:
        utils.log("INFO", "FILE", "File selection cancelled by user")
        return

    if not os.path.exists(file_path):
        utils.log("ERROR", "FILE", f"File not found: {file_path}")
        utils.show_error("파일 오류", f"파일을 찾을 수 없습니다.\n\n{file_path}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # =========================================================
            # [단계 1] Server 연결 및 ML-KEM 키 교환
            # =========================================================
            s.connect((utils.SERVER_IP, utils.PORT))
            utils.log("INFO", "CONNECT", f"Connected to server {utils.SERVER_IP}:{utils.PORT}")

            # Server 공개키 수신
            pk_len_bytes = utils.recv_exact(s, 4)
            pk_len = struct.unpack("!I", pk_len_bytes)[0]

            if pk_len <= 0 or pk_len > 10000:
                utils.log("FAIL", "KEM", f"Invalid public key length: {pk_len}")
                raise ValueError("Invalid public key length")

            public_key = utils.recv_exact(s, pk_len)
            utils.log("INFO", "KEM", f"Server public key received ({len(public_key)} bytes)")

            # Encapsulation 수행
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            utils.log("PASS", "KEM", "Encapsulation completed")
            utils.log("INFO", "KEY", f"Shared Secret Hash: {utils.hash_ss(shared_secret)}")

            # KEM ciphertext 전송
            utils.send_with_length(s, kem_ciphertext)
            utils.log("INFO", "KEM", f"Ciphertext sent ({len(kem_ciphertext)} bytes)")

            # Session key 생성
            session_key = utils.derive_key(shared_secret)
            utils.log("PASS", "KEY", "Session key derived by HKDF")
            utils.log("PASS", "KEM", "Handshake complete")

            # =========================================================
            # [단계 2] 파일 메타데이터 생성 및 전송
            # =========================================================
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)
            file_hash = utils.sha256_file(file_path)

            utils.log("INFO", "FILE", f"Selected file: {filename}")
            utils.log("INFO", "FILE", f"File size: {filesize} bytes")
            utils.log("INFO", "HASH", f"File SHA-256: {file_hash}")

            # filename, filesize, file_hash 전송
            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))
            s.sendall(file_hash.encode("utf-8"))

            utils.log("INFO", "FILE", "File metadata sent")

            # =========================================================
            # [단계 3] ML-DSA 서명 생성 및 전송
            # =========================================================
            metadata_for_sign = (
                filename +
                str(filesize) +
                file_hash
            ).encode("utf-8")

            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)

            utils.log("PASS", "SIGN", "ML-DSA signature generated")
            utils.log("INFO", "SIGN", f"Signature public key size: {len(sig_public_key)} bytes")
            utils.log("INFO", "SIGN", f"Signature size: {len(signature)} bytes")

            utils.send_with_length(s, sig_public_key)
            utils.log("INFO", "SIGN", "Signature public key sent")

            utils.send_with_length(s, signature)
            utils.log("INFO", "SIGN", "Signature sent")

            # =========================================================
            # [단계 4] 파일 Chunk 암호화 및 Payload 손상 테스트
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

                    # 선택적 압축
                    if use_compression:
                        chunk = zlib.compress(chunk)

                    # AES-GCM 암호화
                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    payload = nonce + encrypted_chunk

                    # =================================================
                    # 테스트 시나리오: 암호화 후 payload 손상
                    # 첫 번째 chunk의 payload 마지막 바이트를 변조
                    # =================================================
                    if chunk_index == 0:
                        utils.log("WARN", "TEST", "Simulated damaged encrypted payload")

                        payload = bytearray(payload)
                        payload[-1] ^= 0xFF
                        payload = bytes(payload)

                    # chunk header 전송
                    # flags(1 byte) + chunk_index(8 bytes) + payload_length(4 bytes)
                    s.sendall(struct.pack("!BQI", flags, chunk_index, len(payload)))

                    # 손상된 payload 전송
                    s.sendall(payload)

                    sent_size += original_chunk_size

                    utils.log(
                        "INFO",
                        "CHUNK",
                        f"Sent chunk {chunk_index} ({sent_size}/{filesize} bytes)"
                    )

                    chunk_index += 1

            # =========================================================
            # [단계 5] 테스트 종료 처리
            # =========================================================
            utils.log("WARN", "TEST", "Payload damage test completed on client side")
            utils.log("WARN", "TEST", "Check server log for AES-GCM decryption failure")

            # 테스트 상황에서는 Client 기준 성공 팝업을 띄우지 않음
            # Server가 복호화 실패를 감지하는지가 핵심이기 때문
            try:
                utils.send_with_length(s, b"CLIENT_DONE")
                utils.log("INFO", "TRANSFER", "CLIENT_DONE signal sent")
            except Exception as e:
                utils.log("WARN", "TRANSFER", f"CLIENT_DONE could not be sent: {e}")

        except Exception as e:
            utils.log("ERROR", "CLIENT", str(e))
            utils.show_error("전송 실패", str(e))


if __name__ == "__main__":
=======
import os
import socket
import struct
import zlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils


def main():
    # 1. 전송할 파일 선택
    file_path = utils.select_file()

    if not file_path:
        utils.log("INFO", "FILE", "File selection cancelled by user")
        return

    if not os.path.exists(file_path):
        utils.log("ERROR", "FILE", f"File not found: {file_path}")
        utils.show_error("파일 오류", f"파일을 찾을 수 없습니다.\n\n{file_path}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # =========================================================
            # [단계 1] Server 연결 및 ML-KEM 키 교환
            # =========================================================
            s.connect((utils.SERVER_IP, utils.PORT))
            utils.log("INFO", "CONNECT", f"Connected to server {utils.SERVER_IP}:{utils.PORT}")

            # Server 공개키 수신
            pk_len_bytes = utils.recv_exact(s, 4)
            pk_len = struct.unpack("!I", pk_len_bytes)[0]

            if pk_len <= 0 or pk_len > 10000:
                utils.log("FAIL", "KEM", f"Invalid public key length: {pk_len}")
                raise ValueError("Invalid public key length")

            public_key = utils.recv_exact(s, pk_len)
            utils.log("INFO", "KEM", f"Server public key received ({len(public_key)} bytes)")

            # Encapsulation 수행
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            utils.log("PASS", "KEM", "Encapsulation completed")
            utils.log("INFO", "KEY", f"Shared Secret Hash: {utils.hash_ss(shared_secret)}")

            # KEM ciphertext 전송
            utils.send_with_length(s, kem_ciphertext)
            utils.log("INFO", "KEM", f"Ciphertext sent ({len(kem_ciphertext)} bytes)")

            # Session key 생성
            session_key = utils.derive_key(shared_secret)
            utils.log("PASS", "KEY", "Session key derived by HKDF")
            utils.log("PASS", "KEM", "Handshake complete")

            # =========================================================
            # [단계 2] 파일 메타데이터 생성 및 전송
            # =========================================================
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)
            file_hash = utils.sha256_file(file_path)

            utils.log("INFO", "FILE", f"Selected file: {filename}")
            utils.log("INFO", "FILE", f"File size: {filesize} bytes")
            utils.log("INFO", "HASH", f"File SHA-256: {file_hash}")

            # filename, filesize, file_hash 전송
            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))
            s.sendall(file_hash.encode("utf-8"))

            utils.log("INFO", "FILE", "File metadata sent")

            # =========================================================
            # [단계 3] ML-DSA 서명 생성 및 전송
            # =========================================================
            metadata_for_sign = (
                filename +
                str(filesize) +
                file_hash
            ).encode("utf-8")

            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)

            utils.log("PASS", "SIGN", "ML-DSA signature generated")
            utils.log("INFO", "SIGN", f"Signature public key size: {len(sig_public_key)} bytes")
            utils.log("INFO", "SIGN", f"Signature size: {len(signature)} bytes")

            utils.send_with_length(s, sig_public_key)
            utils.log("INFO", "SIGN", "Signature public key sent")

            utils.send_with_length(s, signature)
            utils.log("INFO", "SIGN", "Signature sent")

            # =========================================================
            # [단계 4] 파일 Chunk 암호화 및 Payload 손상 테스트
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

                    # 선택적 압축
                    if use_compression:
                        chunk = zlib.compress(chunk)

                    # AES-GCM 암호화
                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    payload = nonce + encrypted_chunk

                    # =================================================
                    # 테스트 시나리오: 암호화 후 payload 손상
                    # 첫 번째 chunk의 payload 마지막 바이트를 변조
                    # =================================================
                    if chunk_index == 0:
                        utils.log("WARN", "TEST", "Simulated damaged encrypted payload")

                        payload = bytearray(payload)
                        payload[-1] ^= 0xFF
                        payload = bytes(payload)

                    # chunk header 전송
                    # flags(1 byte) + chunk_index(8 bytes) + payload_length(4 bytes)
                    s.sendall(struct.pack("!BQI", flags, chunk_index, len(payload)))

                    # 손상된 payload 전송
                    s.sendall(payload)

                    sent_size += original_chunk_size

                    utils.log(
                        "INFO",
                        "CHUNK",
                        f"Sent chunk {chunk_index} ({sent_size}/{filesize} bytes)"
                    )

                    chunk_index += 1

            # =========================================================
            # [단계 5] 테스트 종료 처리
            # =========================================================
            utils.log("WARN", "TEST", "Payload damage test completed on client side")
            utils.log("WARN", "TEST", "Check server log for AES-GCM decryption failure")

            # 테스트 상황에서는 Client 기준 성공 팝업을 띄우지 않음
            # Server가 복호화 실패를 감지하는지가 핵심이기 때문
            try:
                utils.send_with_length(s, b"CLIENT_DONE")
                utils.log("INFO", "TRANSFER", "CLIENT_DONE signal sent")
            except Exception as e:
                utils.log("WARN", "TRANSFER", f"CLIENT_DONE could not be sent: {e}")

        except Exception as e:
            utils.log("ERROR", "CLIENT", str(e))
            utils.show_error("전송 실패", str(e))


if __name__ == "__main__":
>>>>>>> 0b30b823d56df3b731c30da2a5f6bbce69de3a03
    main()