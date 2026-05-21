import os
import socket
import struct
import time
import zlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils


def ms(start: float, end: float) -> float:
    return (end - start) * 1000


def main():
    total_start = time.perf_counter()

    file_path = utils.select_file()

    if not file_path:
        utils.log("INFO", "FILE", "사용자가 파일 선택을 취소함")
        return

    if not os.path.exists(file_path):
        utils.log("ERROR", "FILE", f"파일을 찾을 수 없음: {file_path}")
        utils.show_error("파일 오류", f"파일을 찾을 수 없습니다.\n\n{file_path}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # =========================================================
            # 1. Server 연결 및 Client 측 Handshake 시간 측정
            # =========================================================
            connect_start = time.perf_counter()

            s.connect((utils.SERVER_IP, utils.PORT))

            connect_end = time.perf_counter()

            utils.log("INFO", "CONNECT", f"Server 연결 완료: {utils.SERVER_IP}:{utils.PORT}")
            utils.log(
                "RESULT",
                "PERF",
                f"Client Server 연결 시간: {ms(connect_start, connect_end):.3f} ms"
            )

            handshake_start = time.perf_counter()

            pk_len_bytes = utils.recv_exact(s, 4)
            pk_len = struct.unpack("!I", pk_len_bytes)[0]

            if pk_len <= 0 or pk_len > 10000:
                raise ValueError(f"잘못된 공개키 길이: {pk_len}")

            public_key = utils.recv_exact(s, pk_len)
            utils.log("INFO", "KEM", f"Server 공개키 수신 완료 ({len(public_key)} bytes)")

            encap_start = time.perf_counter()

            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            encap_end = time.perf_counter()

            utils.log("PASS", "KEM", "Encapsulation 완료")
            utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")
            utils.log(
                "RESULT",
                "PERF",
                f"Client KEM Encapsulation 시간: {ms(encap_start, encap_end):.3f} ms"
            )

            utils.send_with_length(s, kem_ciphertext)
            utils.log("INFO", "KEM", f"Ciphertext 전송 완료 ({len(kem_ciphertext)} bytes)")

            hkdf_start = time.perf_counter()
            session_key = utils.derive_key(shared_secret)
            hkdf_end = time.perf_counter()

            handshake_end = time.perf_counter()

            utils.log("PASS", "KEY", "HKDF 기반 세션 키 생성 완료")
            utils.log("PASS", "KEM", "키 교환 완료")
            utils.log("RESULT", "PERF", f"Client HKDF 시간: {ms(hkdf_start, hkdf_end):.3f} ms")
            utils.log(
                "RESULT",
                "PERF",
                f"Client 전체 키 교환 시간: {ms(handshake_start, handshake_end):.3f} ms"
            )

            # =========================================================
            # 2. 파일 메타데이터 및 해시 시간 측정
            # =========================================================
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)

            hash_start = time.perf_counter()
            file_hash = utils.sha256_file(file_path)
            hash_end = time.perf_counter()

            utils.log("INFO", "FILE", f"선택된 파일명: {filename}")
            utils.log("INFO", "FILE", f"파일 크기: {filesize} bytes")
            utils.log("INFO", "HASH", f"파일 SHA-256 해시값: {file_hash}")
            utils.log(
                "RESULT",
                "PERF",
                f"Client 파일 해시 생성 시간: {ms(hash_start, hash_end):.3f} ms"
            )

            metadata_send_start = time.perf_counter()

            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))
            s.sendall(file_hash.encode("utf-8"))

            metadata_send_end = time.perf_counter()

            utils.log("INFO", "FILE", "파일 메타데이터 전송 완료")
            utils.log(
                "RESULT",
                "PERF",
                f"Client 메타데이터 전송 시간: {ms(metadata_send_start, metadata_send_end):.3f} ms"
            )

            # =========================================================
            # 3. ML-DSA 서명 생성 및 전송 시간 측정
            # =========================================================
            metadata_for_sign = (filename + str(filesize) + file_hash).encode("utf-8")

            sign_start = time.perf_counter()

            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)

            sign_end = time.perf_counter()

            utils.log("PASS", "SIGN", "ML-DSA 서명 생성 완료")
            utils.log("INFO", "SIGN", f"서명 공개키 크기: {len(sig_public_key)} bytes")
            utils.log("INFO", "SIGN", f"서명값 크기: {len(signature)} bytes")
            utils.log(
                "RESULT",
                "PERF",
                f"Client 서명 생성 시간: {ms(sign_start, sign_end):.3f} ms"
            )

            sig_send_start = time.perf_counter()

            utils.send_with_length(s, sig_public_key)
            utils.send_with_length(s, signature)

            sig_send_end = time.perf_counter()

            utils.log("INFO", "SIGN", "서명 공개키 및 서명값 전송 완료")
            utils.log(
                "RESULT",
                "PERF",
                f"Client 서명 데이터 전송 시간: {ms(sig_send_start, sig_send_end):.3f} ms"
            )

            # =========================================================
            # 4. Chunk 압축 / 암호화 / Socket 전송 시간 측정
            # =========================================================
            aesgcm = AESGCM(session_key)

            use_compression = True
            chunk_index = 0
            sent_size = 0

            compression_time_ms = 0.0
            encryption_time_ms = 0.0
            socket_send_time_ms = 0.0

            utils.log("INFO", "CHUNK", f"Chunk 크기: {utils.CHUNK_SIZE} bytes")
            utils.log("INFO", "CHUNK", "Chunk 전송 시작")

            chunk_total_start = time.perf_counter()

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(utils.CHUNK_SIZE)

                    if not chunk:
                        break

                    original_chunk_size = len(chunk)
                    flags = 0x01 if use_compression else 0x00

                    if use_compression:
                        comp_start = time.perf_counter()
                        chunk = zlib.compress(chunk)
                        comp_end = time.perf_counter()
                        compression_time_ms += ms(comp_start, comp_end)

                    enc_start = time.perf_counter()

                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    payload = nonce + encrypted_chunk

                    enc_end = time.perf_counter()
                    encryption_time_ms += ms(enc_start, enc_end)

                    send_start = time.perf_counter()

                    s.sendall(struct.pack("!BQI", flags, chunk_index, len(payload)))
                    s.sendall(payload)

                    send_end = time.perf_counter()
                    socket_send_time_ms += ms(send_start, send_end)

                    sent_size += original_chunk_size

                    utils.log(
                        "INFO",
                        "CHUNK",
                        f"Chunk {chunk_index} 전송 완료 ({sent_size}/{filesize} bytes)"
                    )

                    chunk_index += 1

            chunk_total_end = time.perf_counter()

            utils.log("PASS", "CHUNK", "전체 Chunk 전송 완료")
            utils.log("RESULT", "TRANSFER", "파일 데이터 전송 완료")
            utils.log("RESULT", "PERF", f"Client 압축 시간: {compression_time_ms:.3f} ms")
            utils.log("RESULT", "PERF", f"Client AES-GCM 암호화 시간: {encryption_time_ms:.3f} ms")
            utils.log("RESULT", "PERF", f"Client Socket 전송 시간: {socket_send_time_ms:.3f} ms")
            utils.log(
                "RESULT",
                "PERF",
                f"Client Chunk 암호화/전송 총 시간: {ms(chunk_total_start, chunk_total_end):.3f} ms"
            )
            utils.log("RESULT", "PERF", f"Client 전송 Chunk 수: {chunk_index}")

            # =========================================================
            # 5. CLIENT_DONE 전송 및 전체 Client 처리 시간 측정
            # =========================================================
            done_start = time.perf_counter()

            utils.send_with_length(s, b"CLIENT_DONE")

            done_end = time.perf_counter()

            utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")
            utils.log(
                "RESULT",
                "PERF",
                f"Client CLIENT_DONE 전송 시간: {ms(done_start, done_end):.3f} ms"
            )

            total_end = time.perf_counter()
            utils.log("RESULT", "PERF", f"Client 전체 처리 시간: {ms(total_start, total_end):.3f} ms")

            utils.show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{filename}")

        except Exception as e:
            utils.log("ERROR", "CLIENT", str(e))
            utils.show_error("전송 실패", str(e))


if __name__ == "__main__":
    main()