import os
import socket
import struct
import time
import zlib
import tempfile
import shutil
import hashlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils


SAVE_DIR = "received_files"


def ms(start: float, end: float) -> float:
    return (end - start) * 1000


def handle_client(conn: socket.socket, addr) -> bool:
    utils.log("INFO", "CONNECT", f"클라이언트 연결됨: {addr}")

    temp_path = None
    total_start = time.perf_counter()

    try:
        # =========================================================
        # 1. ML-KEM Handshake 시간 측정
        # =========================================================
        handshake_start = time.perf_counter()

        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            keygen_start = time.perf_counter()
            public_key = kem.generate_keypair()
            keygen_end = time.perf_counter()

            utils.log("INFO", "KEM", "ML-KEM 키쌍 생성 완료")
            utils.log(
                "RESULT",
                "PERF",
                f"Server KEM 키쌍 생성 시간: {ms(keygen_start, keygen_end):.3f} ms"
            )

            utils.send_with_length(conn, public_key)
            utils.log("INFO", "KEM", f"공개키 전송 완료 ({len(public_key)} bytes)")

            kem_ciphertext = utils.recv_with_length(conn)
            utils.log("INFO", "KEM", f"Ciphertext 수신 완료 ({len(kem_ciphertext)} bytes)")

            decap_start = time.perf_counter()
            shared_secret = kem.decap_secret(kem_ciphertext)
            decap_end = time.perf_counter()

            utils.log("PASS", "KEM", "Decapsulation 완료")
            utils.log(
                "RESULT",
                "PERF",
                f"Server KEM Decapsulation 시간: {ms(decap_start, decap_end):.3f} ms"
            )

        hkdf_start = time.perf_counter()
        session_key = utils.derive_key(shared_secret)
        hkdf_end = time.perf_counter()

        handshake_end = time.perf_counter()

        utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")
        utils.log("PASS", "KEY", "HKDF 기반 세션 키 생성 완료")
        utils.log("PASS", "KEM", "키 교환 완료")
        utils.log("RESULT", "PERF", f"Server HKDF 시간: {ms(hkdf_start, hkdf_end):.3f} ms")
        utils.log(
            "RESULT",
            "PERF",
            f"Server 전체 키 교환 시간: {ms(handshake_start, handshake_end):.3f} ms"
        )

        # =========================================================
        # 2. Metadata 수신 시간 측정
        # =========================================================
        metadata_start = time.perf_counter()

        filename_bytes = utils.recv_with_length(conn)
        filename = os.path.basename(filename_bytes.decode("utf-8"))

        original_filesize = struct.unpack("!Q", utils.recv_exact(conn, 8))[0]
        expected_hash = utils.recv_exact(conn, 64).decode("utf-8")

        metadata_end = time.perf_counter()

        utils.log("INFO", "FILE", f"파일명 수신 완료: {filename}")
        utils.log("INFO", "FILE", f"예상 파일 크기: {original_filesize} bytes")
        utils.log("INFO", "HASH", f"예상 SHA-256 해시값: {expected_hash}")
        utils.log(
            "RESULT",
            "PERF",
            f"Server 메타데이터 수신 시간: {ms(metadata_start, metadata_end):.3f} ms"
        )

        # =========================================================
        # 3. Signature 정보 수신 시간 측정
        # =========================================================
        sig_recv_start = time.perf_counter()

        sig_public_key = utils.recv_with_length(conn)
        signature = utils.recv_with_length(conn)

        sig_recv_end = time.perf_counter()

        utils.log("INFO", "SIGN", f"서명 공개키 수신 완료 ({len(sig_public_key)} bytes)")
        utils.log("INFO", "SIGN", f"서명값 수신 완료 ({len(signature)} bytes)")
        utils.log(
            "RESULT",
            "PERF",
            f"Server 서명 데이터 수신 시간: {ms(sig_recv_start, sig_recv_end):.3f} ms"
        )

        # =========================================================
        # 4. Chunk 수신 / 복호화 / 압축 해제 / 임시 저장 시간 측정
        # =========================================================
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_path = temp_file.name

        utils.log("INFO", "FILE", f"임시 파일 생성 완료: {temp_path}")

        aesgcm = AESGCM(session_key)
        file_hasher = hashlib.sha256()

        received_size = 0
        expected_chunk_index = 0
        chunk_count = 0

        socket_recv_time_ms = 0.0
        decrypt_time_ms = 0.0
        decompress_time_ms = 0.0
        write_hash_time_ms = 0.0

        receive_total_start = time.perf_counter()

        while received_size < original_filesize:
            recv_start = time.perf_counter()

            header = utils.recv_exact(conn, 13)
            flags, chunk_index, payload_len = struct.unpack("!BQI", header)

            if chunk_index != expected_chunk_index:
                raise ValueError(
                    f"Chunk 순서 불일치: expected={expected_chunk_index}, received={chunk_index}"
                )

            if payload_len <= 0:
                raise ValueError("잘못된 payload 길이")

            payload = utils.recv_exact(conn, payload_len)

            recv_end = time.perf_counter()
            socket_recv_time_ms += ms(recv_start, recv_end)

            nonce = payload[:12]
            encrypted_chunk = payload[12:]

            dec_start = time.perf_counter()
            decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
            dec_end = time.perf_counter()
            decrypt_time_ms += ms(dec_start, dec_end)

            if flags & 0x01:
                decomp_start = time.perf_counter()
                decrypted_chunk = zlib.decompress(decrypted_chunk)
                decomp_end = time.perf_counter()
                decompress_time_ms += ms(decomp_start, decomp_end)

            wh_start = time.perf_counter()

            temp_file.write(decrypted_chunk)
            file_hasher.update(decrypted_chunk)

            wh_end = time.perf_counter()
            write_hash_time_ms += ms(wh_start, wh_end)

            received_size += len(decrypted_chunk)

            utils.log(
                "INFO",
                "CHUNK",
                f"Chunk {chunk_index} 수신 완료 ({received_size}/{original_filesize} bytes)"
            )

            expected_chunk_index += 1
            chunk_count += 1

        receive_total_end = time.perf_counter()
        temp_file.close()

        utils.log("PASS", "CHUNK", "전체 Chunk 수신 완료")
        utils.log("RESULT", "PERF", f"Server Socket 수신 시간: {socket_recv_time_ms:.3f} ms")
        utils.log("RESULT", "PERF", f"Server AES-GCM 복호화 시간: {decrypt_time_ms:.3f} ms")
        utils.log("RESULT", "PERF", f"Server 압축 해제 시간: {decompress_time_ms:.3f} ms")
        utils.log(
            "RESULT",
            "PERF",
            f"Server 임시 파일 기록 및 해시 갱신 시간: {write_hash_time_ms:.3f} ms"
        )
        utils.log(
            "RESULT",
            "PERF",
            f"Server 수신/복호화/저장 총 시간: {ms(receive_total_start, receive_total_end):.3f} ms"
        )
        utils.log("RESULT", "PERF", f"Server 수신 Chunk 수: {chunk_count}")

        # =========================================================
        # 5. 검증 시간 측정
        # =========================================================
        verify_start = time.perf_counter()

        size_verify_start = time.perf_counter()

        if received_size != original_filesize:
            utils.log("FAIL", "FILE", "파일 크기 검증 실패")
            return False

        size_verify_end = time.perf_counter()

        utils.log("PASS", "FILE", "파일 크기 검증 성공")
        utils.log(
            "RESULT",
            "PERF",
            f"Server 파일 크기 검증 시간: {ms(size_verify_start, size_verify_end):.3f} ms"
        )

        hash_verify_start = time.perf_counter()
        received_hash = file_hasher.hexdigest()
        hash_verify_end = time.perf_counter()

        if received_hash != expected_hash:
            utils.log("FAIL", "HASH", "파일 해시 검증 실패")
            utils.log("INFO", "HASH", f"예상 해시값: {expected_hash}")
            utils.log("INFO", "HASH", f"계산된 해시값: {received_hash}")
            return False

        utils.log("PASS", "HASH", "파일 해시 검증 성공")
        utils.log(
            "RESULT",
            "PERF",
            f"Server 해시 비교 시간: {ms(hash_verify_start, hash_verify_end):.3f} ms"
        )

        metadata_for_verify = (filename + str(original_filesize) + received_hash).encode("utf-8")

        sig_verify_start = time.perf_counter()

        with oqs.Signature(utils.SIG_ALG) as verifier:
            is_valid = verifier.verify(metadata_for_verify, signature, sig_public_key)

        sig_verify_end = time.perf_counter()

        utils.log(
            "RESULT",
            "PERF",
            f"Server 서명 검증 시간: {ms(sig_verify_start, sig_verify_end):.3f} ms"
        )

        if not is_valid:
            utils.log("FAIL", "SIGN", "서명 검증 실패")
            utils.log("FAIL", "VERIFY", "송신자 인증 실패")
            return False

        verify_end = time.perf_counter()

        utils.log("PASS", "SIGN", "서명 검증 성공")
        utils.log("PASS", "VERIFY", "파일 무결성 검증 성공")
        utils.log("PASS", "VERIFY", "송신자 인증 성공")
        utils.log(
            "RESULT",
            "PERF",
            f"Server 전체 검증 시간: {ms(verify_start, verify_end):.3f} ms"
        )

        # =========================================================
        # 6. CLIENT_DONE 수신 및 최종 저장 시간 측정
        # =========================================================
        done_start = time.perf_counter()
        client_signal = utils.recv_with_length(conn)
        done_end = time.perf_counter()

        if client_signal != b"CLIENT_DONE":
            utils.log("ERROR", "TRANSFER", f"예상하지 못한 Client 신호 수신: {client_signal}")
            return False

        utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 수신 완료")
        utils.log(
            "RESULT",
            "PERF",
            f"Server CLIENT_DONE 수신 시간: {ms(done_start, done_end):.3f} ms"
        )

        save_start = time.perf_counter()

        if not os.path.exists(SAVE_DIR):
            os.makedirs(SAVE_DIR)
            utils.log("INFO", "SYSTEM", f"저장 폴더 생성 완료: {SAVE_DIR}")

        save_path = os.path.join(SAVE_DIR, filename)
        shutil.move(temp_path, save_path)
        temp_path = None

        save_end = time.perf_counter()

        utils.log("RESULT", "TRANSFER", f"파일 저장 완료: {save_path}")
        utils.log("RESULT", "PERF", f"Server 최종 파일 저장 시간: {ms(save_start, save_end):.3f} ms")

        total_end = time.perf_counter()
        utils.log("RESULT", "PERF", f"Server 전체 처리 시간: {ms(total_start, total_end):.3f} ms")

        return True

    except Exception as e:
        utils.log("ERROR", "SERVER", str(e))
        return False

    finally:
        conn.close()
        utils.log("INFO", "CONNECT", "연결 종료")

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
            utils.log("INFO", "FILE", "임시 파일 삭제 완료")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((utils.HOST, utils.PORT))
        s.listen(1)

        utils.log("INFO", "SYSTEM", "PQC 보안 파일 전송 성능 측정 Server 시작")
        utils.log("INFO", "CONNECT", f"{utils.PORT} 포트에서 수신 대기 중")

        while True:
            utils.log("INFO", "CONNECT", "클라이언트 연결 대기 중")
            conn, addr = s.accept()

            if handle_client(conn, addr):
                utils.log("RESULT", "TRANSFER", "파일 전송 처리 완료")


if __name__ == "__main__":
    main()