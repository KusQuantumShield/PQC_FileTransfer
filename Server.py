import os
import socket
import struct
import hashlib
import zlib
import tempfile
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox

import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HOST = "0.0.0.0"
PORT = 9999

KEM_NAME = "Kyber768"
SIG_NAME = "Dilithium3"


def log(level: str, module: str, message: str):
    print(f"[{level}][{module}] {message}")


# shared secret을 직접 출력하지 않고 해시값으로 확인
def hash_ss(shared_secret: bytes) -> str:
    return hashlib.sha256(shared_secret).hexdigest()


# shared secret을 AES-GCM용 session key로 파생
def derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    )
    return hkdf.derive(shared_secret)


# TCP에서 지정한 길이만큼 정확히 수신
def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = b""

    while len(data) < length:
        packet = sock.recv(length - len(data))

        if not packet:
            raise ConnectionError("Connection closed")

        data += packet

    return data


# [길이 + 데이터] 형식으로 들어오는 데이터 수신
def recv_with_length(sock: socket.socket) -> bytes:
    data_len = struct.unpack("!I", recv_exact(sock, 4))[0]

    if data_len < 0:
        raise ValueError("Invalid length")

    return recv_exact(sock, data_len)


# 수신한 파일을 저장할 폴더 선택 GUI
def select_save_directory(filename: str) -> str:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    messagebox.showinfo(
        "저장 위치 선택",
        f"수신된 파일: {filename}\n저장할 폴더를 선택하세요."
    )

    folder = filedialog.askdirectory(title="파일 저장 폴더 선택")
    root.destroy()

    return folder


def show_info(title: str, message: str) -> None:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    messagebox.showinfo(title, message)
    root.destroy()


# ML-KEM 기반 키 교환 수행
def perform_kem_handshake(conn: socket.socket) -> bytes:
    # Server 측 ML-KEM 키쌍 생성
    with oqs.KeyEncapsulation(KEM_NAME) as kem:
        public_key = kem.generate_keypair()
        log("INFO", "KEM", "ML-KEM keypair generated")

        # Client에게 공개키 전송
        conn.sendall(struct.pack("!I", len(public_key)))
        conn.sendall(public_key)
        log("INFO", "KEM", f"Public key sent ({len(public_key)} bytes)")

        # Client가 보낸 KEM ciphertext 수신
        kem_ciphertext = recv_with_length(conn)
        log("INFO", "KEM", f"Ciphertext received ({len(kem_ciphertext)} bytes)")

        if len(kem_ciphertext) <= 0 or len(kem_ciphertext) > 10000:
            log("FAIL", "KEM", "Invalid ciphertext length")
            raise ValueError("Invalid ciphertext length")

        # Decapsulation 수행 후 shared secret 복원
        try:
            shared_secret = kem.decap_secret(kem_ciphertext)
        except Exception as e:
            log("ERROR", "KEM", f"Decapsulation failed: {e}")
            raise

    log("PASS", "KEM", "Decapsulation completed")
    log("INFO", "KEY", f"Shared Secret Hash: {hash_ss(shared_secret)}")

    # shared secret으로부터 session key 생성
    session_key = derive_key(shared_secret)

    log("PASS", "KEY", "Session key derived by HKDF")
    log("PASS", "KEM", "Handshake complete")

    return session_key


# Client가 전송한 파일 메타데이터 수신
def receive_metadata(conn: socket.socket):
    filename_bytes = recv_with_length(conn)
    filename = os.path.basename(filename_bytes.decode("utf-8"))

    if not filename:
        log("FAIL", "FILE", "Invalid filename")
        raise ValueError("Invalid filename")

    original_filesize = struct.unpack(
        "!Q",
        recv_exact(conn, 8)
    )[0]

    expected_hash = recv_exact(
        conn,
        64
    ).decode("utf-8")

    log("INFO", "FILE", f"Filename received: {filename}")
    log("INFO", "FILE", f"Expected file size: {original_filesize} bytes")
    log("INFO", "HASH", f"Expected SHA-256: {expected_hash}")

    return filename, original_filesize, expected_hash


# ML-DSA 서명 공개키와 서명값 수신
def receive_signature(conn: socket.socket):
    sig_public_key = recv_with_length(conn)
    log("INFO", "SIGN", f"Signature public key received ({len(sig_public_key)} bytes)")

    signature = recv_with_length(conn)
    log("INFO", "SIGN", f"Signature received ({len(signature)} bytes)")

    return sig_public_key, signature


# chunk 단위 파일 수신, 복호화, 압축 해제, 임시 파일 저장
def receive_file_chunks(
    conn: socket.socket,
    session_key: bytes,
    original_filesize: int
):
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_path = temp_file.name

    log("INFO", "FILE", f"Temporary file created: {temp_path}")

    aesgcm = AESGCM(session_key)
    file_hasher = hashlib.sha256()

    received_size = 0
    expected_chunk_index = 0

    while received_size < original_filesize:
        # chunk header: flags + chunk_index + payload_length
        header = recv_exact(conn, 13)
        flags, chunk_index, payload_len = struct.unpack(
            "!BQI",
            header
        )

        # chunk 순서 검증
        if chunk_index != expected_chunk_index:
            log(
                "ERROR",
                "CHUNK",
                f"Chunk index mismatch: expected={expected_chunk_index}, received={chunk_index}"
            )
            raise ValueError(
                f"Chunk index mismatch "
                f"(expected={expected_chunk_index}, got={chunk_index})"
            )

        if payload_len <= 0:
            log("ERROR", "CHUNK", "Invalid payload length")
            raise ValueError("Invalid payload length")

        payload = recv_exact(conn, payload_len)

        nonce = payload[:12]
        encrypted_chunk = payload[12:]

        # AES-GCM 기반 chunk 복호화
        try:
            decrypted_chunk = aesgcm.decrypt(
                nonce,
                encrypted_chunk,
                None
            )
        except Exception as e:
            log("ERROR", "CHUNK", f"Chunk decryption failed at index={chunk_index}: {e}")
            raise

        # 압축 플래그가 설정된 경우 zlib 압축 해제
        if flags & 0x01:
            try:
                decrypted_chunk = zlib.decompress(decrypted_chunk)
            except Exception as e:
                log("ERROR", "CHUNK", f"Chunk decompression failed at index={chunk_index}: {e}")
                raise

        # 복호화된 chunk를 임시 파일에 즉시 기록
        temp_file.write(decrypted_chunk)

        # 파일 해시 계산을 위해 chunk 단위로 업데이트
        file_hasher.update(decrypted_chunk)

        received_size += len(decrypted_chunk)

        log(
            "INFO",
            "CHUNK",
            f"Received chunk {chunk_index} ({received_size}/{original_filesize} bytes)"
        )

        expected_chunk_index += 1

    temp_file.close()

    log("PASS", "CHUNK", "All chunks received successfully")

    received_hash = file_hasher.hexdigest()

    return temp_path, received_size, received_hash


# 파일 크기 검증
def verify_file_size(received_size: int, original_filesize: int) -> bool:
    if received_size != original_filesize:
        log("FAIL", "FILE", "File size mismatch")
        log("INFO", "FILE", f"Expected: {original_filesize}")
        log("INFO", "FILE", f"Received: {received_size}")
        return False

    log("PASS", "FILE", "File size verification success")
    return True


# SHA-256 기반 파일 무결성 검증
def verify_file_hash(received_hash: str, expected_hash: str) -> bool:
    if received_hash != expected_hash:
        log("FAIL", "HASH", "File hash mismatch")
        log("INFO", "HASH", f"Expected: {expected_hash}")
        log("INFO", "HASH", f"Calculated: {received_hash}")
        log("FAIL", "VERIFY", "File integrity verification failed")
        return False

    log("PASS", "HASH", "File hash verification success")
    log("INFO", "HASH", f"Calculated SHA-256: {received_hash}")
    log("PASS", "VERIFY", "File integrity: PASS")

    return True


# ML-DSA 기반 송신자 인증 검증
def verify_signature(
    filename: str,
    original_filesize: int,
    received_hash: str,
    signature: bytes,
    sig_public_key: bytes
) -> bool:
    # Client가 서명한 데이터와 동일한 구조로 검증 데이터 재구성
    metadata_for_verify = (
        filename +
        str(original_filesize) +
        received_hash
    ).encode("utf-8")

    try:
        with oqs.Signature(SIG_NAME) as verifier:
            is_valid = verifier.verify(
                metadata_for_verify,
                signature,
                sig_public_key
            )

        if not is_valid:
            log("FAIL", "SIGN", "Signature verification failed")
            log("FAIL", "VERIFY", "Sender authentication failed")
            return False

        log("PASS", "SIGN", "Signature verification success")
        log("PASS", "VERIFY", "Sender authentication: PASS")
        return True

    except Exception as e:
        log("ERROR", "SIGN", f"Signature verification error: {e}")
        return False


# Client의 전송 완료 신호 수신
def receive_done_signal(conn: socket.socket) -> bool:
    client_signal = recv_with_length(conn)

    if client_signal != b"CLIENT_DONE":
        log("ERROR", "TRANSFER", f"Unexpected client signal: {client_signal}")
        return False

    log("INFO", "TRANSFER", "CLIENT_DONE signal received")
    return True


# 검증이 완료된 파일을 사용자가 선택한 경로로 저장
def save_received_file(temp_path: str, filename: str) -> bool:
    save_dir = select_save_directory(filename)

    if not save_dir:
        log("FAIL", "FILE", "Save cancelled by user")
        return False

    save_path = os.path.join(save_dir, filename)

    shutil.move(temp_path, save_path)

    log("RESULT", "TRANSFER", f"File saved successfully: {save_path}")

    show_info(
        "수신 완료",
        f"파일 저장 완료\n\n{save_path}"
    )

    return True


# Client 1개에 대한 전체 처리 흐름
def handle_client(conn: socket.socket, addr) -> bool:
    log("INFO", "CONNECT", f"Client connected: {addr}")

    temp_path = None

    try:
        # 1. ML-KEM 키 교환 및 session key 생성
        session_key = perform_kem_handshake(conn)

        # 2. 파일 메타데이터 수신
        filename, original_filesize, expected_hash = receive_metadata(conn)

        # 3. ML-DSA 서명 공개키 및 서명값 수신
        sig_public_key, signature = receive_signature(conn)

        # 4. chunk 기반 파일 수신 및 해시 계산
        temp_path, received_size, received_hash = receive_file_chunks(
            conn,
            session_key,
            original_filesize
        )

        # 5. 파일 크기 검증
        if not verify_file_size(received_size, original_filesize):
            return False

        # 6. 파일 해시 검증
        if not verify_file_hash(received_hash, expected_hash):
            return False

        # 7. ML-DSA 서명 검증
        if not verify_signature(
            filename,
            original_filesize,
            received_hash,
            signature,
            sig_public_key
        ):
            return False

        # 8. Client 완료 신호 수신
        if not receive_done_signal(conn):
            return False

        # 9. 파일 저장
        if not save_received_file(temp_path, filename):
            return False

        temp_path = None
        return True

    except Exception as e:
        log("ERROR", "SERVER", str(e))
        return False

    finally:
        conn.close()
        log("INFO", "CONNECT", "Connection closed")

        # 오류 발생 시 임시 파일 삭제
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
            log("INFO", "FILE", "Temporary file removed")


# Server socket 생성 및 Client 연결 대기
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)

        log("INFO", "CONNECT", f"Listening on {PORT}")

        while True:
            log("INFO", "CONNECT", "Waiting for connection")
            conn, addr = server_socket.accept()

            if handle_client(conn, addr):
                log("RESULT", "TRANSFER", "File transfer finished")
                break


if __name__ == "__main__":
    main()