import os
import socket
import struct
import hashlib
import zlib
import tkinter as tk
from tkinter import filedialog, messagebox

import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SERVER_IP = "127.0.0.1"
PORT = 9999
CHUNK_SIZE = 1024 * 1024  # 1MB

KEM_NAME = "Kyber768"
SIG_NAME = "Dilithium3"


def log(level: str, module: str, message: str):
    print(f"[{level}][{module}] {message}")


# shared secret을 직접 출력하지 않고 해시값으로 확인
def hash_ss(shared_secret: bytes) -> str:
    return hashlib.sha256(shared_secret).hexdigest()


# 파일 전체에 대한 SHA-256 해시 생성
def sha256_file(file_path: str) -> str:
    h = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)

    return h.hexdigest()


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


# [길이 + 데이터] 형식으로 데이터 전송
def send_with_length(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)


# 전송할 파일 선택 GUI
def select_file() -> str:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    file_path = filedialog.askopenfilename(
        title="전송할 파일 선택",
        filetypes=[("All Files", "*.*")]
    )

    root.destroy()
    return file_path


def show_info(title: str, message: str) -> None:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    messagebox.showinfo(title, message)
    root.destroy()


def show_error(title: str, message: str) -> None:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    messagebox.showerror(title, message)
    root.destroy()


# Server와 TCP socket 연결
def connect_to_server() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, PORT))

    log("PASS", "CONNECT", f"Connected to server {SERVER_IP}:{PORT}")

    return sock


# ML-KEM 기반 키 교환 수행
def perform_kem_handshake(sock: socket.socket) -> bytes:
    # Server 공개키 수신
    pk_len = struct.unpack("!I", recv_exact(sock, 4))[0]

    if pk_len <= 0 or pk_len > 10000:
        log("FAIL", "KEM", f"Invalid public key length: {pk_len}")
        raise ValueError("Invalid public key length")

    public_key = recv_exact(sock, pk_len)
    log("INFO", "KEM", f"Server public key received ({len(public_key)} bytes)")

    # Encapsulation 수행 후 shared secret 생성
    with oqs.KeyEncapsulation(KEM_NAME) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

    log("PASS", "KEM", "Encapsulation completed")
    log("INFO", "KEY", f"Shared Secret Hash: {hash_ss(shared_secret)}")

    # Server가 decapsulation할 수 있도록 ciphertext 전송
    send_with_length(sock, kem_ciphertext)
    log("INFO", "KEM", f"Ciphertext sent ({len(kem_ciphertext)} bytes)")

    # shared secret으로부터 session key 생성
    session_key = derive_key(shared_secret)

    log("PASS", "KEY", "Session key derived by HKDF")
    log("PASS", "KEM", "Handshake complete")

    return session_key


# 파일명, 파일 크기, 파일 해시 생성
def create_file_metadata(file_path: str):
    filename = os.path.basename(file_path)
    filename_bytes = filename.encode("utf-8")
    filesize = os.path.getsize(file_path)
    file_hash = sha256_file(file_path)

    log("INFO", "FILE", f"Selected file: {filename}")
    log("INFO", "FILE", f"File size: {filesize} bytes")
    log("INFO", "HASH", f"File SHA-256: {file_hash}")

    return filename, filename_bytes, filesize, file_hash


# 파일 메타데이터에 대한 ML-DSA 서명 생성
def create_signature(filename: str, filesize: int, file_hash: str):
    metadata_for_sign = (
        filename +
        str(filesize) +
        file_hash
    ).encode("utf-8")

    with oqs.Signature(SIG_NAME) as signer:
        sig_public_key = signer.generate_keypair()
        signature = signer.sign(metadata_for_sign)

    log("PASS", "SIGN", "ML-DSA signature generated")
    log("INFO", "SIGN", f"Signature public key size: {len(sig_public_key)} bytes")
    log("INFO", "SIGN", f"Signature size: {len(signature)} bytes")

    return sig_public_key, signature


# 파일 메타데이터 전송
def send_metadata(
    sock: socket.socket,
    filename_bytes: bytes,
    filesize: int,
    file_hash: str
) -> None:
    send_with_length(sock, filename_bytes)
    sock.sendall(struct.pack("!Q", filesize))
    sock.sendall(file_hash.encode("utf-8"))

    log("INFO", "FILE", "File metadata sent")


# 서명 공개키와 서명값 전송
def send_signature(
    sock: socket.socket,
    sig_public_key: bytes,
    signature: bytes
) -> None:
    send_with_length(sock, sig_public_key)
    log("INFO", "SIGN", "Signature public key sent")

    send_with_length(sock, signature)
    log("INFO", "SIGN", "Signature sent")


# 파일을 chunk 단위로 암호화하여 전송
def send_file_chunks(
    sock: socket.socket,
    file_path: str,
    session_key: bytes,
    filesize: int
) -> None:
    aesgcm = AESGCM(session_key)

    use_compression = True
    chunk_index = 0
    sent_size = 0

    log("INFO", "CHUNK", f"Chunk size: {CHUNK_SIZE} bytes")
    log("INFO", "CHUNK", "Chunk transfer started")

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)

            if not chunk:
                break

            original_chunk_size = len(chunk)
            flags = 0x01 if use_compression else 0x00

            # chunk 단위 압축
            if use_compression:
                chunk = zlib.compress(chunk)

            # chunk 단위 AES-GCM 암호화
            nonce = os.urandom(12)
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
            payload = nonce + encrypted_chunk

            # chunk header: flags + chunk_index + payload_length
            header = struct.pack(
                "!BQI",
                flags,
                chunk_index,
                len(payload)
            )

            sock.sendall(header)
            sock.sendall(payload)

            sent_size += original_chunk_size

            log(
                "INFO",
                "CHUNK",
                f"Sent chunk {chunk_index} ({sent_size}/{filesize} bytes)"
            )

            chunk_index += 1

    log("PASS", "CHUNK", "All chunks sent successfully")
    log("RESULT", "TRANSFER", "File data transfer completed")


# 전송 완료 후 Server에 CLIENT_DONE 신호 전송
def send_done_signal(sock: socket.socket, filename: str) -> None:
    show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{filename}")

    send_with_length(sock, b"CLIENT_DONE")
    log("INFO", "TRANSFER", "CLIENT_DONE signal sent")


# Client 전체 실행 흐름
def main():
    sock = None

    try:
        # 1. 파일 선택
        file_path = select_file()

        if not file_path:
            log("INFO", "FILE", "File selection cancelled by user")
            return

        if not os.path.exists(file_path):
            log("ERROR", "FILE", f"File not found: {file_path}")
            show_error("파일 오류", f"파일을 찾을 수 없습니다.\n\n{file_path}")
            return

        # 2. Server 연결
        sock = connect_to_server()

        # 3. ML-KEM 키 교환 및 session key 생성
        session_key = perform_kem_handshake(sock)

        # 4. 파일 메타데이터 생성
        filename, filename_bytes, filesize, file_hash = create_file_metadata(file_path)

        # 5. ML-DSA 서명 생성
        sig_public_key, signature = create_signature(
            filename,
            filesize,
            file_hash
        )

        # 6. 파일 메타데이터 전송
        send_metadata(
            sock,
            filename_bytes,
            filesize,
            file_hash
        )

        # 7. 서명 공개키 및 서명 전송
        send_signature(
            sock,
            sig_public_key,
            signature
        )

        # 8. 파일 chunk 암호화 전송
        send_file_chunks(
            sock,
            file_path,
            session_key,
            filesize
        )

        # 9. 전송 완료 신호 전송
        send_done_signal(sock, filename)

    except Exception as e:
        log("ERROR", "CLIENT", str(e))
        show_error("전송 실패", str(e))

    finally:
        if sock:
            sock.close()
            log("INFO", "CONNECT", "Connection closed")


if __name__ == "__main__":
    main()