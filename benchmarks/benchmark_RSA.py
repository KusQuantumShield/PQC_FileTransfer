import csv
import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


CSV_FILENAME = "benchmark_RSA.csv"
ITERATIONS = 100

RSA_KEY_SIZE = 2048
AES_SESSION_KEY_SIZE = 32


def ms(start: float, end: float) -> float:
    """
    perf_counter() 차이를 ms 단위로 변환합니다.
    """
    return (end - start) * 1000


def add_result(
    results,
    category,
    algorithm,
    operation,
    iterations="",
    avg_time_ms="",
    value_bytes=""
):
    """
    측정 결과를 CSV 저장용 리스트에 추가합니다.
    """
    results.append({
        "category": category,
        "algorithm": algorithm,
        "operation": operation,
        "iterations": iterations,
        "avg_time_ms": "" if avg_time_ms == "" else f"{avg_time_ms:.4f}",
        "value_bytes": value_bytes
    })


def save_results_to_csv(results, filename=CSV_FILENAME):
    """
    RSA 키 교환 측정 결과를 CSV 파일로 저장합니다.
    """
    fieldnames = [
        "category",
        "algorithm",
        "operation",
        "iterations",
        "avg_time_ms",
        "value_bytes"
    ]

    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[CSV 저장 완료] {filename}")


def generate_rsa_keypair():
    """
    RSA private key와 public key를 생성합니다.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    public_key = private_key.public_key()

    return private_key, public_key


def rsa_encrypt_session_key(public_key, session_key: bytes) -> bytes:
    """
    RSA public key로 AES session key를 암호화합니다.
    """
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_session_key


def rsa_decrypt_session_key(private_key, encrypted_session_key: bytes) -> bytes:
    """
    RSA private key로 암호화된 AES session key를 복호화합니다.
    """
    decrypted_session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_session_key


def get_public_key_size(public_key) -> int:
    """
    RSA public key를 DER 형식으로 변환한 뒤 크기를 측정합니다.
    """
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return len(public_key_der)


def measure_rsa_key_exchange(results, iterations=ITERATIONS):
    """
    RSA 기반 키 교환 성능을 측정합니다.
    """
    print(f"--- RSA 키 교환 성능 측정 ({RSA_KEY_SIZE}-bit, {iterations}회 반복) ---")

    # 1. RSA Keypair Generation
    start = time.perf_counter()

    for _ in range(iterations):
        private_key, public_key = generate_rsa_keypair()

    end = time.perf_counter()

    keygen_ms = ms(start, end) / iterations
    print(f"RSA 키쌍 생성: {keygen_ms:.4f} ms/op")

    add_result(
        results,
        category="RSA",
        algorithm=f"RSA-{RSA_KEY_SIZE}",
        operation="key_generation",
        iterations=iterations,
        avg_time_ms=keygen_ms
    )

    # 비교를 위해 keypair 하나를 생성해두고 encryption/decryption에 사용
    private_key, public_key = generate_rsa_keypair()

    # 2. AES Session Key Generation
    start = time.perf_counter()

    for _ in range(iterations):
        session_key = os.urandom(AES_SESSION_KEY_SIZE)

    end = time.perf_counter()

    session_key_gen_ms = ms(start, end) / iterations
    print(f"AES Session Key 생성: {session_key_gen_ms:.4f} ms/op")

    add_result(
        results,
        category="RSA",
        algorithm="AES-256",
        operation="session_key_generation",
        iterations=iterations,
        avg_time_ms=session_key_gen_ms
    )

    # 3. RSA Encryption
    session_key = os.urandom(AES_SESSION_KEY_SIZE)

    start = time.perf_counter()

    for _ in range(iterations):
        encrypted_session_key = rsa_encrypt_session_key(public_key, session_key)

    end = time.perf_counter()

    encrypt_ms = ms(start, end) / iterations
    print(f"RSA Session Key 암호화: {encrypt_ms:.4f} ms/op")

    add_result(
        results,
        category="RSA",
        algorithm=f"RSA-{RSA_KEY_SIZE}-OAEP-SHA256",
        operation="encryption",
        iterations=iterations,
        avg_time_ms=encrypt_ms
    )

    # 4. RSA Decryption
    encrypted_session_key = rsa_encrypt_session_key(public_key, session_key)

    start = time.perf_counter()

    for _ in range(iterations):
        decrypted_session_key = rsa_decrypt_session_key(private_key, encrypted_session_key)

    end = time.perf_counter()

    decrypt_ms = ms(start, end) / iterations
    print(f"RSA Session Key 복호화: {decrypt_ms:.4f} ms/op")

    add_result(
        results,
        category="RSA",
        algorithm=f"RSA-{RSA_KEY_SIZE}-OAEP-SHA256",
        operation="decryption",
        iterations=iterations,
        avg_time_ms=decrypt_ms
    )

    if session_key != decrypted_session_key:
        raise RuntimeError("RSA session key mismatch")

    total_ms = keygen_ms + session_key_gen_ms + encrypt_ms + decrypt_ms
    print(f"RSA 전체 키 교환 시간: {total_ms:.4f} ms/op")

    add_result(
        results,
        category="RSA",
        algorithm=f"RSA-{RSA_KEY_SIZE}",
        operation="total_key_exchange",
        iterations=iterations,
        avg_time_ms=total_ms
    )

    print()


def measure_rsa_size(results):
    """
    RSA public key, encrypted session key, session key 크기를 측정합니다.
    """
    print(f"--- RSA 키 및 암호문 크기 분석 ({RSA_KEY_SIZE}-bit) ---")

    private_key, public_key = generate_rsa_keypair()
    session_key = os.urandom(AES_SESSION_KEY_SIZE)
    encrypted_session_key = rsa_encrypt_session_key(public_key, session_key)

    public_key_size = get_public_key_size(public_key)
    encrypted_session_key_size = len(encrypted_session_key)
    session_key_size = len(session_key)

    print(f"RSA Public Key DER 크기: {public_key_size} bytes")
    print(f"RSA Encrypted Session Key 크기: {encrypted_session_key_size} bytes")
    print(f"AES Session Key 크기: {session_key_size} bytes")

    add_result(
        results,
        category="SIZE",
        algorithm=f"RSA-{RSA_KEY_SIZE}",
        operation="rsa_public_key_der",
        value_bytes=public_key_size
    )

    add_result(
        results,
        category="SIZE",
        algorithm=f"RSA-{RSA_KEY_SIZE}-OAEP-SHA256",
        operation="encrypted_session_key",
        value_bytes=encrypted_session_key_size
    )

    add_result(
        results,
        category="SIZE",
        algorithm="AES-256",
        operation="session_key",
        value_bytes=session_key_size
    )

    print()


def main():
    print("RSA 키 교환 성능 측정을 시작합니다.\n")

    results = []

    measure_rsa_key_exchange(results, ITERATIONS)
    measure_rsa_size(results)
    save_results_to_csv(results)


if __name__ == "__main__":
    main()