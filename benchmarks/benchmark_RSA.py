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
    - 보안 강도를 위해 통상적으로 사용되는 공개 지수(public_exponent)인 65537을 사용합니다.
    - 키 크기는 상단에 정의된 RSA_KEY_SIZE (예: 2048비트)를 적용합니다.
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
    - 패딩 방식으로는 보안성이 검증된 OAEP (Optimal Asymmetric Encryption Padding)를 사용합니다.
    - MGF 및 기본 해시 알고리즘으로는 SHA256을 적용합니다.
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
    - 암호화 단계에서 사용했던 것과 동일한 OAEP 패딩 및 SHA256 해시 설정을 사용해야 
      정상적으로 원본 세션 키가 복구됩니다.
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
    - 네트워크로 전송될 때 실제로 소비되는 공개키의 바이트(Bytes) 길이를 파악합니다.
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
    # 지정된 횟수만큼 키 쌍 생성을 반복하여 1회 생성에 걸리는 평균 소요 시간을 구합니다.
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
    # 실제 파일 암호화에 사용될 32바이트 크기(AES-256용)의 난수를 생성하는 시간을 측정합니다.
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
    # AES 세션 키를 RSA 공개키로 암호화(KEM의 캡슐화와 유사한 과정)하는 시간 측정입니다.
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
    # 암호화된 AES 세션 키를 RSA 개인키로 복호화(KEM의 역캡슐화에 해당)하는 시간 측정입니다.
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

    # 복호화된 키가 원본과 동일한지 최종 무결성 검증
    if session_key != decrypted_session_key:
        raise RuntimeError("RSA session key mismatch")

    # RSA는 통상적으로 장기 키(Long-term key)를 사용하므로, 매 연결마다 키를 생성하지 않습니다.
    # 따라서 실제 키 교환(Key Exchange) 소요 시간은 (세션 키 생성 + 암호화 + 복호화)로 한정하는 것이 PQC(Ephemeral KEM)와 공정한 비교가 됩니다.
    total_ms = session_key_gen_ms + encrypt_ms + decrypt_ms
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