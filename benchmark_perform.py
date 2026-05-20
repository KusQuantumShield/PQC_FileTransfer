import time
import os
import csv
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import utils


CSV_FILENAME = "Benchmark Results.csv"


def save_results_to_csv(results, filename=CSV_FILENAME):
    """
    성능 측정 결과를 CSV 파일로 저장합니다.
    """
    fieldnames = [
        "category",
        "algorithm",
        "operation",
        "iterations",
        "chunk_size_bytes",
        "avg_time_ms",
        "throughput_MBps"
    ]

    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"[CSV 저장 완료] {filename}\n")


def add_result(
    results,
    category,
    algorithm,
    operation,
    iterations,
    avg_time_ms,
    chunk_size_bytes="",
    throughput_MBps=""
):
    """
    측정 결과를 results 리스트에 추가합니다.
    """
    results.append({
        "category": category,
        "algorithm": algorithm,
        "operation": operation,
        "iterations": iterations,
        "chunk_size_bytes": chunk_size_bytes,
        "avg_time_ms": f"{avg_time_ms:.4f}",
        "throughput_MBps": "" if throughput_MBps == "" else f"{throughput_MBps:.2f}"
    })


def measure_kem_performance(results, iterations=1000):
    """
    KEM (Key Encapsulation Mechanism) 성능을 측정합니다.
    키 생성, 캡슐화, 역캡슐화 속도를 계산합니다.
    """
    print(f"--- KEM 성능 측정 ({utils.KEM_ALG}, {iterations}회 반복) ---")

    # 1. 키 쌍 생성 (Keypair Generation)
    start = time.perf_counter()
    for _ in range(iterations):
        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            public_key = kem.generate_keypair()
    end = time.perf_counter()

    keygen_ms = (end - start) / iterations * 1000
    print(f"키 생성:  {keygen_ms:.4f} ms/op")

    add_result(
        results,
        category="KEM",
        algorithm=utils.KEM_ALG,
        operation="key_generation",
        iterations=iterations,
        avg_time_ms=keygen_ms
    )

    # 2. 캡슐화 (Encapsulation) - 공유 비밀키 생성 및 암호화
    with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
        public_key = kem.generate_keypair()

        start = time.perf_counter()
        for _ in range(iterations):
            ciphertext, shared_secret = kem.encap_secret(public_key)
        end = time.perf_counter()

        encap_ms = (end - start) / iterations * 1000
        print(f"캡슐화:   {encap_ms:.4f} ms/op")

    add_result(
        results,
        category="KEM",
        algorithm=utils.KEM_ALG,
        operation="encapsulation",
        iterations=iterations,
        avg_time_ms=encap_ms
    )

    # 3. 역캡슐화 (Decapsulation) - 암호화된 비밀키 복호화
    with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)

        start = time.perf_counter()
        for _ in range(iterations):
            decrypted_secret = kem.decap_secret(ciphertext)
        end = time.perf_counter()

        decap_ms = (end - start) / iterations * 1000
        print(f"역캡슐화: {decap_ms:.4f} ms/op")

    add_result(
        results,
        category="KEM",
        algorithm=utils.KEM_ALG,
        operation="decapsulation",
        iterations=iterations,
        avg_time_ms=decap_ms
    )

    print()


def measure_dsa_performance(results, iterations=1000):
    """
    DSA (Digital Signature Algorithm) 성능을 측정합니다.
    키 생성, 서명, 검증 속도를 계산합니다.
    """
    print(f"--- DSA 성능 측정 ({utils.SIG_ALG}, {iterations}회 반복) ---")
    message = b"This is a test message for signature validation."

    # 1. 키 쌍 생성 (Keypair Generation)
    start = time.perf_counter()
    for _ in range(iterations):
        with oqs.Signature(utils.SIG_ALG) as signer:
            public_key = signer.generate_keypair()
    end = time.perf_counter()

    keygen_ms = (end - start) / iterations * 1000
    print(f"키 생성:  {keygen_ms:.4f} ms/op")

    add_result(
        results,
        category="DSA",
        algorithm=utils.SIG_ALG,
        operation="key_generation",
        iterations=iterations,
        avg_time_ms=keygen_ms
    )

    # 2. 서명 생성 (Sign)
    with oqs.Signature(utils.SIG_ALG) as signer:
        public_key = signer.generate_keypair()

        start = time.perf_counter()
        for _ in range(iterations):
            signature = signer.sign(message)
        end = time.perf_counter()

        sign_ms = (end - start) / iterations * 1000
        print(f"서명:     {sign_ms:.4f} ms/op")

    add_result(
        results,
        category="DSA",
        algorithm=utils.SIG_ALG,
        operation="sign",
        iterations=iterations,
        avg_time_ms=sign_ms
    )

    # 3. 서명 검증 (Verify)
    with oqs.Signature(utils.SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)

    with oqs.Signature(utils.SIG_ALG) as verifier:
        start = time.perf_counter()
        for _ in range(iterations):
            is_valid = verifier.verify(message, signature, public_key)
        end = time.perf_counter()

        verify_ms = (end - start) / iterations * 1000
        print(f"검증:     {verify_ms:.4f} ms/op")

    add_result(
        results,
        category="DSA",
        algorithm=utils.SIG_ALG,
        operation="verify",
        iterations=iterations,
        avg_time_ms=verify_ms
    )

    print()


def measure_aes_performance(results, chunk_size=1024 * 1024, iterations=100):
    """
    AES-GCM 대칭키 암호화 성능을 측정합니다.
    대용량 데이터(청크) 처리 시의 속도와 처리량(Throughput)을 계산합니다.
    """
    print(f"--- AES-GCM 성능 측정 (청크 크기: {chunk_size / 1024 / 1024:.1f} MB, {iterations}회 반복) ---")

    key = os.urandom(32)
    aesgcm = AESGCM(key)
    data = os.urandom(chunk_size)
    nonce = os.urandom(12)

    # 1. 암호화 (Encrypt)
    start = time.perf_counter()
    for _ in range(iterations):
        ciphertext = aesgcm.encrypt(nonce, data, None)
    end = time.perf_counter()

    enc_time = (end - start) / iterations
    enc_ms = enc_time * 1000
    enc_throughput = (chunk_size / enc_time) / (1024 * 1024)

    print(f"암호화: {enc_ms:.4f} ms/op, 처리량: {enc_throughput:.2f} MB/s")

    add_result(
        results,
        category="AES-GCM",
        algorithm="AES-256-GCM",
        operation="encrypt",
        iterations=iterations,
        chunk_size_bytes=chunk_size,
        avg_time_ms=enc_ms,
        throughput_MBps=enc_throughput
    )

    # 2. 복호화 (Decrypt)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    start = time.perf_counter()
    for _ in range(iterations):
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    end = time.perf_counter()

    dec_time = (end - start) / iterations
    dec_ms = dec_time * 1000
    dec_throughput = (chunk_size / dec_time) / (1024 * 1024)

    print(f"복호화: {dec_ms:.4f} ms/op, 처리량: {dec_throughput:.2f} MB/s")

    add_result(
        results,
        category="AES-GCM",
        algorithm="AES-256-GCM",
        operation="decrypt",
        iterations=iterations,
        chunk_size_bytes=chunk_size,
        avg_time_ms=dec_ms,
        throughput_MBps=dec_throughput
    )

    print()


if __name__ == "__main__":
    print("양자 내성 암호(PQC) 및 대칭키 암호 성능 측정을 시작합니다...\n")

    results = []

    measure_kem_performance(results, 1000)
    measure_dsa_performance(results, 100)
    measure_aes_performance(results, utils.CHUNK_SIZE, 100)

    save_results_to_csv(results)