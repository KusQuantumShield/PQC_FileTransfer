import time
import os
import csv
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqc_transfer.utils import config, crypto


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILENAME = os.path.join(BASE_DIR, "benchmark_results.csv")


def save_results_to_csv(results, filename=CSV_FILENAME):
    """
    수집된 벤치마크 측정 결과 리스트(results)를 CSV(Comma-Separated Values) 파일 포맷으로 저장합니다.
    추후 스프레드시트 프로그램(엑셀 등)이나 데이터 분석 도구(Pandas 등)에서 분석하기 쉽도록 헤더를 포함합니다.
    """
    fieldnames = [
        "category",
        "algorithm",
        "operation",
        "iterations",
        "chunk_size_bytes",
        "avg_time_ms",
        "throughput_MBps",
        "value_bytes"
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
    iterations="",
    avg_time_ms="",
    chunk_size_bytes="",
    throughput_MBps="",
    value_bytes=""
):
    """
    측정 결과를 results 리스트에 추가합니다.
    - 각 측정 단계의 세부 결과(카테고리, 알고리즘, 동작 종류, 소요 시간, 처리량, 바이트 크기 등)를 모아
      최종적으로 CSV 파일로 출력하기 위한 헬퍼(helper) 함수입니다.
    """
    results.append({
        "category": category,
        "algorithm": algorithm,
        "operation": operation,
        "iterations": iterations,
        "chunk_size_bytes": chunk_size_bytes,
        "avg_time_ms": "" if avg_time_ms == "" else f"{avg_time_ms:.4f}",
        "throughput_MBps": "" if throughput_MBps == "" else f"{throughput_MBps:.2f}",
        "value_bytes": value_bytes
    })


def measure_kem_performance(results, iterations=1000):
    """
    KEM(Key Encapsulation Mechanism) 성능을 측정하고, 결과를 results 리스트에 딕셔너리 형태로 저장합니다.
    성능 지표:
      1. 키 생성 (Keypair Generation): 공개키/비밀키 쌍을 생성하는 시간
      2. 캡슐화 (Encapsulation): 공유 비밀키를 생성하고 서버의 공개키로 암호화(캡슐화)하는 시간
      3. 역캡슐화 (Decapsulation): 수신한 암호문을 자신의 비밀키로 풀어 공유 비밀키를 복구하는 시간
      4. HKDF: 교환된 공유 비밀키를 실제 사용할 32바이트 AES 세션 키로 유도(Derive)하는 시간
    """
    print(f"--- KEM 성능 측정 ({config.default_config.kem_alg}, {iterations}회 반복) ---")

    # 1. 키 쌍 생성(Keypair Generation)
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
        start = time.perf_counter()
        for _ in range(iterations):
            public_key = kem.generate_keypair()
        end = time.perf_counter()

    keygen_ms = (end - start) / iterations * 1000
    print(f"키 생성:  {keygen_ms:.4f} ms/op")

    add_result(
        results,
        category="KEM",
        algorithm=config.default_config.kem_alg,
        operation="key_generation",
        iterations=iterations,
        avg_time_ms=keygen_ms
    )

    # 2. 캡슐화(Encapsulation)
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
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
        algorithm=config.default_config.kem_alg,
        operation="encapsulation",
        iterations=iterations,
        avg_time_ms=encap_ms
    )

    # 3. 역캡슐화(Decapsulation)
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
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
        algorithm=config.default_config.kem_alg,
        operation="decapsulation",
        iterations=iterations,
        avg_time_ms=decap_ms
    )

    # 4. HKDF 기반 세션 키 생성
    start = time.perf_counter()

    for _ in range(iterations):
        session_key = crypto.derive_key(shared_secret)

    end = time.perf_counter()

    hkdf_ms = (end - start) / iterations * 1000
    print(f"HKDF:     {hkdf_ms:.4f} ms/op")

    add_result(
        results,
        category="KEM",
        algorithm="HKDF-SHA256",
        operation="hkdf",
        iterations=iterations,
        avg_time_ms=hkdf_ms
    )

    print()


def measure_dsa_performance(results, iterations=1000):
    """
    PQC DSA(디지털 서명 알고리즘) 성능을 측정하고, 결과를 results 리스트에 저장합니다.
    파일 무결성 검증과 송신자 인증에 걸리는 부하를 분석하기 위해,
    키 쌍 생성, 서명(Sign), 검증(Verify)의 3가지 핵심 동작에 대한 평균 처리 시간(ms/op)을 산출합니다.
    """
    print(f"--- DSA 성능 측정 ({config.default_config.sig_alg}, {iterations}회 반복) ---")

    message = b"This is a test message for signature validation."

    # 1. 키 쌍 생성(Keypair Generation)
    with oqs.Signature(config.default_config.sig_alg) as signer:
        start = time.perf_counter()
        for _ in range(iterations):
            public_key = signer.generate_keypair()
        end = time.perf_counter()

    keygen_ms = (end - start) / iterations * 1000
    print(f"키 생성:  {keygen_ms:.4f} ms/op")

    add_result(
        results,
        category="DSA",
        algorithm=config.default_config.sig_alg,
        operation="key_generation",
        iterations=iterations,
        avg_time_ms=keygen_ms
    )

    # 2. 서명 생성(Sign)
    with oqs.Signature(config.default_config.sig_alg) as signer:
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
        algorithm=config.default_config.sig_alg,
        operation="sign",
        iterations=iterations,
        avg_time_ms=sign_ms
    )

    # 3. 서명 검증(Verify)
    with oqs.Signature(config.default_config.sig_alg) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)

    with oqs.Signature(config.default_config.sig_alg) as verifier:
        start = time.perf_counter()

        for _ in range(iterations):
            is_valid = verifier.verify(message, signature, public_key)

        end = time.perf_counter()

        verify_ms = (end - start) / iterations * 1000
        print(f"검증:     {verify_ms:.4f} ms/op")

    add_result(
        results,
        category="DSA",
        algorithm=config.default_config.sig_alg,
        operation="verify",
        iterations=iterations,
        avg_time_ms=verify_ms
    )

    print()


def measure_aes_performance(results, chunk_size=1024 * 1024, iterations=100):
    """
    AES-GCM (대칭키 암호) 성능을 측정하고, 결과를 results 리스트에 추가합니다.
    대용량 파일 전송을 시뮬레이션하기 위해 설정된 chunk_size(기본 1MB) 단위로 데이터를 암호화 및 복호화하여
    1회당 처리 소요 시간(ms/op)뿐만 아니라 초당 처리량(Throughput, MB/s)을 함께 측정합니다.
    """
    print(
        f"--- AES-GCM 성능 측정 "
        f"(청크 크기: {chunk_size / 1024 / 1024:.1f} MB, {iterations}회 반복) ---"
    )

    key = os.urandom(32)
    aesgcm = AESGCM(key)
    data = os.urandom(chunk_size)
    nonce = os.urandom(12)

    # 1. 암호화(Encrypt)
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

    # 2. 복호화(Decrypt)
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


def measure_key_signature_sizes(results):
    """
    PQC 알고리즘은 기존 RSA/ECC에 비해 키와 서명의 크기가 매우 크다는 특징이 있습니다.
    따라서 KEM(공개키, 암호문, 비밀키), DSA(공개키, 서명) 및 AES-GCM(논스), 전송 프로토콜(청크 헤더)에서 
    발생하는 실제 바이트(Bytes) 단위의 크기를 정확히 측정하여 기록합니다.
    이 데이터는 네트워크 대역폭(Bandwidth) 사용량 분석에 핵심적인 자료가 됩니다.
    """
    print(f"--- 키 및 서명 크기 분석 ({config.default_config.kem_alg}, {config.default_config.sig_alg}) ---")

    # 1. KEM 관련 크기 측정
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
        kem_public_key = kem.generate_keypair()
        kem_ciphertext, kem_shared_secret = kem.encap_secret(kem_public_key)

    kem_public_key_size = len(kem_public_key)
    kem_ciphertext_size = len(kem_ciphertext)
    kem_shared_secret_size = len(kem_shared_secret)

    print(f"KEM Public Key:      {kem_public_key_size} bytes")
    print(f"KEM Ciphertext:      {kem_ciphertext_size} bytes")
    print(f"KEM Shared Secret:   {kem_shared_secret_size} bytes")

    add_result(
        results,
        category="SIZE",
        algorithm=config.default_config.kem_alg,
        operation="kem_public_key",
        value_bytes=kem_public_key_size
    )

    add_result(
        results,
        category="SIZE",
        algorithm=config.default_config.kem_alg,
        operation="kem_ciphertext",
        value_bytes=kem_ciphertext_size
    )

    add_result(
        results,
        category="SIZE",
        algorithm=config.default_config.kem_alg,
        operation="kem_shared_secret",
        value_bytes=kem_shared_secret_size
    )

    # 2. DSA 관련 크기 측정
    message = b"This is a test message for signature size analysis."

    with oqs.Signature(config.default_config.sig_alg) as signer:
        sig_public_key = signer.generate_keypair()
        signature = signer.sign(message)

    sig_public_key_size = len(sig_public_key)
    signature_size = len(signature)

    print(f"DSA Public Key:      {sig_public_key_size} bytes")
    print(f"DSA Signature:       {signature_size} bytes")

    add_result(
        results,
        category="SIZE",
        algorithm=config.default_config.sig_alg,
        operation="dsa_public_key",
        value_bytes=sig_public_key_size
    )

    add_result(
        results,
        category="SIZE",
        algorithm=config.default_config.sig_alg,
        operation="dsa_signature",
        value_bytes=signature_size
    )

    # 3. AES-GCM 및 Chunk header 고정 크기
    aes_gcm_nonce_size = 12
    chunk_header_size = 13

    print(f"AES-GCM Nonce:       {aes_gcm_nonce_size} bytes")
    print(f"Chunk Header:        {chunk_header_size} bytes")

    add_result(
        results,
        category="SIZE",
        algorithm="AES-GCM",
        operation="nonce",
        value_bytes=aes_gcm_nonce_size
    )

    add_result(
        results,
        category="SIZE",
        algorithm="CHUNK",
        operation="chunk_header",
        value_bytes=chunk_header_size
    )

    print()


if __name__ == "__main__":
    # 전체 양자 내성 암호 및 대칭키 암호 체계 성능 벤치마크 진입점
    print("양자 내성 암호(PQC) 및 대칭키 암호 성능 측정을 시작합니다...\n")

    results = []

    # 1. KEM (Key Encapsulation Mechanism) 성능 측정 (1000회 반복)
    measure_kem_performance(results, 1000)
    
    # 2. DSA (Digital Signature Algorithm) 성능 측정 (100회 반복)
    measure_dsa_performance(results, 100)
    
    # 3. 대용량 데이터를 처리하는 AES-GCM 대칭키 성능 측정 (기본 CHUNK 크기로 100회 반복)
    measure_aes_performance(results, config.default_config.chunk_size, 100)
    
    # 4. KEM, DSA 등 각 알고리즘이 소비하는 바이트(Bytes) 크기 분석
    measure_key_signature_sizes(results)

    # 수집된 모든 결과를 CSV로 저장
    save_results_to_csv(results)