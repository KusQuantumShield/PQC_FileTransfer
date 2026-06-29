import sys
import time
import os

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqc_transfer.utils import config


def measure_kem_performance(iterations=1000):
    """
    KEM (Key Encapsulation Mechanism) 알고리즘의 3단계 주요 연산(키 생성, 캡슐화, 역캡슐화)에 대한
    성능(소요 시간)을 측정합니다. PQC(양자 내성 암호)의 특징상 키 길이가 길고 연산 방식이 기존 RSA/ECC와
    다르므로, 이 벤치마크를 통해 병목 지점을 파악할 수 있습니다.
    """
    print(
        f"--- KEM 성능 측정 ({config.default_config.kem_alg}, {iterations}회 반복) ---"
    )

    # 1. 키 쌍 생성 (Keypair Generation)
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
        start = time.perf_counter()
        for _ in range(iterations):
            public_key = kem.generate_keypair()
        end = time.perf_counter()
    print(f"키 생성:  {(end - start) / iterations * 1000:.4f} ms/op")

    # 2. 캡슐화 (Encapsulation) - 공유 비밀키 생성 및 암호화
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
        public_key = kem.generate_keypair()
        start = time.perf_counter()
        for _ in range(iterations):
            ciphertext, shared_secret = kem.encap_secret(public_key)
        end = time.perf_counter()
        print(f"캡슐화:   {(end - start) / iterations * 1000:.4f} ms/op")

    # 3. 역캡슐화 (Decapsulation) - 암호화된 비밀키 복호화
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        start = time.perf_counter()
        for _ in range(iterations):
            kem.decap_secret(ciphertext)
        end = time.perf_counter()
        print(f"역캡슐화: {(end - start) / iterations * 1000:.4f} ms/op")
    print()


def measure_dsa_performance(iterations=1000):
    """
    DSA (Digital Signature Algorithm) 성능을 측정합니다.
    양자 내성 서명 알고리즘(예: ML-DSA)의 키 생성, 서명(Sign), 검증(Verify) 단계별
    소요 시간을 측정하여, 서버/클라이언트 간 인증 과정에서 발생하는 오버헤드를 분석합니다.
    """
    print(
        f"--- DSA 성능 측정 ({config.default_config.sig_alg}, {iterations}회 반복) ---"
    )
    message = b"This is a test message for signature validation."

    # 1. 키 쌍 생성 (Keypair Generation)
    with oqs.Signature(config.default_config.sig_alg) as signer:
        start = time.perf_counter()
        for _ in range(iterations):
            public_key = signer.generate_keypair()
        end = time.perf_counter()
    print(f"키 생성:  {(end - start) / iterations * 1000:.4f} ms/op")

    # 2. 서명 생성 (Sign)
    with oqs.Signature(config.default_config.sig_alg) as signer:
        public_key = signer.generate_keypair()
        start = time.perf_counter()
        for _ in range(iterations):
            signature = signer.sign(message)
        end = time.perf_counter()
        print(f"서명:     {(end - start) / iterations * 1000:.4f} ms/op")

    # 3. 서명 검증 (Verify)
    with oqs.Signature(config.default_config.sig_alg) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)

    with oqs.Signature(config.default_config.sig_alg) as verifier:
        start = time.perf_counter()
        for _ in range(iterations):
            verifier.verify(message, signature, public_key)
        end = time.perf_counter()
        print(f"검증:     {(end - start) / iterations * 1000:.4f} ms/op")
    print()


def measure_aes_performance(chunk_size=1024 * 1024, iterations=100):
    """
    AES-GCM 대칭키 암호화 성능을 측정합니다.
    PQC 통신 이후 설정된 세션 키를 이용해 실제 대용량 데이터를 암/복호화할 때의
    처리 속도와 처리량(Throughput, MB/s 단위)을 계산합니다.
    """
    print(
        f"--- AES-GCM 성능 측정 (청크 크기: {chunk_size / 1024 / 1024:.1f} MB, {iterations}회 반복) ---"
    )
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
    print(
        f"암호화: {enc_time * 1000:.4f} ms/op, 처리량: {(chunk_size / enc_time) / (1024 * 1024):.2f} MB/s"
    )

    # 2. 복호화 (Decrypt)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    start = time.perf_counter()
    for _ in range(iterations):
        aesgcm.decrypt(nonce, ciphertext, None)
    end = time.perf_counter()
    dec_time = (end - start) / iterations
    print(
        f"복호화: {dec_time * 1000:.4f} ms/op, 처리량: {(chunk_size / dec_time) / (1024 * 1024):.2f} MB/s"
    )
    print()


if __name__ == "__main__":
    # 벤치마크 프로그램 진입점 (단순 콘솔 출력 버전)
    print("양자 내성 암호(PQC) 및 대칭키 암호 성능 측정을 시작합니다...\n")

    # 1. KEM (Key Encapsulation Mechanism) - 키 쌍 생성, 캡슐화, 역캡슐화 성능 측정
    measure_kem_performance(1000)

    # 2. DSA (Digital Signature Algorithm) - 키 쌍 생성, 서명, 검증 성능 측정
    measure_dsa_performance(100)

    # 3. AES-GCM 대용량 청크 단위 암/복호화 성능 및 처리량 측정
    measure_aes_performance(config.default_config.chunk_size, 100)
