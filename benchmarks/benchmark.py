import time
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from pqc_transfer import utils

def measure_kem_performance(iterations=1000):
    """
    KEM (Key Encapsulation Mechanism) 성능을 측정합니다.
    키 생성, 캡슐화, 역캡슐화 속도를 계산합니다.
    """
    print(f"--- KEM 성능 측정 ({utils.KEM_ALG}, {iterations}회 반복) ---")
    
    # 1. 키 쌍 생성 (Keypair Generation)
    with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
        start = time.perf_counter()
        for _ in range(iterations):
            public_key = kem.generate_keypair()
        end = time.perf_counter()
    print(f"키 생성:  {(end - start) / iterations * 1000:.4f} ms/op")

    # 2. 캡슐화 (Encapsulation) - 공유 비밀키 생성 및 암호화
    with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        start = time.perf_counter()
        for _ in range(iterations):
            ciphertext, shared_secret = kem.encap_secret(public_key)
        end = time.perf_counter()
        print(f"캡슐화:   {(end - start) / iterations * 1000:.4f} ms/op")

    # 3. 역캡슐화 (Decapsulation) - 암호화된 비밀키 복호화
    with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        start = time.perf_counter()
        for _ in range(iterations):
            decrypted_secret = kem.decap_secret(ciphertext)
        end = time.perf_counter()
        print(f"역캡슐화: {(end - start) / iterations * 1000:.4f} ms/op")
    print()

def measure_dsa_performance(iterations=1000):
    """
    DSA (Digital Signature Algorithm) 성능을 측정합니다.
    키 생성, 서명, 검증 속도를 계산합니다.
    """
    print(f"--- DSA 성능 측정 ({utils.SIG_ALG}, {iterations}회 반복) ---")
    message = b"This is a test message for signature validation."
    
    # 1. 키 쌍 생성 (Keypair Generation)
    with oqs.Signature(utils.SIG_ALG) as signer:
        start = time.perf_counter()
        for _ in range(iterations):
            public_key = signer.generate_keypair()
        end = time.perf_counter()
    print(f"키 생성:  {(end - start) / iterations * 1000:.4f} ms/op")

    # 2. 서명 생성 (Sign)
    with oqs.Signature(utils.SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        start = time.perf_counter()
        for _ in range(iterations):
            signature = signer.sign(message)
        end = time.perf_counter()
        print(f"서명:     {(end - start) / iterations * 1000:.4f} ms/op")

    # 3. 서명 검증 (Verify)
    with oqs.Signature(utils.SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
        
    with oqs.Signature(utils.SIG_ALG) as verifier:
        start = time.perf_counter()
        for _ in range(iterations):
            is_valid = verifier.verify(message, signature, public_key)
        end = time.perf_counter()
        print(f"검증:     {(end - start) / iterations * 1000:.4f} ms/op")
    print()

def measure_aes_performance(chunk_size=1024*1024, iterations=100):
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
    print(f"암호화: {enc_time * 1000:.4f} ms/op, 처리량: {(chunk_size / enc_time) / (1024*1024):.2f} MB/s")

    # 2. 복호화 (Decrypt)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    start = time.perf_counter()
    for _ in range(iterations):
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    end = time.perf_counter()
    dec_time = (end - start) / iterations
    print(f"복호화: {dec_time * 1000:.4f} ms/op, 처리량: {(chunk_size / dec_time) / (1024*1024):.2f} MB/s")
    print()

if __name__ == "__main__":
    print("양자 내성 암호(PQC) 및 대칭키 암호 성능 측정을 시작합니다...\n")
    measure_kem_performance(1000)
    measure_dsa_performance(100)
    measure_aes_performance(utils.CHUNK_SIZE, 100)
