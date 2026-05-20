import time
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import utils

def measure_kem_performance(iterations=1000):
    print(f"--- KEM Benchmark ({utils.KEM_ALG}, {iterations} iterations) ---")
    
    # 1. Keypair Generation
    start = time.perf_counter()
    for _ in range(iterations):
        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            public_key = kem.generate_keypair()
    end = time.perf_counter()
    print(f"Keygen: {(end - start) / iterations * 1000:.4f} ms/op")

    # 2. Encapsulation
    with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        start = time.perf_counter()
        for _ in range(iterations):
            ciphertext, shared_secret = kem.encap_secret(public_key)
        end = time.perf_counter()
        print(f"Encap:  {(end - start) / iterations * 1000:.4f} ms/op")

    # 3. Decapsulation
    with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        start = time.perf_counter()
        for _ in range(iterations):
            decrypted_secret = kem.decap_secret(ciphertext)
        end = time.perf_counter()
        print(f"Decap:  {(end - start) / iterations * 1000:.4f} ms/op")
    print()

def measure_dsa_performance(iterations=1000):
    print(f"--- DSA Benchmark ({utils.SIG_ALG}, {iterations} iterations) ---")
    message = b"This is a test message for signature validation."
    
    # 1. Keypair Generation
    start = time.perf_counter()
    for _ in range(iterations):
        with oqs.Signature(utils.SIG_ALG) as signer:
            public_key = signer.generate_keypair()
    end = time.perf_counter()
    print(f"Keygen: {(end - start) / iterations * 1000:.4f} ms/op")

    # 2. Sign
    with oqs.Signature(utils.SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        start = time.perf_counter()
        for _ in range(iterations):
            signature = signer.sign(message)
        end = time.perf_counter()
        print(f"Sign:   {(end - start) / iterations * 1000:.4f} ms/op")

    # 3. Verify
    with oqs.Signature(utils.SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
        
    with oqs.Signature(utils.SIG_ALG) as verifier:
        start = time.perf_counter()
        for _ in range(iterations):
            is_valid = verifier.verify(message, signature, public_key)
        end = time.perf_counter()
        print(f"Verify: {(end - start) / iterations * 1000:.4f} ms/op")
    print()

def measure_aes_performance(chunk_size=1024*1024, iterations=100):
    print(f"--- AES-GCM Benchmark (Chunk size: {chunk_size / 1024 / 1024:.1f} MB, {iterations} iterations) ---")
    key = os.urandom(32)
    aesgcm = AESGCM(key)
    data = os.urandom(chunk_size)
    nonce = os.urandom(12)
    
    # 1. Encrypt
    start = time.perf_counter()
    for _ in range(iterations):
        ciphertext = aesgcm.encrypt(nonce, data, None)
    end = time.perf_counter()
    enc_time = (end - start) / iterations
    print(f"Encrypt: {enc_time * 1000:.4f} ms/op, Throughput: {(chunk_size / enc_time) / (1024*1024):.2f} MB/s")

    # 2. Decrypt
    ciphertext = aesgcm.encrypt(nonce, data, None)
    start = time.perf_counter()
    for _ in range(iterations):
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    end = time.perf_counter()
    dec_time = (end - start) / iterations
    print(f"Decrypt: {dec_time * 1000:.4f} ms/op, Throughput: {(chunk_size / dec_time) / (1024*1024):.2f} MB/s")
    print()

if __name__ == "__main__":
    print("Starting PQC & Symmetric Crypto Benchmarks...\n")
    measure_kem_performance(1000)
    measure_dsa_performance(100)
    measure_aes_performance(utils.CHUNK_SIZE, 100)
