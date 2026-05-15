import os
import socket
import struct
import zlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils

def run_attack_client(file_path: str):
    """
    [서명 변조 공격(Signature Manipulation Attack) 시나리오]
    
    공격 목표:
    중간자(Man-in-the-Middle) 또는 악의적인 클라이언트가 데이터의 출처 인증을 방해하기 위해
    전자서명 값을 고의로 훼손
    
    동작 방식:
    1. 파일 데이터, 메타데이터(크기, 해시)는 모두 정상적인 원본 값을 사용
    2. ML-DSA 서명 알고리즘으로 생성된 올바른 서명값(Signature bytes)을 가로챔
    3. 서명 배열의 첫 번째 바이트 값을 +1 증가시키는 방식으로 서명을 고의로 훼손
    4. 훼손된 서명값을 서버로 전송하고 데이터는 올바르게 전송
    
    예상되는 서버의 반응:
    서버는 파일 복호화 및 해시 검증 등은 모두 무사히 마칠 수 있음 (데이터는 정상이므로)
    하지만 클라이언트 신원 인증을 위한 ML-DSA 서명 검증 단계에서
    서명값 자체가 손상되었거나 메타데이터와 불일치하기 때문에 False가 반환
    서버는 송신자를 신뢰할 수 없다고 판단하고 최종적으로 파일 저장을 차단
    """
    print("\n[ATTACK] === 서명 변조 공격(Signature Manipulation Attack) 시작 ===")
    
    # 공격 대상 파일이 있는지 검사
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 1. 서버 연결 및 KEM 키 캡슐화 (정상 프로세스)
            s.connect((utils.SERVER_IP, utils.PORT))
            print(f"[ATTACK] 서버({utils.SERVER_IP}:{utils.PORT})에 연결되었습니다.")

            public_key = utils.recv_with_length(s)
            
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            utils.send_with_length(s, kem_ciphertext)
            session_key = utils.derive_key(shared_secret)

            # 2. 메타데이터 생성 및 전송 (정상 값)
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)
            file_hash = utils.sha256_file(file_path)
            
            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))
            s.sendall(file_hash.encode("utf-8"))

            # 3. 양자 내성 전자서명(ML-DSA) 생성
            metadata_for_sign = (filename + str(filesize) + file_hash).encode("utf-8")
            with oqs.Signature(utils.SIG_ALG) as signer:
                # 클라이언트의 일회용 서명 키쌍을 생성
                sig_public_key = signer.generate_keypair()
                # 원본 메타데이터에 대한 올바른 서명 생성
                signature = signer.sign(metadata_for_sign)
                
            # =========================================================
            # [공격 포인트: 서명 데이터 임의 훼손]
            # 올바르게 만들어진 서명 바이트 배열의 0번 인덱스 값을 변경
            # =========================================================
            print("[ATTACK] 올바르게 생성된 서명의 첫 번째 바이트를 강제로 훼손합니다!")
            
            # 서명의 0번째 바이트에 1을 더하고, 256으로 나눈 나머지를 취해 오버플로우를 방지
            modified_byte = (signature[0] + 1) % 256
            # 조작된 바이트와 나머지 정상 바이트들을 다시 합침
            signature = bytes([modified_byte]) + signature[1:]

            # 공개키와 훼손된 서명을 서버로 전송
            utils.send_with_length(s, sig_public_key)
            utils.send_with_length(s, signature)

            # 4. 파일 데이터 청크 전송 (정상)
            aesgcm = AESGCM(session_key)
            chunk_index = 0
            
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(utils.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # 압축 및 암호화 등은 원본 데이터 그대로 정상적으로 수행
                    compressed_chunk = zlib.compress(chunk)
                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, compressed_chunk, None)
                    payload = nonce + encrypted_chunk
                    
                    s.sendall(struct.pack("!BQI", 0x01, chunk_index, len(payload)))
                    s.sendall(payload)
                    chunk_index += 1
            
            print("[ATTACK] 변조된 서명과 함께 올바른 데이터를 모두 전송했습니다.")
            
            # 5. 전송 완료 신호 발송
            utils.send_with_length(s, b"CLIENT_DONE")
            
        except Exception as e:
            # 서명 검증 실패 시 서버가 소켓을 강제로 끊어 예외가 발생할 수 있음
            print(f"[ATTACK] 전송 중 오류가 발생했습니다. (서버 측 차단일 수 있습니다): {e}")

if __name__ == "__main__":
    # 테스트용 더미 파일 생성
    test_file = "test_signature_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for Signature attack." * 100)
        
    # 공격 시나리오 실행
    run_attack_client(test_file)
