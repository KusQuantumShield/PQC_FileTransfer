import os
import socket
import struct
import zlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils

def run_attack_client(file_path: str):
    """
    [해시 변조 공격(Hash Manipulation Attack) 시나리오]
    
    공격 목표:
    송신자가 파일의 무결성을 증명하는 해시값을 임의로 조작하여 서버에 전송
    
    동작 방식:
    1. 원본 파일의 진짜 해시 대신 0으로만 채워진 가짜 해시를 생성
    2. 파일 메타데이터 전송 시 이 가짜 해시를 보냄
    3. 서명 생성 시에도 이 가짜 해시를 포함하여 서명
       (서명 자체는 변조된 데이터와 일치하므로 서명 검증은 통과)
    4. 실제 데이터는 원본 그대로 암호화하여 전송
    
    예상되는 서버의 반응:
    서버는 모든 데이터를 수신한 뒤 복호화된 데이터의 실제 해시를 계산
    그 다음 클라이언트가 메타데이터로 보낸 가짜 해시("0000...")와 
    실제 해시를 비교하게 되고 이 두 값이 불일치하므로 서버는 파일 저장을 거부하고 에러를 발생
    """
    print("\n[ATTACK] === 해시 변조 공격(Hash Manipulation Attack) 시작 ===")
    
    # 공격에 사용할 대상 파일이 있는지 확인
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    # TCP 소켓을 생성하여 서버와 통신을 시작
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 1. 서버 연결
            s.connect((utils.SERVER_IP, utils.PORT))
            print(f"[ATTACK] 서버({utils.SERVER_IP}:{utils.PORT})에 연결되었습니다.")

            # 서버 측에서 생성한 양자 내성 KEM 공개키를 수신
            public_key = utils.recv_with_length(s)
            
            # 2. 클라이언트 KEM 캡슐화 수행
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                # 서버 공개키를 이용해 비밀키를 캡슐화
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            # 캡슐화된 암호문을 서버에 전송
            utils.send_with_length(s, kem_ciphertext)
            
            # 공유 비밀키를 HKDF를 이용해 32바이트 AES-GCM 세션 키로 변환
            session_key = utils.derive_key(shared_secret)

            # 3. 메타데이터 준비 단계
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)
            
            # =========================================================
            # [공격 포인트: 가짜 해시 주입]
            # 정상적인 클라이언트라면 utils.sha256_file() 결과를 전송해야 하지만
            # 공격자는 강제로 문자열 "0"이 64개 나열된 가짜 해시를 만듦
            # =========================================================
            print("[ATTACK] 파일 해시를 모두 '0'으로 채워진 가짜 해시로 변조합니다!")
            fake_hash = "0" * 64
            
            # 4. 변조된 메타데이터 전송
            # 가짜 해시를 포함한 파일 정보들을 서버에 전송
            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))
            s.sendall(fake_hash.encode("utf-8"))

            # 5. 서명 생성 (변조된 해시를 포함)
            # ML-DSA 서명 알고리즘을 사용해 메타데이터 문자열에 전자서명
            # 서버 측에서는 '서명' 자체는 클라이언트가 보낸 데이터와 일치하므로 유효하다고 판단
            metadata_for_sign = (filename + str(filesize) + fake_hash).encode("utf-8")
            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)

            # 서명 검증을 위한 공개키와 서명값을 전송
            utils.send_with_length(s, sig_public_key)
            utils.send_with_length(s, signature)

            # 6. 실제 데이터(페이로드) 청크 전송
            # 데이터 자체는 변조하지 않고 올바르게 AES-GCM으로 암호화해서 보냄
            aesgcm = AESGCM(session_key)
            chunk_index = 0
            
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(utils.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # 데이터를 압축
                    compressed_chunk = zlib.compress(chunk)
                    
                    # 12바이트 랜덤 Nonce를 생성
                    nonce = os.urandom(12)
                    
                    # 암호화 및 태그 생성
                    encrypted_chunk = aesgcm.encrypt(nonce, compressed_chunk, None)
                    payload = nonce + encrypted_chunk
                    
                    # 헤더와 함께 청크 데이터를 전송
                    s.sendall(struct.pack("!BQI", 0x01, chunk_index, len(payload)))
                    s.sendall(payload)
                    chunk_index += 1
            
            print("[ATTACK] 변조된 해시와 함께 원본 데이터 전송을 마쳤습니다.")
            
            # 7. 종료 신호 전송
            utils.send_with_length(s, b"CLIENT_DONE")
            
        except Exception as e:
            # 네트워크가 도중에 차단되거나 끊겼을 경우 에러를 출력
            print(f"[ATTACK] 전송 중 예외 또는 오류 발생 (서버가 연결을 차단했을 수 있습니다): {e}")

if __name__ == "__main__":
    # 테스트를 위한 더미 파일을 즉석에서 생성
    test_file = "test_hash_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for Hash attack." * 100)
        
    # 공격 시나리오 실행
    run_attack_client(test_file)
