import os
import socket
import struct
import zlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils

def run_attack_client(file_path: str):
    """
    [페이로드 변조 공격(Payload Manipulation Attack) 시나리오]
    
    공격 목표:
    파일 전송 과정에서 공격자가 암호화되기 직전의 평문 데이터 일부를 악의적으로 수정
    
    동작 방식:
    1. 메타데이터(파일명, 사이즈, 정상 해시)와 전자서명은 조작하지 않고 올바르게 보냄
    2. 파일을 청크 단위로 읽어올 때 0번째 청크의 특정 위치 데이터를 "HACKED"라는 문자열로 덮어씌움
    3. 악성 코드가 섞인 청크를 클라이언트가 정상적인 세션 키로 AES-GCM 암호화하여 서버로 전송
    
    예상되는 서버의 반응:
    클라이언트가 올바른 암호화 키(Session Key)로 암호화를 했기 때문에
    서버의 AES-GCM 복호화 과정(태그 검증)은 정상적으로 통과
    하지만 복호화된 데이터들로 최종 파일 해시를 계산했을 때
    수신된 파일의 해시값이 메타데이터로 전달받은 원본 해시값과 다르게 나오게 됨
    결과적으로 서버는 해시 불일치를 선언하고 파일 저장을 거부
    """
    print("\n[ATTACK] === 페이로드 변조 공격(Payload Manipulation Attack) 시작 ===")
    
    # 공격 대상 파일 존재 유무 확인
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 1. 서버에 연결 및 KEM 키 교환 진행
            s.connect((utils.SERVER_IP, utils.PORT))
            print(f"[ATTACK] 서버({utils.SERVER_IP}:{utils.PORT})에 연결되었습니다.")

            # 서버의 KEM 공개키 수신
            public_key = utils.recv_with_length(s)
            
            # 클라이언트 KEM 캡슐화 및 비밀키 도출
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            # 암호문 전송 및 AES 세션 키 준비
            utils.send_with_length(s, kem_ciphertext)
            session_key = utils.derive_key(shared_secret)

            # 2. 메타데이터 수집 (여기서는 정상적인 값 사용)
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)
            file_hash = utils.sha256_file(file_path)
            
            # 메타데이터 전송 (파일명, 크기, 해시)
            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))
            s.sendall(file_hash.encode("utf-8"))

            # 3. 메타데이터 전자서명 생성 및 전송 (정상 서명 사용)
            metadata_for_sign = (filename + str(filesize) + file_hash).encode("utf-8")
            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)

            utils.send_with_length(s, sig_public_key)
            utils.send_with_length(s, signature)

            # 4. 청크 전송 시 데이터 강제 변조
            aesgcm = AESGCM(session_key)
            chunk_index = 0
            
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(utils.CHUNK_SIZE)
                    if not chunk:
                        break
                        
                    # =========================================================
                    # [공격 포인트: 청크 평문 데이터 조작]
                    # 첫 번째 전송되는 청크(0번 청크)의 내용을 강제로 조작
                    # =========================================================
                    if chunk_index == 0:
                        print("[ATTACK] 파일의 첫 번째 청크 평문 앞부분을 'HACKED'로 변조합니다!")
                        # 앞 6바이트 길이를 악의적인 문자열인 'HACKED'로 대체
                        chunk = b"HACKED" + chunk[6:]
                    
                    # 변조된 청크를 정상적으로 압축 및 AES-GCM 암호화 처리
                    compressed_chunk = zlib.compress(chunk)
                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, compressed_chunk, None)
                    payload = nonce + encrypted_chunk
                    
                    # 패킷 구성 및 전송
                    s.sendall(struct.pack("!BQI", 0x01, chunk_index, len(payload)))
                    s.sendall(payload)
                    chunk_index += 1
            
            print("[ATTACK] 변조된 평문 페이로드가 모두 서버로 전송되었습니다.")
            
            # 5. 전송 완료 신호 발송
            utils.send_with_length(s, b"CLIENT_DONE")
            
        except Exception as e:
            print(f"[ATTACK] 전송 중 예상된 예외 발생 (서버에서 통신을 중단했을 수 있습니다): {e}")

if __name__ == "__main__":
    # 테스트를 위한 더미 파일 생성
    test_file = "test_payload_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for Payload attack." * 100)
    
    # 공격 시나리오 실행
    run_attack_client(test_file)
