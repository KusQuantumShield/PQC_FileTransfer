import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from pqc_transfer.core.client import PQCClient

class AttackHashClient(PQCClient):
    """해시 변조 공격을 수행하는 클라이언트 (PQCClient 상속)"""
    def create_and_send_signature(self, conn, file_hash: str, sent_size: int, session_key: bytes):
        print("[ATTACK] 파일 해시를 모두 '0'으로 채워진 가짜 해시로 변조합니다!")
        # 원본 해시를 조작하여 가짜 해시로 서명까지 생성 및 전송되게 함
        fake_hash = '0' * 64
        
        # 원래의 서명 생성 로직 호출 (조작된 해시가 전송됨)
        super().create_and_send_signature(conn, fake_hash, sent_size, session_key)

def run_attack_client(file_path: str):
    print(f"\n[ATTACK] === 해시 변조 공격(Hash Manipulation Attack) ===")
    
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    client = AttackHashClient.from_config(file_path)
    try:
        client.transfer()
        print("[ATTACK] 경고: 서버가 공격을 차단하지 않았습니다 (서버 응답 SERVER_OK).")
    except Exception as e:
        print(f"[ATTACK] 서버가 정상적으로 공격을 차단했습니다 (예외 발생): {e}")

if __name__ == "__main__":
    test_file = "test_hash_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for attack." * 100)
    run_attack_client(test_file)
