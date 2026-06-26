import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from pqc_transfer.core.client import PQCClient
from pqc_transfer.protocol import chunk_stream
from pqc_transfer.utils import network

class AttackPayloadClient(PQCClient):
    """페이로드 변조 공격을 수행하는 클라이언트 (PQCClient 상속)"""
    def transfer_file_chunks(self):
        # ChunkSender를 가로채어 첫 번째 패킷 변조
        original_sendall = self.socket.sendall
        
        def mocked_sendall(data):
            # 대략적인 암호문 크기 (정확한 패킷 검사 로직 적용 가능)
            if isinstance(data, bytes) and len(data) > 1024:
                print("[ATTACK] 파일의 첫 번째 청크 암호문 앞부분을 변조합니다! (AES-GCM 무결성 검증 시뮬레이션)")
                mut_data = bytearray(data)
                mut_data[0] ^= 0xFF
                original_sendall(bytes(mut_data))
                # 한 번만 변조 후 복원
                self.socket.sendall = original_sendall
            else:
                original_sendall(data)
                
        self.socket.sendall = mocked_sendall
        super().transfer_file_chunks()
        self.socket.sendall = original_sendall # 혹시 모를 복원

def run_attack_client(file_path: str):
    print(f"\n[ATTACK] === 페이로드 변조 공격(Payload Manipulation Attack) ===")
    
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    client = AttackPayloadClient(file_path)
    try:
        client.transfer()
        print("[ATTACK] 경고: 서버가 공격을 차단하지 않았습니다 (서버 응답 SERVER_OK).")
    except Exception as e:
        print(f"[ATTACK] 서버가 정상적으로 공격을 차단했습니다 (예외 발생): {e}")

if __name__ == "__main__":
    test_file = "test_payload_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for attack." * 100)
    run_attack_client(test_file)
