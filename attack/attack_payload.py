import sys
from pqc_transfer.core.client import PQCClient

class AttackPayloadClient(PQCClient):
    """페이로드 변조 공격을 수행하는 클라이언트 (PQCClient 상속)"""
    def transfer_file_chunks(self, conn, session_key: bytes) -> tuple[int, str]:
        # ChunkSender를 가로채어 첫 번째 패킷 변조
        original_send_with_length = conn.send_with_length
        
        def mocked_send_with_length(data):
            # 대략적인 암호문 크기 (정확한 패킷 검사 로직 적용 가능)
            if isinstance(data, bytes) and len(data) > 1024:
                print("[ATTACK] 파일의 첫 번째 청크 암호문 앞부분을 변조합니다! (AES-GCM 무결성 검증 시뮬레이션)")
                mut_data = bytearray(data)
                mut_data[0] ^= 0xFF
                original_send_with_length(bytes(mut_data))
                # 한 번만 변조 후 복원
                conn.send_with_length = original_send_with_length
            else:
                original_send_with_length(data)
                
        conn.send_with_length = mocked_send_with_length
        return super().transfer_file_chunks(conn, session_key)

def run_attack_client(file_path: str):
    print(f"\n[ATTACK] === 페이로드 변조 공격(Payload Manipulation Attack) ===")
    
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    client = AttackPayloadClient.from_config(file_path)
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
