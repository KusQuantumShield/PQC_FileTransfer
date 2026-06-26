import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from pqc_transfer.core.client import PQCClient
from pqc_transfer.utils import network

class AttackSignatureClient(PQCClient):
    """전자서명 변조 공격을 수행하는 클라이언트 (PQCClient 상속)"""
    def create_and_send_signature(self):
        # 7. 서명할 메타데이터 구성 시, 의도적으로 다른 내용으로 서명
        # (예: sent_size를 999999로 위조하여 서명)
        print("[ATTACK] 파일 메타데이터(크기)를 위조하여 PQC 전자서명을 생성합니다!")
        fake_size = 999999
        challenge_nonce = network.recv_with_length(self.socket).decode("utf-8")
        if challenge_nonce.startswith("ERROR:"):
            raise ValueError(f"서버 거부: {challenge_nonce[6:]}")
        
        # 가짜 메타데이터로 서명 생성
        from pqc_transfer.utils import config
        import oqs
        from pqc_transfer.protocol.signature import _build_metadata_payload
        fake_metadata = _build_metadata_payload(self.client_id, self.filename, fake_size, self.file_hash, self.session_key, challenge_nonce)
        
        key_dir = config.KEY_DIR
        sig_sec_file = os.path.join(key_dir, "client_sig_sec.bin")
        sig_pub_file = os.path.join(key_dir, "client_sig_pub.bin")
        with open(sig_sec_file, "rb") as f:
            secret_key = f.read()
        with open(sig_pub_file, "rb") as f:
            sig_public_key = f.read()
            
        with oqs.Signature(config.SIG_ALG, secret_key=secret_key) as signer:
            signature = signer.sign(fake_metadata)
            
        # 8. 서명 공개키와 조작된 서명 전송
        network.send_with_length(self.socket, sig_public_key)
        network.send_with_length(self.socket, signature)

def run_attack_client(file_path: str):
    print(f"\n[ATTACK] === 서명 변조 공격(Signature Manipulation Attack) ===")
    
    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    client = AttackSignatureClient(file_path)
    try:
        client.transfer()
        print("[ATTACK] 경고: 서버가 공격을 차단하지 않았습니다 (서버 응답 SERVER_OK).")
    except Exception as e:
        print(f"[ATTACK] 서버가 정상적으로 공격을 차단했습니다 (예외 발생): {e}")

if __name__ == "__main__":
    test_file = "test_signature_attack.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for attack." * 100)
    run_attack_client(test_file)
