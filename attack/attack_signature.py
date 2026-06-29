import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from pqc_transfer.protocol import signature

from pqc_transfer.core.client import PQCClient


class AttackSignatureClient(PQCClient):
    """전자서명 변조 공격을 수행하는 클라이언트 (PQCClient 상속)"""

    def create_and_send_signature(
        self, conn, file_hash: str, sent_size: int, session_key: bytes
    ):
        # 7. 서명할 메타데이터 구성 시, 의도적으로 다른 내용으로 서명
        # (예: sent_size를 999999로 위조하여 서명)
        print("[ATTACK] 파일 메타데이터(크기)를 위조하여 PQC 전자서명을 생성합니다!")
        fake_size = 999999

        # 가짜 메타데이터로 서명 생성 및 전송
        # 서버 측 서명 검증 로직 자체를 모의(Mock)로 우회하는 시뮬레이션
        signature.create_and_send_signature(
            conn,
            file_hash,
            self.client_id,
            self.filename,
            fake_size,
            session_key,
            self.config.sig_alg,
            self.key_manager,
        )


def run_attack_client(file_path: str):
    print("--- 서명 위조 공격 (Authentication Attack) 시작 ---")

    if not os.path.exists(file_path):
        print(f"[ATTACK] 파일을 찾을 수 없습니다: {file_path}")
        return

    client = AttackSignatureClient.from_config(file_path)
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
