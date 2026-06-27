import os

SERVER_IP = os.environ.get("PQC_SERVER_IP", "127.0.0.1")  # 클라이언트가 접속할 서버의 IP 주소
HOST = os.environ.get("PQC_HOST", "0.0.0.0")              # 서버가 수신 대기할 IP 주소
PORT = int(os.environ.get("PQC_PORT", "9999"))            # 포트 번호
CHUNK_SIZE = int(os.environ.get("PQC_CHUNK_SIZE", 4 * 1024 * 1024)) # 청크 크기 (기본 4MB)

# 양자 내성 암호(PQC) 알고리즘 설정
KEM_ALG = os.environ.get("PQC_KEM_ALG", "ML-KEM-768")
SIG_ALG = os.environ.get("PQC_SIG_ALG", "ML-DSA-65")

# 암호화 키를 저장할 디렉토리 (기본값: ~/.pqc_transfer_keys)
KEY_DIR = os.environ.get("PQC_KEY_DIR", os.path.expanduser("~/.pqc_transfer_keys"))

# 수신된 파일을 저장할 기본 디렉토리
SAVE_DIR = os.environ.get("PQC_SAVE_DIR", os.path.join(os.getcwd(), "received_files"))
