import os
from dataclasses import dataclass, field

@dataclass
class AppConfig:
    server_ip: str = field(default_factory=lambda: os.environ.get("PQC_SERVER_IP", "127.0.0.1"))
    host: str = field(default_factory=lambda: os.environ.get("PQC_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.environ.get("PQC_PORT", "9999")))
    chunk_size: int = field(default_factory=lambda: int(os.environ.get("PQC_CHUNK_SIZE", 4 * 1024 * 1024)))
    
    kem_alg: str = field(default_factory=lambda: os.environ.get("PQC_KEM_ALG", "ML-KEM-768"))
    sig_alg: str = field(default_factory=lambda: os.environ.get("PQC_SIG_ALG", "ML-DSA-65"))
    
    key_dir: str = field(default_factory=lambda: os.environ.get("PQC_KEY_DIR", os.path.expanduser("~/.pqc_transfer_keys")))
    save_dir: str = field(default_factory=lambda: os.environ.get("PQC_SAVE_DIR", os.path.join(os.getcwd(), "received_files")))

# 전역 접근을 위한 기본 인스턴스 (필요 시 DI를 통해 대체 가능)
default_config = AppConfig()
