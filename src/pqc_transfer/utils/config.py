import os
from dataclasses import dataclass, field

@dataclass
class AppConfig:
    """
    애플리케이션 전반에서 사용되는 설정(Configuration) 객체입니다.
    
    환경 변수(Environment Variables)를 통해 초기화되며, PQC 서버 주소 및 포트,
    청크 크기, 사용할 키 캡슐화(KEM)/서명(Signature) 알고리즘 등의 상태를 관리합니다.
    이를 통해 설정 데이터에 대한 의존성 주입(DI)이 가능해져 코드의 결합도가 낮아집니다.
    """
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
