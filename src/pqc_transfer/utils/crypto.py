import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def hash_ss(shared_secret: bytes) -> str:
    """
    공유 비밀키(Shared Secret)의 SHA-256 해시값을 문자열(Hex)로 반환합니다.
    주로 콘솔 로그에 출력하여 클라이언트와 서버가 동일한 키를 도출했는지 디버깅하고 검증하는 용도로 사용됩니다.
    보안상 실제 키를 직접 출력하면 유출 위험이 있으므로, 안전하게 해시값만 출력합니다.
    """
    # 내장 라이브러리 hashlib을 사용하여 전달받은 공유 비밀키의 SHA-256 다이제스트를 16진수 문자열로 반환
    return hashlib.sha256(shared_secret).hexdigest()

def derive_key(shared_secret: bytes) -> bytes:
    """
    KEM을 통해 교환된 공유 비밀키 원본을 그대로 암호화 키로 사용하는 대신,
    HKDF (HMAC-based Key Derivation Function)를 거쳐 안전하고 균일한 32바이트(256비트) 세션 키로 도출합니다.
    이렇게 하면 키의 난수성이 크게 향상되어 AES-GCM 같은 대칭키 암호화 알고리즘에 사용하기 적합해집니다.
    """
    # HKDF 객체 초기화: 강력한 암호학적 해시 알고리즘인 SHA-256을 기반으로 사용
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        # AES-256-GCM 알고리즘에 필요한 정확한 키 길이인 32바이트(256비트) 지정
        length=32,                  
        # 양쪽(서버/클라이언트)이 동일한 키를 도출해야 하므로 별도의 salt는 생략함 (None)
        salt=None,                  
        # 키 도출 목적을 나타내는 애플리케이션 종속적인 컨텍스트 정보 (바이트 문자열)
        info=b"handshake data",     
    )
    # 초기화된 HKDF 객체를 사용하여 원본 공유 비밀키로부터 최종 세션 키를 도출 및 반환
    return hkdf.derive(shared_secret)

def sha256_file(file_path: str, chunk_size: int = 1024 * 1024) -> str:
    """
    지정된 경로의 파일에 대해 SHA-256 해시를 계산하여 16진수 문자열로 반환합니다.
    대용량 파일(예: 수 GB)을 한 번에 메모리에 올리면 MemoryError(OOM)가 발생할 수 있으므로,
    chunk_size 단위로 나누어 읽거나 Python 3.11+ 의 빠른 file_digest를 활용합니다.
    """
    if hasattr(hashlib, 'file_digest'):
        with open(file_path, "rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()
            
    # hashlib 라이브러리의 sha256 해시 객체 초기화
    h = hashlib.sha256()
    # 메모리 복사본 생성을 방지하기 위해 고정 크기(CHUNK_SIZE) 버퍼와 memoryview 활용 (Zero-copy 최적화)
    buffer = bytearray(chunk_size)
    view = memoryview(buffer)
    # 파일을 바이너리 읽기 모드("rb")로 엽니다.
    with open(file_path, "rb") as f:
        while True:
            bytes_read = f.readinto(buffer)
            if not bytes_read:
                break
            # 읽어온 실제 조각만큼만 memoryview로 슬라이싱하여 해시 누적(update)
            h.update(view[:bytes_read])
    # 최종적으로 누적 계산된 해시값을 16진수 문자열 형식으로 반환합니다.
    return h.hexdigest()
