import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def hash_ss(shared_secret: bytes) -> str:
    """
    공유 비밀키(Shared Secret)의 SHA-256 해시값을 계산합니다.
    
    Args:
        shared_secret (bytes): KEM을 통해 교환된 원본 공유 비밀키.
        
    Returns:
        str: 로깅 및 디버깅 용도로 안전하게 출력 가능한 SHA-256 해시값(16진수 문자열).
    """
    return hashlib.sha256(shared_secret).hexdigest()

def derive_key(shared_secret: bytes) -> bytes:
    """
    HKDF를 사용하여 원본 공유 비밀키로부터 안전한 32바이트 세션 키를 도출합니다.
    
    Args:
        shared_secret (bytes): KEM을 통해 교환된 원본 공유 비밀키.
        
    Returns:
        bytes: AES-256-GCM 알고리즘에 적합한 32바이트(256비트) 길이의 파생 키.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    )
    return hkdf.derive(shared_secret)

def sha256_file(file_path: str, chunk_size: int = 1024 * 1024) -> str:
    """
    효율적인 메모리 관리를 통해 대상 파일의 SHA-256 해시를 계산합니다.
    
    Python 3.11 이상인 경우 `hashlib.file_digest`를 사용하여 빠르게 처리하며,
    그렇지 않은 경우 OOM(Out Of Memory) 방지를 위해 Zero-copy 방식의 
    청크(chunk) 단위 메모리뷰(memoryview) 읽기를 수행합니다.
    
    Args:
        file_path (str): 해시를 계산할 파일의 절대 또는 상대 경로.
        chunk_size (int): 파일 읽기 버퍼의 크기(바이트). 기본값은 1MB입니다.
        
    Returns:
        str: 계산된 파일의 SHA-256 다이제스트(16진수 문자열).
    """
    if hasattr(hashlib, 'file_digest'):
        with open(file_path, "rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()
            
    h = hashlib.sha256()
    buffer = bytearray(chunk_size)
    view = memoryview(buffer)
    
    with open(file_path, "rb") as f:
        while True:
            bytes_read = f.readinto(buffer)
            if not bytes_read:
                break
            h.update(view[:bytes_read])
            
    return h.hexdigest()
