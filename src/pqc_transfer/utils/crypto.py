import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def hash_ss(shared_secret: bytes) -> str:
    """
    공유 비밀키(Shared Secret)의 SHA-256 해시값을 문자열로 반환
    주로 콘솔 로그에 출력하여 클라이언트와 서버가 동일한 키를 도출했는지 확인하는 용도로 사용
    보안상 실제 키를 직접 출력하지 않고 해시값만 출력
    """
    return hashlib.sha256(shared_secret).hexdigest()

def derive_key(shared_secret: bytes) -> bytes:
    """
    KEM을 통해 교환된 공유 비밀키 원본을 그대로 암호화 키로 사용하는 대신
    HKDF (HMAC-based Key Derivation Function)를 거쳐 안전한 32바이트(256비트) 세션 키로 도출
    이렇게 하면 키의 난수성이 향상되어 AES-GCM 같은 대칭키 암호화에 사용하기 적합해짐
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                  # AES-256-GCM에 사용할 32바이트 길이
        salt=None,                  # 별도의 salt는 사용하지 않음
        info=b"handshake data",     # 키 도출 목적을 나타내는 컨텍스트 정보
    )
    return hkdf.derive(shared_secret)
