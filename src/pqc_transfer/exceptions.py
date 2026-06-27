class PQCBaseError(Exception):
    """PQC File Transfer 애플리케이션의 최상위 예외 클래스입니다."""
    pass

class PQCProtocolError(PQCBaseError):
    """프로토콜 규격(헤더, 길이, 순서 등)에 위배되는 데이터가 수신될 때 발생합니다."""
    pass

class PQCHandshakeError(PQCProtocolError):
    """초기 KEM 키 교환(Handshake) 과정에서 발생하는 오류입니다."""
    pass

class PQCIntegrityError(PQCBaseError):
    """데이터 위변조가 의심되거나 무결성 검증(AES-GCM MAC, SHA-256)에 실패할 때 발생합니다."""
    pass

class PQCAuthenticationError(PQCBaseError):
    """서버나 클라이언트의 서명 검증(ML-DSA) 또는 신원 확인(TOFU)에 실패할 때 발생합니다."""
    pass

class PQCSecurityError(PQCBaseError):
    """Zip Bomb, 디스크 고갈(DoS), 디렉토리 순회 공격 등 보안 정책에 위배될 때 발생합니다."""
    pass

class PQCNetworkError(PQCBaseError):
    """통신 중 소켓이 끊어지거나 시간 초과가 발생했을 때 발생합니다."""
    pass
