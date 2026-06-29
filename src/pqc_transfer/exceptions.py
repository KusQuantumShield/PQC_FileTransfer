class PQCBaseError(Exception):
    """
    PQC File Transfer 애플리케이션에서 발생하는 모든 커스텀 예외의 최상위 기저 클래스입니다.

    모든 하위 모듈은 이 클래스 혹은 이 클래스를 상속받은 하위 예외만 발생시켜야 하며,
    이를 통해 호출부(핸들러 등)에서 PQC 관련 예외와 내장 파이썬 예외를 명확히 구분할 수 있습니다.
    """

    pass


class PQCProtocolError(PQCBaseError):
    """
    통신 프로토콜 규격(헤더 길이, 순서, 인덱스 불일치 등)에 위배되는 데이터가 수신될 때 발생합니다.
    """

    pass


class PQCHandshakeError(PQCProtocolError):
    """
    초기 KEM(Key Encapsulation Mechanism) 키 쌍 생성 및 교환 과정에서 발생하는 오류입니다.
    """

    pass


class PQCIntegrityError(PQCBaseError):
    """
    수신된 데이터의 위변조가 의심되거나, AES-GCM 복호화(MAC 인증) 및 SHA-256 검증에 실패할 때 발생합니다.
    """

    pass


class PQCAuthenticationError(PQCBaseError):
    """
    서버 또는 클라이언트의 ML-DSA 전자서명 검증에 실패하거나 신원 확인(TOFU)에 실패할 때 발생합니다.
    """

    pass


class PQCSecurityError(PQCBaseError):
    """
    Zip Bomb, 디스크 고갈(DoS), 디렉토리 순회 공격 등 보안 정책에 명백히 위배되는 악의적 요청 시 발생합니다.
    """

    pass


class PQCNetworkError(PQCBaseError):
    """
    통신 중 소켓이 비정상적으로 끊어지거나 Slowloris 등 타임아웃(Timeout)이 발생했을 때 발생합니다.
    """

    pass
