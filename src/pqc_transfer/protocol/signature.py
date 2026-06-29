import time
import oqs

from ..utils import crypto, logger, network
from .. import exceptions
from . import constants


def _build_metadata_payload(
    client_id: str,
    filename: str,
    filesize: int,
    file_hash: str,
    session_key: bytes,
    challenge_nonce: str,
) -> bytes:
    session_key_hash = crypto.hash_ss(session_key)
    return f"{client_id}|{filename}|{filesize}|{file_hash}|{session_key_hash}|{challenge_nonce}".encode(
        "utf-8"
    )


def create_and_send_signature(
    conn: network.SecureConnection,
    file_hash: str,
    client_id: str,
    filename: str,
    sent_size: int,
    session_key: bytes,
    sig_alg: str,
    km,
) -> None:
    """
    클라이언트가 최종 전송된 파일의 해시와 메타데이터를 취합하여 PQC(ML-DSA) 서명을 생성 및 전송합니다.

    서버로부터 Replay 공격을 방지하기 위한 Challenge Nonce를 먼저 수신한 뒤,
    모든 정보를 하나로 묶어 서명(Sign)함으로써 송신자의 신원과 파일의 무결성을 증명합니다.

    Args:
        conn (network.SecureConnection): 서버와 연결된 보안 소켓.
        file_hash (str): 파일 전송 중 계산된 전체 데이터의 SHA-256 해시값.
        client_id (str): 클라이언트 고유 식별자.
        filename (str): 전송된 파일명.
        sent_size (int): 실제로 송신된 총 데이터 크기(바이트).
        session_key (bytes): 통신에 사용된 대칭키.
        sig_alg (str): 전자서명 알고리즘 (예: ML-DSA-44).
        km: 서명 키쌍을 관리하는 KeyManager.

    Raises:
        exceptions.PQCAuthenticationError: 서버가 악의적 요청으로 판단하여 수신을 거부한 경우.
    """
    conn.send_with_length(file_hash.encode("utf-8"))

    challenge_nonce = conn.recv_with_length(max_len=constants.MAX_NONCE_LEN).decode(
        "utf-8"
    )
    if challenge_nonce.startswith("ERROR:"):
        raise exceptions.PQCAuthenticationError(f"서버 거부: {challenge_nonce[6:]}")
    logger.log("INFO", "SIGN", "서버로부터 Replay 방지용 Challenge Nonce 수신 완료")

    metadata_for_sign = _build_metadata_payload(
        client_id, filename, sent_size, file_hash, session_key, challenge_nonce
    )

    sign_start_time = time.perf_counter()

    sig_public_key, secret_key = km.get_client_sig_keys()

    with oqs.Signature(sig_alg, secret_key=secret_key) as signer:
        signature = signer.sign(metadata_for_sign)

    sign_end_time = time.perf_counter()

    logger.log(
        "PASS",
        "SIGN",
        f"ML-DSA 서명 생성 완료 (소요 시간: {sign_end_time - sign_start_time:.4f} 초)",
    )
    logger.log("INFO", "SIGN", f"서명 공개키 크기: {len(sig_public_key)} 바이트")
    logger.log("INFO", "SIGN", f"서명 크기: {len(signature)} 바이트")

    conn.send_with_length(sig_public_key)
    logger.log("INFO", "SIGN", "서명 공개키 전송 완료")

    conn.send_with_length(signature)
    logger.log("INFO", "SIGN", "서명 전송 완료")


def verify_signature(
    conn: network.SecureConnection,
    client_id: str,
    filename: str,
    received_size: int,
    session_key: bytes,
    file_hash: str,
    challenge_nonce: str,
    sig_alg: str,
    km,
) -> bool:
    """
    서버가 클라이언트로부터 받은 파일 해시와 ML-DSA 서명을 통해 무결성과 송신자를 인증합니다.

    파일 해시의 일치 여부를 1차적으로 검증한 후, Challenge Nonce를 발급합니다.
    그 뒤 클라이언트가 제출한 공개키의 신뢰성을 검증(TrustStore)하고 서명의 유효성을 확인합니다.

    Args:
        conn (network.SecureConnection): 클라이언트와 연결된 보안 소켓.
        client_id (str): 수신한 메타데이터 상의 클라이언트 ID.
        filename (str): 수신된 파일명.
        received_size (int): 실제로 서버가 수신 및 기록한 파일 크기.
        session_key (bytes): 통신에 사용된 대칭키.
        file_hash (str): 서버 측에서 수신 중 직접 계산한 파일의 해시값.
        challenge_nonce (str): 서버가 클라이언트에게 부여할 난수 챌린지.
        sig_alg (str): 전자서명 알고리즘 (예: ML-DSA-44).
        km: 신뢰된 클라이언트 목록을 검증하는 KeyManager.

    Returns:
        bool: 서명 및 인증이 성공적으로 완료되었을 경우 True, 그렇지 않으면 False.
    """
    client_file_hash = conn.recv_with_length(max_len=constants.MAX_HASH_LEN).decode(
        "utf-8"
    )
    if client_file_hash != file_hash:
        logger.log(
            "ERROR",
            "HASH",
            f"해시 불일치: 클라이언트={client_file_hash}, 계산됨={file_hash}",
        )
        conn.send_with_length(b"ERROR:HASH_MISMATCH")
        return False

    logger.log("PASS", "HASH", "파일 무결성 검증 완료 (해시 일치)")

    conn.send_with_length(challenge_nonce.encode("utf-8"))

    sig_public_key = conn.recv_with_length(max_len=constants.MAX_SIG_KEY_LEN)

    if not km.verify_and_trust_client(client_id, sig_public_key):
        logger.log(
            "FAIL",
            "VERIFY",
            "등록되지 않은 송신자의 공개키입니다 (MitM 또는 공격 의심)",
        )
        conn.send_with_length(b"ERROR:UNTRUSTED_CLIENT")
        return False

    signature = conn.recv_with_length(max_len=constants.MAX_SIG_LEN)

    verify_start_time = time.perf_counter()

    metadata_for_verify = _build_metadata_payload(
        client_id, filename, received_size, file_hash, session_key, challenge_nonce
    )

    with oqs.Signature(sig_alg) as verifier:
        expected_sig_pk_len = verifier.details["length_public_key"]
        expected_sig_len = verifier.details["length_signature"]

        if len(sig_public_key) != expected_sig_pk_len:
            logger.log(
                "ERROR",
                "SIGN",
                f"유효하지 않은 클라이언트 서명 공개키 길이: {len(sig_public_key)}",
            )
            conn.send_with_length(b"ERROR:INVALID_SIG_PK_LENGTH")
            return False

        if len(signature) != expected_sig_len:
            logger.log(
                "ERROR", "SIGN", f"유효하지 않은 클라이언트 서명 길이: {len(signature)}"
            )
            conn.send_with_length(b"ERROR:INVALID_SIG_LENGTH")
            return False

        if not verifier.verify(metadata_for_verify, signature, sig_public_key):
            logger.log(
                "FAIL",
                "SIGN",
                "전자서명 검증 실패: 서명이 위조되었거나 데이터가 변조되었습니다!",
            )
            conn.send_with_length(b"ERROR:SIGNATURE_VERIFICATION_FAILED")
            return False

    verify_end_time = time.perf_counter()
    logger.log(
        "PASS",
        "SIGN",
        f"ML-DSA 서명 검증 완료 (소요 시간: {verify_end_time - verify_start_time:.4f} 초)",
    )

    return True
