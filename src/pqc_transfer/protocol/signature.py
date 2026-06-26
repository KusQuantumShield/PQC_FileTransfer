import time
import oqs

from ..utils import config, crypto, key_manager, logger, network
from .. import exceptions
from . import constants

import socket

def _build_metadata_payload(client_id: str, filename: str, filesize: int, file_hash: str, session_key: bytes, challenge_nonce: str) -> bytes:
    session_key_hash = crypto.hash_ss(session_key)
    return f"{client_id}|{filename}|{filesize}|{file_hash}|{session_key_hash}|{challenge_nonce}".encode("utf-8")

def create_and_send_signature(sock: socket.socket, file_hash: str, client_id: str, filename: str, sent_size: int, session_key: bytes, sig_alg: str, km) -> None:
    """
    클라이언트 관점의 데이터 서명 및 전송
    """
    network.send_with_length(sock, file_hash.encode("utf-8"))
    
    challenge_nonce = network.recv_with_length(sock, max_len=constants.MAX_NONCE_LEN).decode("utf-8")
    if challenge_nonce.startswith("ERROR:"):
        raise exceptions.PQCAuthenticationError(f"서버 거부: {challenge_nonce[6:]}")
    logger.log("INFO", "SIGN", "서버로부터 Replay 방지용 Challenge Nonce 수신 완료")
    
    metadata_for_sign = _build_metadata_payload(client_id, filename, sent_size, file_hash, session_key, challenge_nonce)

    sign_start_time = time.perf_counter()
    
    sig_public_key, secret_key = km.get_client_sig_keys()
    
    with oqs.Signature(sig_alg, secret_key=secret_key) as signer:
        signature = signer.sign(metadata_for_sign)
        
    sign_end_time = time.perf_counter()

    logger.log("PASS", "SIGN", f"ML-DSA 서명 생성 완료 (소요 시간: {sign_end_time - sign_start_time:.4f} 초)")
    logger.log("INFO", "SIGN", f"서명 공개키 크기: {len(sig_public_key)} 바이트")
    logger.log("INFO", "SIGN", f"서명 크기: {len(signature)} 바이트")

    network.send_with_length(sock, sig_public_key)
    logger.log("INFO", "SIGN", "서명 공개키 전송 완료")

    network.send_with_length(sock, signature)
    logger.log("INFO", "SIGN", "서명 전송 완료")

def verify_signature(conn: socket.socket, client_id: str, filename: str, received_size: int, session_key: bytes, file_hash: str, challenge_nonce: str, sig_alg: str, km) -> bool:
    """
    서버 관점의 클라이언트 서명 검증
    """
    client_file_hash = network.recv_with_length(conn, max_len=constants.MAX_HASH_LEN).decode("utf-8")
    if client_file_hash != file_hash:
        logger.log("ERROR", "HASH", f"해시 불일치: 클라이언트={client_file_hash}, 계산됨={file_hash}")
        network.send_with_length(conn, b"ERROR:HASH_MISMATCH")
        return False
        
    logger.log("PASS", "HASH", "파일 무결성 검증 완료 (해시 일치)")

    network.send_with_length(conn, challenge_nonce.encode("utf-8"))

    sig_public_key = network.recv_with_length(conn, max_len=constants.MAX_SIG_KEY_LEN)
    
    if not km.verify_and_trust_client(client_id, sig_public_key):
        logger.log("FAIL", "VERIFY", "등록되지 않은 송신자의 공개키입니다 (MitM 또는 공격 의심)")
        network.send_with_length(conn, b"ERROR:UNTRUSTED_CLIENT")
        return False

    signature = network.recv_with_length(conn, max_len=constants.MAX_SIG_LEN)
    
    verify_start_time = time.perf_counter()
    
    metadata_for_verify = _build_metadata_payload(client_id, filename, received_size, file_hash, session_key, challenge_nonce)

    with oqs.Signature(sig_alg) as verifier:
        expected_sig_pk_len = verifier.details['length_public_key']
        expected_sig_len = verifier.details['length_signature']
        
        if len(sig_public_key) != expected_sig_pk_len:
            logger.log("ERROR", "SIGN", f"유효하지 않은 클라이언트 서명 공개키 길이: {len(sig_public_key)}")
            network.send_with_length(conn, b"ERROR:INVALID_SIG_PK_LENGTH")
            return False
            
        if len(signature) != expected_sig_len:
            logger.log("ERROR", "SIGN", f"유효하지 않은 클라이언트 서명 길이: {len(signature)}")
            network.send_with_length(conn, b"ERROR:INVALID_SIG_LENGTH")
            return False

        if not verifier.verify(metadata_for_verify, signature, sig_public_key):
            logger.log("FAIL", "SIGN", "전자서명 검증 실패: 서명이 위조되었거나 데이터가 변조되었습니다!")
            network.send_with_length(conn, b"ERROR:SIGNATURE_VERIFICATION_FAILED")
            return False
            
    verify_end_time = time.perf_counter()
    logger.log("PASS", "SIGN", f"ML-DSA 서명 검증 완료 (소요 시간: {verify_end_time - verify_start_time:.4f} 초)")
    
    return True
