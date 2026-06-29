import struct
import time
import oqs

from ..utils import config, crypto, key_manager, logger, connection
from .. import exceptions
from . import constants

import socket

def perform_client_handshake(conn: connection.SecureConnection, server_ip: str, kem_alg: str, sig_alg: str, km) -> bytes:
    """
    클라이언트 관점의 KEM 핸드셰이크 수행
    """
    kem_start_time = time.perf_counter()
    
    pk_len_bytes = conn.recv_exact(4)
    pk_len = struct.unpack("!I", pk_len_bytes)[0]
    
    if pk_len <= 0 or pk_len > 10000:
        logger.log("FAIL", "KEM", f"유효하지 않은 공개키 길이: {pk_len}")
        raise exceptions.PQCHandshakeError("Invalid public key length")

    public_key = conn.recv_exact(pk_len)
    
    with oqs.KeyEncapsulation(kem_alg) as kem:
        expected_pk_len = kem.details['length_public_key']
        if len(public_key) != expected_pk_len:
            logger.log("ERROR", "KEM", f"유효하지 않은 서버 공개키 길이: {len(public_key)} (예상: {expected_pk_len})")
            raise exceptions.PQCHandshakeError(f"유효하지 않은 서버 공개키 길이 (크래시 방어)")
            
        server_sig_pk = conn.recv_with_length(max_len=constants.MAX_SIG_KEY_LEN)
        server_signature = conn.recv_with_length(max_len=constants.MAX_SIG_LEN)
        
        with oqs.Signature(sig_alg) as verifier:
            expected_sig_pk_len = verifier.details['length_public_key']
            expected_sig_len = verifier.details['length_signature']
            
            if len(server_sig_pk) != expected_sig_pk_len:
                logger.log("ERROR", "SIGN", f"유효하지 않은 서버 서명 공개키 길이: {len(server_sig_pk)}")
                raise exceptions.PQCAuthenticationError("유효하지 않은 서버 서명 공개키 길이 (크래시 방어)")
                
            if len(server_signature) != expected_sig_len:
                logger.log("ERROR", "SIGN", f"유효하지 않은 서버 서명 길이: {len(server_signature)}")
                raise exceptions.PQCAuthenticationError("유효하지 않은 서버 서명 길이 (크래시 방어)")

            if not verifier.verify(public_key, server_signature, server_sig_pk):
                logger.log("FAIL", "SIGN", "서버 서명 검증 실패: 임시 KEM 공개키가 변조되었습니다! (MitM 공격 의심)")
                raise exceptions.PQCAuthenticationError("서버 서명 검증 실패 (MitM 공격 의심)")
                
        logger.log("PASS", "SIGN", "서버 서명 검증 성공 (KEM 공개키 무결성 확인)")

        if not km.verify_and_trust_server(server_ip, server_sig_pk):
            logger.log("FAIL", "VERIFY", "서버 인증 실패: 서버의 서명 공개키가 변경되었습니다! (MitM 공격 의심)")
            raise exceptions.PQCAuthenticationError("서버의 서명 공개키가 변경되었습니다! (MitM 공격 의심)")

        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

    logger.log("PASS", "KEM", "캡슐화 완료")
    logger.log("INFO", "KEY", f"공유 비밀키 해시: {crypto.hash_ss(shared_secret)}")

    conn.send_with_length(kem_ciphertext)
    logger.log("INFO", "KEM", f"암호문 전송 완료 ({len(kem_ciphertext)} 바이트)")

    session_key = crypto.derive_key(shared_secret)
    kem_end_time = time.perf_counter()
    logger.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
    logger.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")
    
    return session_key

def perform_server_handshake(conn: connection.SecureConnection, kem_alg: str, sig_alg: str, km) -> bytes:
    """
    서버 관점의 KEM 핸드셰이크 수행
    """
    kem_start_time = time.perf_counter()
    
    with oqs.KeyEncapsulation(kem_alg) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        
    logger.log("PASS", "KEM", "KEM 임시 키쌍 생성 완료")
    logger.log("INFO", "KEM", f"공개키 크기: {len(public_key)} 바이트")

    conn.sock.sendall(struct.pack("!I", len(public_key)))
    conn.sock.sendall(public_key)
    
    sig_public_key, sig_secret_key = km.get_server_sig_keys()
    with oqs.Signature(sig_alg, secret_key=sig_secret_key) as signer:
        signature = signer.sign(public_key)
        
    conn.send_with_length(sig_public_key)
    conn.send_with_length(signature)

    logger.log("INFO", "SIGN", "임시 KEM 공개키 서명 및 전송 완료 (MitM 방어용)")

    kem_ciphertext = conn.recv_with_length(max_len=constants.MAX_KEM_CIPHERTEXT_LEN)
    logger.log("INFO", "KEM", f"클라이언트 암호문 수신 완료 ({len(kem_ciphertext)} 바이트)")

    with oqs.KeyEncapsulation(kem_alg, secret_key=secret_key) as kem:
        shared_secret = kem.decap_secret(kem_ciphertext)
        
    logger.log("PASS", "KEM", "디캡슐화 완료")
    logger.log("INFO", "KEY", f"공유 비밀키 해시: {crypto.hash_ss(shared_secret)}")

    session_key = crypto.derive_key(shared_secret)
    kem_end_time = time.perf_counter()
    logger.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
    logger.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")
    
    return session_key
