import os
import socket
import struct
import zlib
import time

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils

def main():
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 클라이언트 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    # 1. 사용자에게 전송할 파일을 선택받음
    file_path = utils.select_file()

    if not file_path:
        utils.log("INFO", "FILE", "사용자가 파일 선택을 취소했습니다")
        return

    if not os.path.exists(file_path):
        utils.log("ERROR", "FILE", f"파일을 찾을 수 없습니다: {file_path}")
        utils.show_error("파일 오류", f"파일을 찾을 수 없습니다.\n\n{file_path}")
        return

    # TCP IPv4 소켓 생성
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # =========================================================
            # [단계 1] 서버 접속 및 핸드셰이크 (KEM을 이용한 키 교환)
            # =========================================================
            s.connect((utils.SERVER_IP, utils.PORT))
            utils.log("INFO", "CONNECT", f"서버 {utils.SERVER_IP}:{utils.PORT}에 연결되었습니다")

            kem_start_time = time.perf_counter()

            # 서버가 보낸 양자 내성 공개키(Public Key)를 수신
            pk_len_bytes = utils.recv_exact(s, 4)
            pk_len = struct.unpack("!I", pk_len_bytes)[0]
            
            if pk_len <= 0 or pk_len > 10000:
                utils.log("FAIL", "KEM", f"유효하지 않은 공개키 길이: {pk_len}")
                raise ValueError("Invalid public key length")

            public_key = utils.recv_exact(s, pk_len)
            utils.log("INFO", "KEM", f"서버 공개키를 수신했습니다 ({len(public_key)} 바이트)")

            # KEM 알고리즘을 사용하여 서버의 공개키로 공유 비밀키를 캡슐화
            with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            utils.log("PASS", "KEM", "캡슐화 완료")
            utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")

            # 생성된 KEM 암호문을 서버로 전송
            utils.send_with_length(s, kem_ciphertext)
            utils.log("INFO", "KEM", f"암호문 전송 완료 ({len(kem_ciphertext)} 바이트)")

            # 교환된 공유 비밀키(shared_secret)를 HKDF를 통해 안전한 32바이트 세션 키로 도출
            session_key = utils.derive_key(shared_secret)
            kem_end_time = time.perf_counter()
            utils.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
            utils.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")

            # =========================================================
            # [단계 2] 전송할 파일의 초기 메타데이터 전송
            # =========================================================
            filename = os.path.basename(file_path)
            filename_bytes = filename.encode("utf-8")
            filesize = os.path.getsize(file_path)

            utils.log("INFO", "FILE", f"선택된 파일: {filename}")
            utils.log("INFO", "FILE", f"파일 크기: {filesize} 바이트")

            # 파일명, 파일 크기를 차례대로 서버에 전송 (해시는 아직 계산 안됨)
            utils.send_with_length(s, filename_bytes)
            s.sendall(struct.pack("!Q", filesize))

            utils.log("INFO", "FILE", "초기 파일 메타데이터 전송 완료")

            # =========================================================
            # [단계 3] 대칭키 암호화(AES-GCM) 기반 대용량 파일 전송 및 해시 계산
            # =========================================================
            aesgcm = AESGCM(session_key)
            use_compression = True
            chunk_index = 0
            sent_size = 0
            
            # 스트리밍 해시 계산을 위한 초기화
            import hashlib
            file_hasher = hashlib.sha256()

            utils.log("INFO", "CHUNK", f"청크 크기: {utils.CHUNK_SIZE} 바이트")
            utils.log("INFO", "CHUNK", "청크 전송 시작")

            transfer_start_time = time.perf_counter()

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(utils.CHUNK_SIZE)
                    if not chunk:
                        break

                    original_chunk_size = len(chunk)
                    
                    # 실시간 해시 업데이트
                    file_hasher.update(chunk)
                    
                    flags = 0x01 if use_compression else 0x00

                    if use_compression:
                        chunk = zlib.compress(chunk)

                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    payload = nonce + encrypted_chunk

                    # [청크 헤더 구조: 총 13바이트]
                    s.sendall(struct.pack("!BQI", flags, chunk_index, len(payload)))
                    # [청크 데이터 전송]
                    s.sendall(payload)

                    sent_size += original_chunk_size
                    utils.log("INFO", "CHUNK", f"청크 {chunk_index} 전송 완료 ({sent_size}/{filesize} 바이트)")
                    chunk_index += 1

            transfer_end_time = time.perf_counter()
            file_hash = file_hasher.hexdigest()
            
            utils.log("PASS", "CHUNK", "모든 청크 전송 완료")
            utils.log("RESULT", "TRANSFER", f"파일 데이터 전송 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")
            utils.log("INFO", "HASH", f"최종 파일 SHA-256: {file_hash}")

            # =========================================================
            # [단계 4] 후반 메타데이터 전송 및 전자서명 생성
            # =========================================================
            # 계산된 최종 파일 해시 전송
            s.sendall(file_hash.encode("utf-8"))
            
            # 무결성 검증을 위한 서명 데이터 조합
            metadata_for_sign = (filename + str(filesize) + file_hash).encode("utf-8")

            sign_start_time = time.perf_counter()
            with oqs.Signature(utils.SIG_ALG) as signer:
                sig_public_key = signer.generate_keypair()
                signature = signer.sign(metadata_for_sign)
            sign_end_time = time.perf_counter()

            utils.log("PASS", "SIGN", f"ML-DSA 서명 생성 완료 (소요 시간: {sign_end_time - sign_start_time:.4f} 초)")
            utils.log("INFO", "SIGN", f"서명 공개키 크기: {len(sig_public_key)} 바이트")
            utils.log("INFO", "SIGN", f"서명 크기: {len(signature)} 바이트")

            # 서버가 서명을 검증할 수 있도록 클라이언트가 생성한 서명 검증용 공개키를 전송
            utils.send_with_length(s, sig_public_key)
            utils.log("INFO", "SIGN", "서명 공개키 전송 완료")

            # 생성된 서명 데이터를 전송
            utils.send_with_length(s, signature)
            utils.log("INFO", "SIGN", "서명 전송 완료")

            # =========================================================
            # [단계 5] 마무리 및 종료 신호 전송
            # =========================================================
            utils.show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{filename}")

            utils.send_with_length(s, b"CLIENT_DONE")
            utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")

        except Exception as e:
            utils.log("ERROR", "CLIENT", str(e), exc_info=True)
            utils.show_error("전송 실패", str(e))


if __name__ == "__main__":
    main()
