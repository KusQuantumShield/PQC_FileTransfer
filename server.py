import os
import socket
import struct
import zlib
import tempfile
import shutil
import hashlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import utils

# 자동으로 저장될 디렉토리 이름 지정
SAVE_DIR = "received_files"

def handle_client(conn: socket.socket, addr) -> bool:
    """
    클라이언트가 접속했을 때 호출되어 1:1 통신 및 파일 수신을 처리하는 핸들러 함수입니다.
    보안 교환, 메타데이터 수신, 무결성 검증 등을 모두 담당합니다.
    """
    utils.log("INFO", "CONNECT", f"클라이언트가 연결되었습니다: {addr}")
    temp_path = None # 임시로 저장할 파일의 시스템 경로

    try:
        # =========================================================
        # [단계 1] 핸드셰이크: KEM 키 생성 및 교환
        # =========================================================
        import time
        kem_start_time = time.perf_counter()
        
        # 서버 측에서 먼저 일회용 양자 내성 공개키/개인키 쌍을 생성
        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            public_key = kem.generate_keypair()
            utils.log("INFO", "KEM", "ML-KEM 키쌍 생성 완료")

            # 생성된 공개키를 클라이언트에게 전송
            utils.send_with_length(conn, public_key)
            utils.log("INFO", "KEM", f"공개키 전송 완료 ({len(public_key)} 바이트)")

            # 클라이언트는 서버의 공개키로 무작위 비밀키를 캡슐화(암호화)하여 반환
            kem_ciphertext = utils.recv_with_length(conn)
            utils.log("INFO", "KEM", f"암호문 수신 완료 ({len(kem_ciphertext)} 바이트)")

            try:
                # 수신한 암호문을 서버의 개인키로 캡슐화 해제(Decapsulate)하여 클라이언트가 생성한 비밀키를 복원
                shared_secret = kem.decap_secret(kem_ciphertext)
                utils.log("PASS", "KEM", "캡슐화 해제 완료")
            except Exception as e:
                utils.log("ERROR", "KEM", f"캡슐화 해제 실패: {e}", exc_info=True)
                return False

        utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")

        # 교환된 공유 비밀키를 HKDF를 통해 32바이트 세션 키로 변환
        session_key = utils.derive_key(shared_secret)
        kem_end_time = time.perf_counter()
        utils.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
        utils.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")

        # =========================================================
        # [단계 2] 전송될 파일의 초기 메타데이터 수신
        # =========================================================
        # 파일명 수신 (디렉토리 탐색 공격, Path Traversal 공격을 막기 위해 os.path.basename 사용)
        filename_bytes = utils.recv_with_length(conn)
        filename = os.path.basename(filename_bytes.decode("utf-8"))

        if not filename:
            utils.log("FAIL", "FILE", "유효하지 않은 파일명")
            raise ValueError("Invalid filename")

        # 파일 크기 수신 (8바이트 고정 길이, Unsigned long long)
        original_filesize = struct.unpack("!Q", utils.recv_exact(conn, 8))[0]

        utils.log("INFO", "FILE", f"파일명 수신 완료: {filename}")
        utils.log("INFO", "FILE", f"예상 파일 크기: {original_filesize} 바이트")

        # =========================================================
        # [단계 3] 대용량 파일 청크(Chunk) 수신 및 복호화
        # =========================================================
        # 저장 디렉토리가 없으면 생성 (임시 파일도 이곳에 저장하기 위함)
        if not os.path.exists(SAVE_DIR):
            os.makedirs(SAVE_DIR)
            utils.log("INFO", "SYSTEM", f"디렉토리 생성됨: {SAVE_DIR}")

        # 네트워크 전송 중에는 메모리에 올리지 않고 임시 파일(Temp file)에 바로 기록
        # /tmp 파티션 용량 부족을 막고, 빠른 이동(shutil.move)을 위해 SAVE_DIR 내부에 생성
        temp_file = tempfile.NamedTemporaryFile(dir=SAVE_DIR, delete=False)
        temp_path = temp_file.name

        utils.log("INFO", "FILE", f"임시 파일 생성됨: {temp_path}")

        # 세션 키를 이용해 AES-GCM 복호화 객체 초기화
        aesgcm = AESGCM(session_key)
        # 스트리밍 방식으로 수신된 데이터의 해시를 실시간 계산하기 위한 객체 초기화
        file_hasher = hashlib.sha256()

        received_size = 0         # 현재까지 온전하게 복호화되어 기록된 바이트 수
        expected_chunk_index = 0  # 예상되는 다음 청크의 번호 (순서가 뒤바뀌는지 검증)

        transfer_start_time = time.perf_counter()

        while received_size < original_filesize:
            # 1. 13바이트 고정 크기의 청크 헤더 수신
            header = utils.recv_exact(conn, 13)
            flags, chunk_index, payload_len = struct.unpack("!BQI", header)

            # 청크 순서가 맞는지 엄격하게 검증 (네트워크 패킷 섞임 방지)
            if chunk_index != expected_chunk_index:
                utils.log(
                    "ERROR",
                    "CHUNK",
                    f"청크 인덱스 불일치: 예상됨={expected_chunk_index}, 수신됨={chunk_index}"
                )
                raise ValueError(f"Chunk index mismatch (expected={expected_chunk_index}, got={chunk_index})")

            if payload_len <= 0:
                utils.log("ERROR", "CHUNK", "유효하지 않은 페이로드 길이")
                raise ValueError("Invalid payload length")

            # 2. 파악된 페이로드 길이만큼 데이터(Nonce + 암호문) 수신
            payload = utils.recv_exact(conn, payload_len)

            # 페이로드 분리: 처음 12바이트는 암호화 시 사용된 Nonce(IV), 나머지는 실제 암호문 데이터
            nonce = payload[:12]
            encrypted_chunk = payload[12:]

            # 3. AES-GCM을 사용하여 청크 데이터 복호화 
            try:
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
            except Exception as e:
                utils.log("ERROR", "CHUNK", f"인덱스 {chunk_index}에서 청크 복호화 실패: {e}", exc_info=True)
                return False

            # 4. 클라이언트가 압축을 적용(flags 0x01)한 경우 zlib로 다시 압축을 품
            if flags & 0x01:
                try:
                    decrypted_chunk = zlib.decompress(decrypted_chunk)
                except Exception as e:
                    utils.log("ERROR", "CHUNK", f"인덱스 {chunk_index}에서 청크 압축 해제 실패: {e}", exc_info=True)
                    return False

            # 5. 복호화 및 압축 해제가 완료된 평문 데이터를 임시 파일에 기록
            temp_file.write(decrypted_chunk)

            # 6. 추후 무결성 검증을 위해 해시(SHA-256) 업데이트
            file_hasher.update(decrypted_chunk)
            received_size += len(decrypted_chunk)

            utils.log("INFO", "CHUNK", f"청크 {chunk_index} 수신 완료 ({received_size}/{original_filesize} 바이트)")
            expected_chunk_index += 1

        transfer_end_time = time.perf_counter()
        temp_file.close() # 쓰기가 완료되었으므로 임시 파일 스트림을 닫음
        utils.log("PASS", "CHUNK", f"모든 청크 수신 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")

        # =========================================================
        # [단계 4] 후반 메타데이터(해시) 및 클라이언트 서명 수신
        # =========================================================
        
        # 원본 파일의 예상 해시 수신 (64바이트 문자열)
        expected_hash = utils.recv_exact(conn, 64).decode("utf-8")
        utils.log("INFO", "HASH", f"클라이언트가 전송한 원본 SHA-256: {expected_hash}")

        # 클라이언트가 서명 생성 시 사용한 공개키 수신
        sig_public_key = utils.recv_with_length(conn)
        utils.log("INFO", "SIGN", f"서명 공개키 수신 완료 ({len(sig_public_key)} 바이트)")

        # 실제 서명 데이터 수신
        signature = utils.recv_with_length(conn)
        utils.log("INFO", "SIGN", f"서명 수신 완료 ({len(signature)} 바이트)")

        # =========================================================
        # [단계 5] 파일 무결성 및 서명 검증
        # =========================================================
        # 5-1. 사이즈 검증
        if received_size != original_filesize:
            utils.log("FAIL", "FILE", "파일 크기 불일치")
            utils.log("INFO", "FILE", f"예상됨: {original_filesize}, 수신됨: {received_size}")
            return False

        utils.log("PASS", "FILE", "파일 크기 검증 성공")

        # 5-2. 해시 검증
        received_hash = file_hasher.hexdigest()
        if received_hash != expected_hash:
            utils.log("FAIL", "HASH", "파일 해시 불일치")
            utils.log("INFO", "HASH", f"예상됨: {expected_hash}, 계산됨: {received_hash}")
            utils.log("FAIL", "VERIFY", "파일 무결성 검증 실패")
            return False
            
        utils.log("PASS", "HASH", "파일 해시 검증 성공")
        utils.log("INFO", "HASH", f"계산된 SHA-256: {received_hash}")

        # 5-3. 클라이언트 서명 검증
        metadata_for_verify = (filename + str(original_filesize) + received_hash).encode("utf-8")

        try:
            sign_verify_start_time = time.perf_counter()
            with oqs.Signature(utils.SIG_ALG) as verifier:
                is_valid = verifier.verify(metadata_for_verify, signature, sig_public_key)
            sign_verify_end_time = time.perf_counter()

            if not is_valid:
                utils.log("FAIL", "SIGN", "서명 검증 실패")
                utils.log("FAIL", "VERIFY", "송신자 인증 실패")
                return False

            utils.log("PASS", "SIGN", f"서명 검증 성공 (소요 시간: {sign_verify_end_time - sign_verify_start_time:.4f} 초)")
            utils.log("PASS", "VERIFY", "송신자 인증 성공")

        except Exception as e:
            utils.log("ERROR", "SIGN", f"서명 검증 오류: {e}", exc_info=True)
            return False

        utils.log("PASS", "VERIFY", "파일 무결성: 통과")
        utils.log("PASS", "VERIFY", "송신자 인증: 통과")

        # =========================================================
        # [단계 6] 클라이언트 종료 신호 대기 및 파일 자동 저장
        # =========================================================
        client_signal = utils.recv_with_length(conn)
        if client_signal != b"CLIENT_DONE":
            utils.log("ERROR", "TRANSFER", f"예상치 못한 클라이언트 신호: {client_signal}")
            return False

        utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 수신 완료")

        # 최종 저장 경로 조합 후 임시 파일 이동
        save_path = os.path.join(SAVE_DIR, filename)
        shutil.move(temp_path, save_path)
        temp_path = None # 성공적으로 이동했으므로 temp_path 해제

        utils.log("RESULT", "TRANSFER", f"파일이 자동으로 저장됨: {save_path}")

        return True

    except Exception as e:
        utils.log("ERROR", "SERVER", str(e), exc_info=True)
        return False

    finally:
        # 정상/비정상 여부와 관계없이 소켓 자원 반환
        conn.close()
        utils.log("INFO", "CONNECT", "연결이 종료되었습니다")
        
        # 오류가 발생하여 파일이 저장(이동)되지 못하고 임시 폴더에 남은 찌꺼기 파일이 있다면 삭제
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
            utils.log("INFO", "FILE", "임시 파일이 삭제되었습니다")

def main():
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 서버 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    # 서버 소켓 초기화
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 개발 및 빈번한 재시작 중 "Address already in use" 에러를 방지하기 위해 주소/포트 즉시 재사용 옵션 적용
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((utils.HOST, utils.PORT))
        s.listen(1) # 한 번에 1개의 클라이언트 접속만 대기 큐에 허용
        
        utils.log("INFO", "SYSTEM", f"PQC 보안 서버 데몬이 시작되었습니다")
        utils.log("INFO", "CONNECT", f"{utils.PORT} 포트에서 수신 대기 중")

        # 서버는 수동으로 종료(Ctrl+C)할 때까지 계속해서 새로운 클라이언트의 연결을 기다리는 무한 루프를 돎
        while True:
            utils.log("INFO", "CONNECT", "연결 대기 중")
            conn, addr = s.accept() # 클라이언트가 접속할 때까지 블로킹 상태로 대기
            
            # 접속한 클라이언트를 처리하는 메인 핸들러 호출
            if handle_client(conn, addr):
                utils.log("RESULT", "TRANSFER", "파일 전송이 완료되었습니다")

if __name__ == "__main__":
    main()

