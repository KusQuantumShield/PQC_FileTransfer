import os
import socket
import struct
import zlib
import time

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from pqc_transfer import utils

def test_misssign_test():
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 클라이언트 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    file_path = os.path.join(os.path.dirname(__file__), '../test.txt')

    if not file_path:
        utils.log("INFO", "FILE", "사용자가 파일 선택을 취소했습니다")
        return

    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            f.write("This is a dummy test file for testing.")

    # TCP IPv4 소켓 생성
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 빠른 전송을 위해 Nagle 알고리즘 비활성화
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # 대용량 파일 전송을 위해 송수신 소켓 버퍼 크기 증가 (4MB)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        
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
            _ = utils.recv_with_length(s, max_len=20000)
            _ = utils.recv_with_length(s, max_len=20000)
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
            client_id = "test_script_id2"
            utils.send_with_length(s, client_id.encode("utf-8"))

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
            
            # 압축 효율이 떨어지는 포맷은 zlib 생략
            uncompressible_exts = {'.zip', '.rar', '.7z', '.gz', '.mp4', '.avi', '.mkv', '.jpg', '.jpeg', '.png', '.pdf', '.gif', '.webp'}
            ext = os.path.splitext(filename)[1].lower()
            use_compression = ext not in uncompressible_exts
            
            if not use_compression:
                utils.log("INFO", "COMPRESS", f"'{ext}' 파일은 이미 압축/암호화되어 있어 Zlib 스트리밍 압축을 생략합니다.")
                
            chunk_index = 0
            sent_size = 0
            
            # 2. Zlib 스트리밍 압축을 위한 상태 유지 객체 생성
            compressor = zlib.compressobj(level=1) if use_compression else None

            # 스트리밍 해시 계산을 위한 초기화
            import hashlib
            file_hasher = hashlib.sha256()

            utils.log("INFO", "CHUNK", f"청크 크기: {utils.CHUNK_SIZE} 바이트")
            utils.log("INFO", "CHUNK", "청크 전송 시작")

            transfer_start_time = time.perf_counter()

            # AES-GCM Nonce (12바이트)를 매번 생성하지 않고, 
            # 8바이트의 순차적인 인덱스와 4바이트의 고정 난수를 결합하여 속도를 높임
            base_nonce_suffix = os.urandom(4)

            # 불필요한 메모리 할당(Copy)을 막기 위해 고정된 bytearray 버퍼에 데이터를 읽어옴 (Zero-copy)
            buffer = bytearray(utils.CHUNK_SIZE)
            with open(file_path, "rb") as f:
                while True:
                    bytes_read = f.readinto(buffer)
                    if bytes_read == 0:
                        # 3. 파일 끝에 도달 -> Z_FINISH 처리 및 명시적 EOF(0x02) 플래그를 담은 마지막 빈 청크 전송
                        flags = 0x03 if use_compression else 0x02 # 0x01 (압축) | 0x02 (EOF)
                        chunk_data = compressor.flush(zlib.Z_FINISH) if use_compression else b""
                        
                        nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                        temp_payload_len = len(nonce) + len(chunk_data) + 16
                        header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                        
                        # 취약점 패치: 평문 헤더(header)를 AEAD의 인증 데이터(AAD)로 결합하여 헤더 변조를 즉시 차단
                        encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                        # 페이로드 길이를 다시 계산 (암호문 길이에만 영향을 미치므로)
                        payload_len = len(nonce) + len(encrypted_chunk)
                        
                        # 헤더를 최종 길이로 다시 패킹
                        header = struct.pack("!BQI", flags, chunk_index, payload_len)
                        
                        s.sendall(header + nonce)
                        s.sendall(encrypted_chunk)
                        break
                        
                    # 파일에서 읽은 크기만큼만 memoryview로 잘라서 참조
                    chunk_view = memoryview(buffer)[:bytes_read]
                    
                    # 실시간 해시 업데이트
                    file_hasher.update(chunk_view)
                    
                    # 일반 데이터 청크 전송 (압축 포함, Z_FINISH 생략)
                    flags = 0x01 if use_compression else 0x00
                    if use_compression:
                        chunk_data = compressor.compress(chunk_view) + compressor.flush(zlib.Z_SYNC_FLUSH)
                    else:
                        chunk_data = chunk_view

                    nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                    # [청크 헤더 구조: 총 13바이트]
                    # 취약점 패치: 헤더를 인증 데이터(AAD)로 사용하기 위해 임시 길이로 먼저 패킹
                    temp_payload_len = len(nonce) + len(chunk_data) + 16 # tag(16)
                    header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                    
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                    payload_len = len(nonce) + len(encrypted_chunk)

                    # 실제 payload_len으로 헤더 최종 확정
                    header = struct.pack("!BQI", flags, chunk_index, payload_len)
                    
                    # 메모리 복사 방지를 위해 헤더+Nonce와 대용량 암호문을 분리하여 전송
                    # TCP_NODELAY가 활성화되어 있으므로 분리 전송해도 지연 없이 빠르게 전송됨
                    s.sendall(header + nonce)
                    s.sendall(encrypted_chunk)
                    
                    sent_size += bytes_read

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
            
            # 서버로부터 Replay 방지용 Challenge Nonce 수신
            challenge_nonce = utils.recv_with_length(s).decode("utf-8")
            if challenge_nonce.startswith("ERROR:"):
                raise ValueError(f"서버 거부: {challenge_nonce[6:]}")
            
            # 무결성 검증을 위한 서명 데이터 조합 (Canonicalization 취약점 방지를 위해 구분자 사용)
            session_key_hash = utils.hash_ss(session_key)
            metadata_for_sign = f"{client_id}|{filename}|{sent_size}|{file_hash}|{session_key_hash}|{challenge_nonce}".encode("utf-8")

            sign_start_time = time.perf_counter()
            key_dir = os.path.expanduser("~/.pqc_transfer_keys")
            os.makedirs(key_dir, exist_ok=True)
            sig_sec_file = os.path.join(key_dir, "client_sig_sec.bin")
            sig_pub_file = os.path.join(key_dir, "client_sig_pub.bin")
            if os.path.exists(sig_sec_file) and os.path.exists(sig_pub_file):
                with open(sig_sec_file, "rb") as f:
                    secret_key = f.read()
                with open(sig_pub_file, "rb") as f:
                    sig_public_key = f.read()
                with oqs.Signature(utils.SIG_ALG, secret_key=secret_key) as signer:
                    signature = signer.sign(metadata_for_sign)
            else:
                with oqs.Signature(utils.SIG_ALG) as signer:
                    sig_public_key = signer.generate_keypair()
                    signature = signer.sign(metadata_for_sign)
                    secret_key = signer.export_secret_key()
                import stat
                fd = os.open(sig_sec_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
                with os.fdopen(fd, "wb") as f:
                    f.write(secret_key)
                with open(sig_pub_file, "wb") as f:
                    f.write(sig_public_key)
            sign_end_time = time.perf_counter()

            utils.log("PASS", "SIGN", f"ML-DSA 서명 생성 완료 (소요 시간: {sign_end_time - sign_start_time:.4f} 초)")
            utils.log("INFO", "SIGN", f"서명 공개키 크기: {len(sig_public_key)} 바이트")
            utils.log("INFO", "SIGN", f"서명 크기: {len(signature)} 바이트")

            # === 테스트 시나리오: Signature 변조 ===
            utils.log("WARN", "TEST", "유효하지 않은 ML-DSA 서명 시뮬레이션")
            signature = bytearray(signature)
            signature[0] = (signature[0] + 1) % 256
            signature = bytes(signature)
            # ======================================

            # 서버가 서명을 검증할 수 있도록 클라이언트가 생성한 서명 검증용 공개키를 전송
            utils.send_with_length(s, sig_public_key)
            utils.log("INFO", "SIGN", "서명 공개키 전송 완료")

            # 생성된 서명 데이터를 전송
            utils.send_with_length(s, signature)
            utils.log("INFO", "SIGN", "서명 전송 완료")

            # =========================================================
            # [단계 5] 마무리 및 종료 신호 전송
            # =========================================================
            utils.send_with_length(s, b"CLIENT_DONE")
            utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")

            # 서버의 최종 응답 수신
            response = utils.recv_with_length(s).decode("utf-8")
            if response.startswith("ERROR:"):
                utils.log("ERROR", "SERVER", f"서버 거부: {response[6:]}")
                utils.show_error("서버 거부", f"서버 거부: {response[6:]}")
            elif response == "SERVER_OK":
                utils.log("PASS", "TRANSFER", "서버가 정상적으로 수신을 완료했습니다")
                utils.show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{filename}")
                assert False, "취약점 발견: 서버가 변조된 서명을 정상으로 판정했습니다!"

        except ConnectionRefusedError:
            utils.log("ERROR", "TEST", "서버에 연결할 수 없습니다. 테스트를 진행하려면 먼저 서버를 실행하세요.")
            sys.exit(1)
        except (ConnectionResetError, BrokenPipeError, ConnectionError):
            try:
                s.settimeout(1.0)
                err_bytes = utils.recv_with_length(s)
                err_msg = err_bytes.decode("utf-8")
                if err_msg.startswith("ERROR:"):
                    utils.log("ERROR", "CLIENT", f"서버가 통신을 차단했습니다: {err_msg[6:]}")
                    utils.show_error("서버 거부", f"서버에서 보안 검증 실패로 통신을 차단했습니다.\n\n사유: {err_msg[6:]}")
                    return
            except Exception:
                pass
            utils.log("INFO", "TRANSFER", "서버가 연결을 종료했습니다 (정상적인 방어 동작)")
            utils.show_info("방어 성공", "서버가 연결을 종료했습니다 (정상적인 방어 동작)")

        except Exception as e:
            utils.log("ERROR", "CLIENT", str(e), exc_info=True)
            utils.show_error("전송 실패", str(e))
            sys.exit(1)


if __name__ == "__main__":
    test_misssign_test()
