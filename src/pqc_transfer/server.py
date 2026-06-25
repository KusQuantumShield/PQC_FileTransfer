import os
import socket
import struct
import zlib
import tempfile
import shutil
import hashlib
import time
import threading

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import re

CLIENT_ID_PATTERN = re.compile(r'^[\w-]+$')

from . import utils

# 자동으로 저장될 디렉토리 이름 지정
SAVE_DIR = "received_files"

# 파일 저장 시 이름 충돌 방지를 위한 전역 락
_file_save_lock = threading.Lock()

class PQCServerHandler:
    """
    클라이언트 연결을 1:1로 처리하는 서버 프로토콜 핸들러
    각 단계(핸드셰이크, 파일 수신, 서명 검증 등)를 독립적인 메서드로 분리하여 유지보수성을 높였습니다.
    """
    def __init__(self, conn: socket.socket, addr):
        self.conn = conn
        self.addr = addr
        self.session_key = None
        self.temp_path = None
        self.temp_file = None
        self.filename = None
        self.original_filesize = 0
        self.received_size = 0
        self.file_hasher = hashlib.sha256()

    def handle(self) -> bool:
        """
        단일 클라이언트와의 모든 통신 과정을 순차적으로 관리하는 메인 제어 메서드입니다.
        
        [처리 순서]
        1. 핸드셰이크 (KEM 공개키 송신 및 암호문 수신을 통한 세션 키 교환)
        2. 메타데이터 수신 (파일명 및 크기)
        3. 파일 데이터 청크 수신 (AES-GCM 복호화 및 실시간 압축 해제, 파일 저장)
        4. 서명 및 무결성 검증 (해시 대조 및 PQC 전자서명 검증)
        5. 전송 마무리 (임시 파일을 실제 파일로 이동 및 정리)
        
        Returns:
            bool: 모든 과정이 성공적으로 완료되면 True, 예외가 발생하거나 실패하면 False
        """
        utils.log("INFO", "CONNECT", f"클라이언트가 연결되었습니다: {self.addr}")
        try:
            if not self.perform_handshake(): return False
            if not self.receive_metadata(): return False
            if not self.receive_file_chunks(): return False
            if not self.verify_signature(): return False
            if not self.finalize_transfer(): return False
            return True
        except (ConnectionError, ConnectionResetError, BrokenPipeError) as e:
            utils.log("ERROR", "SERVER", f"클라이언트 연결 끊김: {e}")
            return False
        except Exception as e:
            utils.log("ERROR", "SERVER", str(e), exc_info=True)
            return False
        finally:
            self.cleanup()

    def abort(self, reason: str) -> bool:
        """클라이언트에게 상세한 에러 사유를 전달하고 연결을 안전하게 종료합니다 (Graceful Shutdown)"""
        try:
            utils.send_with_length(self.conn, f"ERROR:{reason}".encode('utf-8'))
            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 5))
            self.conn.shutdown(socket.SHUT_WR)
            self.conn.settimeout(1.0)
            bytes_drained = 0
            while bytes_drained < 1024 * 1024:  # 최대 1MB까지만 버퍼를 비우고 강제 종료
                chunk = self.conn.recv(1024)
                if not chunk:
                    break
                bytes_drained += len(chunk)
        except Exception:
            pass
        return False

    def perform_handshake(self) -> bool:
        """[단계 1] 핸드셰이크: KEM 키 생성 및 교환"""
        kem_start_time = time.perf_counter()
        
        # [보안 수정] 서버 인증 부재를 이유로 정적 KEM 키쌍을 사용하면 KEM의 핵심인 전방향 안전성(Forward Secrecy)이 훼손됩니다.
        # KEM은 일회성(Ephemeral)으로 사용해야 하며, 서버 인증은 서명(Signature)을 통해 이루어져야 합니다.
        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            public_key = kem.generate_keypair()
            utils.log("INFO", "KEM", "ML-KEM 임시(Ephemeral) 키쌍 생성 완료")

            # [보안 추가] 서버의 정적 서명 키를 로드하거나 생성하여 KEM 공개키에 서명 (MitM 완벽 방어)
            server_sig_pk, server_sig_sk = utils.get_server_sig_keys()

            with oqs.Signature(utils.SIG_ALG, secret_key=server_sig_sk) as signer:
                server_signature = signer.sign(public_key)

            # 2. 클라이언트에게 서버의 공개키 및 서명 전송
            utils.send_with_length(self.conn, public_key)
            utils.send_with_length(self.conn, server_sig_pk)
            utils.send_with_length(self.conn, server_signature)
            utils.log("INFO", "SIGN", "임시 KEM 공개키에 서명하여 클라이언트에게 전송 완료 (서버 인증)")

            # 3. 클라이언트로부터 KEM 암호문 수신 (공유 비밀키 도출용)
            kem_ciphertext = utils.recv_with_length(self.conn, max_len=10000)
            
            # [취약점 패치] 수신한 KEM 암호문의 길이가 정확한지 검증하여 Buffer Over-read(메모리 누수 및 크래시) 방지
            if len(kem_ciphertext) != kem.details['length_ciphertext']:
                utils.log("ERROR", "KEM", f"유효하지 않은 KEM 암호문 길이: {len(kem_ciphertext)}")
                return self.abort("유효하지 않은 KEM 암호문 길이 (크래시 방어)")
                
            utils.log("INFO", "KEM", f"암호문 수신 완료 ({len(kem_ciphertext)} 바이트)")

            try:
                # 4. 서버의 비밀키로 암호문을 디캡슐화하여 공유 비밀키 획득
                shared_secret = kem.decap_secret(kem_ciphertext)
                utils.log("PASS", "KEM", "캡슐화 해제 완료")
            except Exception as e:
                utils.log("ERROR", "KEM", f"캡슐화 해제 실패: {e}", exc_info=True)
                return self.abort("KEM 캡슐화 해제 실패 (변조 또는 불일치)")

        utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")
        # 5. HKDF를 이용해 공유 비밀키로부터 AES-GCM 세션 키 도출
        self.session_key = utils.derive_key(shared_secret)
        kem_end_time = time.perf_counter()
        utils.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
        utils.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")
        return True

    def receive_metadata(self) -> bool:
        """
        [단계 2] 전송될 파일의 초기 메타데이터 수신
        
        클라이언트가 전송할 원본 파일의 이름과 총 크기를 수신합니다.
        악의적인 경로 조작 공격(Directory Traversal)을 방지하기 위해 파일명에서
        기본적인 검증(basename 변환, 길이 체크, 특수문자 제한)을 수행합니다.
        """
        # 0. 클라이언트 고유 식별자 수신 (NAT 환경 다중 접속 지원)
        client_id_bytes = utils.recv_with_length(self.conn, max_len=1024)
        self.client_id = client_id_bytes.decode("utf-8")

        # 1. 파일명 수신 (가변 길이 문자열이므로 먼저 길이를 받고 이후 데이터를 받음)
        filename_bytes = utils.recv_with_length(self.conn, max_len=1024)
        raw_filename = filename_bytes.decode("utf-8").replace("\\", "/")
        self.filename = os.path.basename(raw_filename)

        if not self.filename or len(self.filename) > 255 or self.filename in (".", ".."):
            utils.log("FAIL", "FILE", "유효하지 않은 파일명")
            return self.abort("유효하지 않은 파일명")

        self.original_filesize = struct.unpack("!Q", utils.recv_exact(self.conn, 8))[0]
        
        # Zip Bomb 및 디스크 고갈(DoS) 방지를 위해 최대 파일 크기 제한 (예: 10GB)
        MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024 # 10 GB
        if self.original_filesize > MAX_FILE_SIZE:
            utils.log("ERROR", "FILE", f"파일 크기가 서버 제한({MAX_FILE_SIZE} 바이트)을 초과했습니다.")
            return self.abort("파일 크기 제한 초과 (DoS 방어)")
            
        utils.log("INFO", "FILE", f"파일명 수신 완료: {self.filename}")
        utils.log("INFO", "FILE", f"예상 파일 크기: {self.original_filesize} 바이트")
        return True

    def receive_file_chunks(self) -> bool:
        """[단계 3] 대용량 파일 청크(Chunk) 수신 및 복호화"""
        # 수신된 파일을 저장할 기본 디렉토리(received_files)를 생성합니다. (이미 존재하면 무시)
        os.makedirs(SAVE_DIR, exist_ok=True)
        # 임시 파일을 생성하여 수신 중인 데이터를 안전하게 기록합니다. (delete=False로 설정하여 닫아도 삭제되지 않게 함)
        self.temp_file = tempfile.NamedTemporaryFile(dir=SAVE_DIR, delete=False)
        self.temp_path = self.temp_file.name
        utils.log("INFO", "FILE", f"임시 파일 생성됨: {self.temp_path}")

        # 클라이언트와 KEM 핸드셰이크를 통해 도출한 세션 키로 AES-GCM 암복호화 객체를 초기화합니다.
        aesgcm = AESGCM(self.session_key)
        # Zlib 압축 해제를 위한 decompressor 객체를 초기화합니다.
        decompressor = zlib.decompressobj()

        # 한 번에 수신할 수 있는 최대 페이로드 크기를 설정합니다.
        # 압축(zlib) 시 버퍼링되거나 무작위 데이터로 인해 원본 크기보다 커질 수 있으므로 여유롭게 2배로 잡습니다.
        MAX_PAYLOAD_SIZE = utils.CHUNK_SIZE * 2
        # 불필요한 메모리 할당(복사)을 피하기 위해 고정 크기의 bytearray를 버퍼로 사용합니다.
        recv_buffer = bytearray(MAX_PAYLOAD_SIZE)
        # memoryview를 사용하여 버퍼의 특정 부분을 슬라이싱할 때 메모리 복사본이 생성되지 않도록 합니다.
        recv_view = memoryview(recv_buffer)

        expected_chunk_index = 0
        transfer_start_time = time.perf_counter()
        header_struct = struct.Struct("!BQI")
        
        # 최적화: 헤더 수신을 위한 고정 크기 버퍼 사전 할당 (Zero-copy)
        header_buffer = bytearray(13)
        header_view = memoryview(header_buffer)

        while True:
            # 1. 13바이트 고정 길이의 헤더를 수신합니다. (1바이트 플래그, 8바이트 인덱스, 4바이트 페이로드 길이)
            utils.recv_exact_into(self.conn, header_view, 13)
            # 수신한 헤더 바이너리를 파이썬 변수로 언패킹합니다. (플래그 1B, 인덱스 8B, 페이로드 길이 4B)
            flags, chunk_index, payload_len = header_struct.unpack_from(header_buffer, 0)

            # 공격자가 청크 순서를 조작하거나 누락시키는 재전송(Replay)/순서 조작 공격을 방지하기 위한 검증입니다.
            if chunk_index != expected_chunk_index:
                utils.log("ERROR", "CHUNK", f"청크 인덱스 불일치: 예상됨={expected_chunk_index}, 수신됨={chunk_index}")
                return self.abort(f"청크 인덱스 불일치")

            # 수신할 페이로드 길이가 유효한 범위를 벗어나는지 확인하여 버퍼 오버플로우 공격을 방지합니다.
            if payload_len <= 0 or payload_len > MAX_PAYLOAD_SIZE:
                utils.log("ERROR", "CHUNK", "유효하지 않은 페이로드 길이")
                return self.abort(f"유효하지 않은 페이로드 길이")

            # 계산된 페이로드 길이만큼 정확히 데이터를 수신하여 recv_view 버퍼에 바로 채워 넣습니다.
            utils.recv_exact_into(self.conn, recv_view, payload_len)
            
            # 페이로드 분리: 앞의 12바이트는 AES-GCM 복호화에 필요한 Nonce(난수), 나머지는 실제 암호화된 데이터입니다.
            # 최적화: bytes() 복사를 제거하고 memoryview를 그대로 전달 (Zero-copy)
            nonce = recv_view[:12]
            encrypted_chunk = recv_view[12:payload_len]

            try:
                # AES-GCM을 사용하여 복호화 및 무결성 검증을 동시에 수행합니다.
                # header 전체를 Associated Data(AAD)로 사용하여, 누군가 헤더 정보(예: 인덱스나 플래그)를 변조하면 복호화가 실패하도록 합니다.
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, associated_data=header_buffer)
            except Exception as e:
                utils.log("ERROR", "CHUNK", f"인덱스 {chunk_index}에서 청크 복호화 실패(무결성 훼손 가능성): {e}")
                return self.abort("청크 무결성 검증 실패 (데이터 변조 또는 키 불일치)")

            # flags & 0x01: 압축(Compression) 비트가 켜져 있는지 비트 연산으로 확인합니다.
            if flags & 0x01:
                try:
                    # 복호화된 데이터를 Zlib으로 압축 해제합니다.
                    # 악의적으로 엄청난 압축률을 가진 작은 파일을 보내 서버 메모리를 고갈시키는 'Zip Bomb(압축 폭탄)' 공격을
                    # 방지하기 위해 최대 해제 크기(max_length)를 청크 크기의 2배로 엄격히 제한합니다.
                    decrypted_chunk = decompressor.decompress(decrypted_chunk, max_length=utils.CHUNK_SIZE * 2)
                    if decompressor.unconsumed_tail:
                        utils.log("ERROR", "COMPRESS", "Zip Bomb 공격 감지: 허용된 압축 해제 크기 초과")
                        return self.abort("압축 해제 크기 제한 초과 (Zip Bomb 공격 감지)")
                except Exception as e:
                    utils.log("ERROR", "COMPRESS", f"청크 {chunk_index} 압축 해제 실패: {e}")
                    return self.abort("데이터 압축 해제 실패 (데이터 손상 의심)")

            # 안전하게 복호화 및 압축 해제된 순수 원본 데이터를 임시 파일에 기록합니다.
            # 스트리밍 압축 시 zlib.decompress가 데이터를 버퍼링하여 빈 문자열을 반환할 수 있으므로 압축 사용 시에는 허용합니다.
            if len(decrypted_chunk) == 0 and not (flags & 0x02) and not (flags & 0x01):
                utils.log("ERROR", "CHUNK", "의미 없는 0바이트 청크 수신 (무한 루프 DoS 방어)")
                return self.abort("비정상적인 0바이트 청크 데이터")
                
            self.temp_file.write(decrypted_chunk)
            
            # 파일 전체의 무결성을 최종 검증하기 위해 복호화된 원본 데이터를 SHA-256 해시 함수에 업데이트합니다.
            self.file_hasher.update(decrypted_chunk)
            # 전체 진행률을 추적하기 위해 수신된 바이트 수를 누적합니다.
            self.received_size += len(decrypted_chunk)
            if self.received_size > self.original_filesize:
                utils.log("ERROR", "FILE", "수신된 데이터가 선언된 파일 크기를 초과했습니다 (DoS 방어)")
                return self.abort("수신 파일 크기 초과")

            utils.log("INFO", "CHUNK", f"청크 {chunk_index} 수신 완료 ({self.received_size}/{self.original_filesize} 바이트)")
            expected_chunk_index += 1

            # flags & 0x02: EOF(End of File) 비트가 켜져 있으면, 파일의 마지막 청크임을 의미하므로 루프를 종료합니다.
            if flags & 0x02:
                utils.log("INFO", "CHUNK", "모든 청크 데이터 수신 완료 (EOF 플래그 감지)")
                break

        transfer_end_time = time.perf_counter()
        self.temp_file.close()
        utils.log("PASS", "CHUNK", f"모든 청크 수신 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")
        return True

    def verify_signature(self) -> bool:
        """
        [단계 4 & 5] 후반 메타데이터(해시) 수신 및 서명/무결성 검증
        
        파일 청크 수신 과정에서 계산한 스트리밍 SHA-256 해시와 클라이언트가 보낸 최종 해시를 비교합니다.
        또한, '파일명|수신크기|파일해시' 문자열을 조합하여 PQC 전자서명(예: ML-DSA)을 검증함으로써,
        데이터가 중간에 변조되지 않았음(무결성)과 송신자가 올바름(인증)을 암호학적으로 증명합니다.
        """
        expected_hash = utils.recv_exact(self.conn, 64).decode("utf-8")
        utils.log("INFO", "HASH", f"클라이언트가 전송한 원본 SHA-256: {expected_hash}")

        # Replay 공격(재전송 공격) 방지를 위한 1회용 Challenge Nonce 생성 및 전송
        challenge_nonce = os.urandom(32).hex()
        utils.send_with_length(self.conn, challenge_nonce.encode("utf-8"))
        utils.log("INFO", "VERIFY", "Replay 방지용 Challenge Nonce 전송 완료")

        sig_public_key = utils.recv_with_length(self.conn, max_len=20000)
        
        # [취약점 패치 및 최적화] 서명 객체를 한 번만 초기화하여 불필요한 메모리 할당 및 해제 방지
        with oqs.Signature(utils.SIG_ALG) as verifier:
            expected_sig_pk_len = verifier.details['length_public_key']
            expected_sig_len = verifier.details['length_signature']
            
            if len(sig_public_key) != expected_sig_pk_len:
                utils.log("ERROR", "SIGN", f"유효하지 않은 서명 공개키 길이: {len(sig_public_key)}")
                return self.abort("유효하지 않은 서명 공개키 길이 (크래시 방어)")
                
            utils.log("INFO", "SIGN", f"서명 공개키 수신 완료 ({len(sig_public_key)} 바이트)")

            # TOFU(Trust On First Use) 기반 최초 접속 공개키 신뢰 및 검증
            # 보안 패치: 디렉토리 순회 공격 방지를 위해 client_id 검증 (알파벳, 숫자, 하이픈, 언더스코어만 허용)
            if not CLIENT_ID_PATTERN.match(self.client_id):
                utils.log("FAIL", "VERIFY", "유효하지 않은 클라이언트 ID 포맷입니다.")
                return self.abort("유효하지 않은 클라이언트 ID 포맷")
            
            if not utils.verify_and_trust_client(self.client_id, sig_public_key):
                utils.log("FAIL", "VERIFY", "등록되지 않은 송신자의 공개키입니다 (MitM 또는 공격 의심)")
                return self.abort("송신자 인증 실패 (MitM 공격 방어)")

            signature = utils.recv_with_length(self.conn, max_len=20000)
            
            # [취약점 패치] 수신한 서명 데이터의 길이가 정확한지 검증 (Buffer Over-read 크래시 방지)
            if len(signature) != expected_sig_len:
                utils.log("ERROR", "SIGN", f"유효하지 않은 서명 길이: {len(signature)}")
                return self.abort("유효하지 않은 서명 길이 (크래시 방어)")
                
            utils.log("INFO", "SIGN", f"서명 수신 완료 ({len(signature)} 바이트)")

            utils.log("PASS", "FILE", "파일 크기 동적 동기화 성공")

            received_hash = self.file_hasher.hexdigest()
            
            if self.received_size != self.original_filesize:
                utils.log("FAIL", "FILE", f"파일 크기 불일치: 선언됨={self.original_filesize}, 수신됨={self.received_size}")
                return self.abort("불완전한 파일 전송 (크기 불일치)")
                
            if received_hash != expected_hash:
                utils.log("FAIL", "HASH", "파일 해시 불일치")
                utils.log("INFO", "HASH", f"예상됨: {expected_hash}, 계산됨: {received_hash}")
                utils.log("FAIL", "VERIFY", "파일 무결성 검증 실패")
                return self.abort("파일 무결성 검증 실패 (해시 불일치)")
                
            utils.log("PASS", "HASH", "파일 해시 검증 성공")
            utils.log("INFO", "HASH", f"계산된 SHA-256: {received_hash}")

            # 무결성 검증을 위한 서명 데이터 조합 (MitM 세션 바인딩 및 Replay 방지 난수 포함)
            # [보안 수정] 서명 데이터에 송신자의 고유 식별자(client_id)를 포함시켜 Identity Misbinding(릴레이 공격) 방어
            session_key_hash = utils.hash_ss(self.session_key)
            metadata_for_verify = f"{self.client_id}|{self.filename}|{self.received_size}|{received_hash}|{session_key_hash}|{challenge_nonce}".encode("utf-8")

            try:
                sign_verify_start_time = time.perf_counter()
                # 양자 내성 암호(PQC) 기반 전자서명(예: ML-DSA) 알고리즘으로 서명 검증 수행
                is_valid = verifier.verify(metadata_for_verify, signature, sig_public_key)
                sign_verify_end_time = time.perf_counter()

                if not is_valid:
                    utils.log("FAIL", "SIGN", "서명 검증 실패")
                    utils.log("FAIL", "VERIFY", "송신자 인증 실패")
                    return self.abort("전자서명 검증 실패 (파일 변조 또는 위장 의심)")

                utils.log("PASS", "SIGN", f"서명 검증 성공 (소요 시간: {sign_verify_end_time - sign_verify_start_time:.4f} 초)")
                utils.log("PASS", "VERIFY", "송신자 인증 성공")
            except Exception as e:
                utils.log("ERROR", "SIGN", f"서명 검증 오류: {e}", exc_info=True)
                return self.abort("전자서명 검증 처리 중 예기치 않은 오류 발생")

        utils.log("PASS", "VERIFY", "파일 무결성: 통과")
        utils.log("PASS", "VERIFY", "송신자 인증: 통과")
        return True

    def finalize_transfer(self) -> bool:
        """
        [단계 6] 클라이언트 종료 신호 대기 및 파일 자동 저장
        
        클라이언트로부터 'CLIENT_DONE' 신호를 수신한 후, 
        안전하게 임시 파일(.tmp)을 실제 저장 경로(received_files 폴더)로 이동합니다.
        이름이 겹칠 경우 (1), (2) 등 숫자를 붙여 파일 덮어쓰기를 방지합니다.
        """
        client_signal = utils.recv_with_length(self.conn, max_len=1000)
        if client_signal != b"CLIENT_DONE":
            utils.log("ERROR", "TRANSFER", f"예상치 못한 클라이언트 신호: {client_signal}")
            return self.abort("정상적인 종료 신호(CLIENT_DONE)를 수신하지 못했습니다")

        utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 수신 완료")

        target_dir = SAVE_DIR
        base_name, ext = os.path.splitext(self.filename)
        
        if not self.temp_file.closed:
            self.temp_file.close()

        # 전역 락을 사용하여 파일 이름 중복 확인과 예약(선점)만 수행하여 임계 구역(Critical Section) 최소화
        with _file_save_lock:
            save_path = os.path.join(target_dir, self.filename)
            counter = 1
            while os.path.exists(save_path):
                save_path = os.path.join(target_dir, f"{base_name}({counter}){ext}")
                counter += 1
            # 빈 파일을 즉시 생성하여 다른 클라이언트 스레드가 동일한 이름을 가져가지 못하도록 예약(선점)합니다.
            open(save_path, 'a').close()
            
        # [최적화] 파일 이동(Move)은 파일 시스템에 따라 오래 걸릴 수 있으므로 락을 해제한 상태에서 병렬 처리합니다.
        # 파일 이동 전에 열려있는 파일 핸들을 명시적으로 닫아줍니다 (Windows OS 등에서 PermissionError 발생 방지)
        if hasattr(self, 'temp_file') and self.temp_file and not self.temp_file.closed:
            self.temp_file.close()
            
        shutil.move(self.temp_path, save_path)
        self.temp_path = None

        utils.log("RESULT", "TRANSFER", f"파일이 자동으로 저장됨: {save_path}")
        try:
            utils.send_with_length(self.conn, b"SERVER_OK")
        except Exception:
            pass
        return True

    def cleanup(self):
        """
        소켓 연결을 종료하고, 파일 전송이 비정상적으로 종료되었을 경우
        남아있는 임시 파일을 안전하게 삭제하여 디스크 용량 누수를 방지합니다.
        """
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        
        # [취약점 패치] 임시 파일의 파일 디스크립터를 명시적으로 닫아 FD 고갈 및 Windows PermissionError 방지
        if hasattr(self, 'temp_file') and self.temp_file and not self.temp_file.closed:
            try:
                self.temp_file.close()
            except Exception:
                pass

        if self.temp_path and os.path.exists(self.temp_path):
            try:
                os.remove(self.temp_path)
                utils.log("INFO", "FILE", "임시 파일이 삭제되었습니다")
            except Exception as e:
                utils.log("ERROR", "FILE", f"임시 파일 삭제 실패: {e}")
                
        try:
            if self.conn:
                self.conn.close()
                utils.log("INFO", "CONNECT", "연결이 종료되었습니다")
        except Exception:
            pass


def main():
    """
    서버 프로그램의 진입점(Entry Point)입니다.
    소켓을 열어 포트를 바인딩하고 클라이언트의 연결을 대기합니다.
    연결이 수립되면 독립적인 핸들러(PQCServerHandler)를 백그라운드 스레드에서 실행하여 다중 클라이언트를 동시 처리합니다.
    """
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 서버 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    from concurrent.futures import ThreadPoolExecutor

    # 최대 동시 접속자 수를 제한하여 스레드 폭발(Thread Exhaustion) DoS 공격 방어
    MAX_CONCURRENT_CLIENTS = 100
    connection_semaphore = threading.Semaphore(MAX_CONCURRENT_CLIENTS)
    
    # [서버 최적화] 매 연결마다 스레드를 생성하는 오버헤드를 없애기 위해 스레드 풀 적용
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CLIENTS)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        s.bind((utils.HOST, utils.PORT))
        s.listen(10)  # 다중 접속을 위해 백로그 증가
        
        utils.log("INFO", "SYSTEM", f"PQC 보안 서버 데몬이 시작되었습니다 (최대 동시 접속: {MAX_CONCURRENT_CLIENTS}명)")
        utils.log("INFO", "CONNECT", f"{utils.PORT} 포트에서 수신 대기 중")

        while True:
            try:
                conn, addr = s.accept()
                
                # 동시 접속자 수 제한 검사
                if not connection_semaphore.acquire(blocking=False):
                    utils.log("ERROR", "SYSTEM", f"최대 동시 접속자 수({MAX_CONCURRENT_CLIENTS})를 초과했습니다. 연결을 거부합니다: {addr}")
                    conn.close()
                    continue
                
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
                conn.settimeout(15.0)
                
                handler = PQCServerHandler(conn, addr)
                
                def handle_client(h):
                    try:
                        if h.handle():
                            utils.log("RESULT", "TRANSFER", "파일 전송이 완료되었습니다")
                    finally:
                        connection_semaphore.release()
                
                executor.submit(handle_client, handler)
            except KeyboardInterrupt:
                utils.log("INFO", "SYSTEM", "서버를 종료합니다.")
                executor.shutdown(wait=False)
                break
            except Exception as e:
                utils.log("ERROR", "SYSTEM", f"서버 수신 오류: {e}")

if __name__ == "__main__":
    main()
