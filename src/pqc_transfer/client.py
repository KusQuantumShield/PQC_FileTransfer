import os
import socket
import struct
import zlib
import time
import hashlib
import sys

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import utils

class PQCClient:
    """
    서버와 파일 송수신을 담당하는 클라이언트 클래스
    """
    def __init__(self, file_path: str):
        """
        PQCClient 객체 생성 및 파일 정보 초기화
        
        Args:
            file_path (str): 전송할 파일의 절대 경로 또는 상대 경로
            
        초기화되는 주요 속성:
            - filename: 전송할 파일의 이름 (경로 제외)
            - filesize: 파일의 총 크기 (바이트 단위)
            - session_key: 서버와 교환하여 생성된 대칭키 (AES-GCM 암호화에 사용)
            - file_hasher: 전송할 원본 데이터의 실시간 무결성 검증을 위한 SHA-256 객체
        """
        self.file_path = file_path
        self.filename = os.path.basename(file_path)
        self.filesize = os.path.getsize(file_path)
        self.socket = None
        self.session_key = None
        self.file_hasher = hashlib.sha256()
        self.sent_size = 0
        self.file_hash = None

    def transfer(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self.socket = s
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            
            try:
                self.socket.connect((utils.SERVER_IP, utils.PORT))
                utils.log("INFO", "CONNECT", f"서버 {utils.SERVER_IP}:{utils.PORT}에 연결되었습니다")

                self.perform_handshake()
                self.send_metadata()
                self.transfer_file_chunks()
                self.create_and_send_signature()
                self.finalize_transfer()

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
                utils.log("ERROR", "CLIENT", "서버와의 연결이 끊어졌습니다. (서버 측 무결성/인증 검증 실패로 인한 통신 차단)")
                utils.show_error("전송 실패", "서버와의 연결이 끊어졌습니다.\n\n서버 측 보안 검증(무결성/송신자 인증) 실패로 인해 통신이 차단되었을 수 있습니다.")
            except Exception as e:
                utils.log("ERROR", "CLIENT", str(e), exc_info=True)
                utils.show_error("전송 실패", str(e))

    def perform_handshake(self):
        """
        서버와의 초기 KEM(Key Encapsulation Mechanism) 핸드셰이크를 수행합니다.
        
        [동작 과정]
        1. 서버로부터 양자 내성 암호(PQC) 기반의 공개키를 수신합니다.
        2. 수신한 공개키를 사용하여 공유 비밀키(shared_secret)와 암호문(ciphertext)을 생성합니다.
        3. 암호문을 서버로 전송하여, 서버도 동일한 공유 비밀키를 획득할 수 있도록 합니다.
        4. HKDF를 이용해 공유 비밀키에서 안전한 세션 키(session_key)를 도출합니다.
        """
        kem_start_time = time.perf_counter()
        
        # 1. 서버에서 전송한 공개키 길이 수신 (4바이트 정수형)
        pk_len_bytes = utils.recv_exact(self.socket, 4)
        pk_len = struct.unpack("!I", pk_len_bytes)[0]
        
        if pk_len <= 0 or pk_len > 10000:
            utils.log("FAIL", "KEM", f"유효하지 않은 공개키 길이: {pk_len}")
            raise ValueError("Invalid public key length")

        # 2. 서버의 KEM(키 캡슐화 메커니즘) 공개키 수신
        public_key = utils.recv_exact(self.socket, pk_len)
        utils.log("INFO", "KEM", f"서버 공개키를 수신했습니다 ({len(public_key)} 바이트)")

        # 3. 양자 내성 암호(PQC) 기반 KEM을 사용하여 공유 비밀키(shared_secret)와 암호문(kem_ciphertext) 생성
        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        utils.log("PASS", "KEM", "캡슐화 완료")
        utils.log("INFO", "KEY", f"공유 비밀키 해시: {utils.hash_ss(shared_secret)}")

        utils.send_with_length(self.socket, kem_ciphertext)
        utils.log("INFO", "KEM", f"암호문 전송 완료 ({len(kem_ciphertext)} 바이트)")

        # 5. HKDF(HMAC-based Extract-and-Expand Key Derivation Function)를 사용하여 공유 비밀키에서 세션 키 도출
        self.session_key = utils.derive_key(shared_secret)
        kem_end_time = time.perf_counter()
        utils.log("PASS", "KEY", "HKDF로 세션 키 도출 완료")
        utils.log("PASS", "KEM", f"핸드셰이크 완료 (소요 시간: {kem_end_time - kem_start_time:.4f} 초)")

    def send_metadata(self):
        """
        파일 전송 전, 파일 이름과 파일 크기(메타데이터)를 서버로 전송합니다.
        
        이 정보는 서버가 수신할 파일의 예상 크기와 저장할 파일명을 결정하는 데 사용됩니다.
        """
        utils.log("INFO", "FILE", f"선택된 파일: {self.filename}")
        utils.log("INFO", "FILE", f"파일 크기: {self.filesize} 바이트")

        # 파일명을 UTF-8로 인코딩하여 전송합니다.
        filename_bytes = self.filename.encode("utf-8")
        utils.send_with_length(self.socket, filename_bytes)
        
        # 파일 크기(8바이트 부호 없는 정수)를 패킹하여 서버로 전송합니다.
        self.socket.sendall(struct.pack("!Q", self.filesize))

        utils.log("INFO", "FILE", "초기 파일 메타데이터 전송 완료")

    def transfer_file_chunks(self):
        """
        대용량 파일을 안전하게 전송하기 위해 CHUNK_SIZE 단위로 나누어 전송합니다.
        
        [보안 및 전송 최적화 기법]
        - AES-GCM 알고리즘을 사용하여 데이터의 기밀성과 무결성(AEAD)을 동시에 보장합니다.
        - 이미 압축된 파일 포맷(예: zip, mp4 등)은 zlib 압축을 생략하여 CPU 자원 낭비를 방지합니다.
        - Zero-copy 기법(memoryview 및 bytearray)을 활용하여 대용량 파일 전송 시 메모리 효율을 극대화합니다.
        - 파일 전송과 동시에 SHA-256 해시를 계산하여(스트리밍 해시), 모든 전송 완료 시 파일 전체의 해시를 획득합니다.
        """
        # 세션 키를 이용해 AES-GCM 암호화 객체를 초기화합니다.
        aesgcm = AESGCM(self.session_key)
        
        # 압축할 필요가 없는(이미 압축된) 확장자 목록을 정의합니다.
        uncompressible_exts = {'.zip', '.rar', '.7z', '.gz', '.mp4', '.avi', '.mkv', '.jpg', '.jpeg', '.png', '.pdf', '.gif', '.webp'}
        ext = os.path.splitext(self.filename)[1].lower()
        use_compression = ext not in uncompressible_exts
        
        if not use_compression:
            utils.log("INFO", "COMPRESS", f"'{ext}' 파일은 이미 압축/암호화되어 있어 Zlib 스트리밍 압축을 생략합니다.")
            
        chunk_index = 0
        # 스트리밍 압축을 위해 압축 객체를 초기화합니다. (압축 레벨 1로 속도 우선)
        compressor = zlib.compressobj(level=1) if use_compression else None

        utils.log("INFO", "CHUNK", f"청크 크기: {utils.CHUNK_SIZE} 바이트")
        utils.log("INFO", "CHUNK", "청크 전송 시작")

        transfer_start_time = time.perf_counter()
        # 모든 청크에서 공통으로 사용할 4바이트 난수 접미사를 생성합니다.
        base_nonce_suffix = os.urandom(4)

        # 불필요한 메모리 복사를 방지하기 위해 고정 크기(CHUNK_SIZE)의 바이트 배열을 생성합니다.
        buffer = bytearray(utils.CHUNK_SIZE)
        with open(self.file_path, "rb") as f:
            while True:
                # 버퍼(buffer) 크기만큼 파일에서 데이터를 읽어옵니다. (readinto 활용으로 zero-copy)
                bytes_read = f.readinto(buffer)
                
                # 파일의 끝(EOF)에 도달한 경우 (읽은 바이트가 0일 때)
                if bytes_read == 0:
                    # 플래그: 0x01(압축) 또는 0x00(비압축) 상태에 0x02(EOF) 비트를 더해 마지막 패킷임을 명시합니다.
                    flags = 0x03 if use_compression else 0x02
                    # Zlib의 버퍼에 남아있는 모든 데이터를 밀어내어(flush) 암호화할 마지막 조각을 만듭니다.
                    chunk_data = compressor.flush(zlib.Z_FINISH) if use_compression else b""
                    
                    # Nonce 구성: 8바이트 순차 청크 인덱스 + 4바이트 고정 난수 접미사 = 총 12바이트
                    nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                    # AES-GCM 인증 태그 크기(16바이트)를 포함하여 임시 페이로드 길이 계산
                    temp_payload_len = len(nonce) + len(chunk_data) + 16
                    # Associated Data(AAD)로 사용하기 위한 13바이트 헤더 조립 (플래그 1B + 인덱스 8B + 길이 4B)
                    header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                    
                    # 데이터를 AES-GCM으로 암호화합니다. 헤더를 AAD로 제공하여 헤더 변조도 감지할 수 있게 합니다.
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                    # 실제 암호문 생성 후, Nonce 길이를 포함하여 최종 페이로드 길이를 계산합니다.
                    payload_len = len(nonce) + len(encrypted_chunk)
                    # 최종 계산된 페이로드 길이로 헤더를 다시 구성합니다.
                    header = struct.pack("!BQI", flags, chunk_index, payload_len)
                    
                    # 헤더, Nonce, 암호화된 청크 데이터를 순차적으로 소켓을 통해 전송합니다.
                    self.socket.sendall(header + nonce)
                    self.socket.sendall(encrypted_chunk)
                    break # 마지막 청크 전송을 마치고 무한 루프 종료
                    
                # 버퍼 전체가 아닌 실제로 읽은 바이트만큼만 잘라내는 memoryview (메모리 복사 없음)
                chunk_view = memoryview(buffer)[:bytes_read]
                # 실시간으로 원본 데이터에 대한 SHA-256 해시 업데이트
                self.file_hasher.update(chunk_view)
                
                # 압축 여부에 따라 플래그 설정 및 압축 수행
                flags = 0x01 if use_compression else 0x00
                if use_compression:
                    chunk_data = compressor.compress(chunk_view) + compressor.flush(zlib.Z_SYNC_FLUSH)
                else:
                    chunk_data = chunk_view

                # Nonce 구성 (인덱스 + 접미사)
                nonce = struct.pack("!Q", chunk_index) + base_nonce_suffix
                # 헤더 구성을 위한 임시 페이로드 길이 계산
                temp_payload_len = len(nonce) + len(chunk_data) + 16
                header = struct.pack("!BQI", flags, chunk_index, temp_payload_len)
                
                # 데이터 암호화 (무결성 및 기밀성 확보)
                encrypted_chunk = aesgcm.encrypt(nonce, chunk_data, associated_data=header)
                # 최종 페이로드 길이 도출 및 헤더 재구성
                payload_len = len(nonce) + len(encrypted_chunk)
                header = struct.pack("!BQI", flags, chunk_index, payload_len)
                
                # 네트워크로 전송
                self.socket.sendall(header + nonce)
                self.socket.sendall(encrypted_chunk)
                
                # 전체 진행 상황을 누적 집계하여 출력
                self.sent_size += bytes_read
                utils.log("INFO", "CHUNK", f"청크 {chunk_index} 전송 완료 ({self.sent_size}/{self.filesize} 바이트)")
                chunk_index += 1

        transfer_end_time = time.perf_counter()
        self.file_hash = self.file_hasher.hexdigest()
        
        utils.log("PASS", "CHUNK", "모든 청크 전송 완료")
        utils.log("RESULT", "TRANSFER", f"파일 데이터 전송 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")
        utils.log("INFO", "HASH", f"최종 파일 SHA-256: {self.file_hash}")

    def create_and_send_signature(self):
        """
        전송된 파일 데이터의 최종 해시값을 전송하고, PQC 전자서명을 생성하여 서버에 송신합니다.
        
        이 서명은 파일 메타데이터(파일명, 전송된 크기, 최종 해시값)에 대해 ML-DSA 등의 
        양자 내성 서명 알고리즘을 적용하여 송신자의 신원을 증명하고 데이터의 위변조를 방지합니다.
        """
        # 1. 계산된 파일 원본의 전체 해시값 전송
        self.socket.sendall(self.file_hash.encode("utf-8"))
        
        # 서버로부터 Replay 방지용 Challenge Nonce 수신
        challenge_nonce = utils.recv_with_length(self.socket).decode("utf-8")
        if challenge_nonce.startswith("ERROR:"):
            raise ValueError(f"서버 거부: {challenge_nonce[6:]}")
        utils.log("INFO", "SIGN", "서버로부터 Replay 방지용 Challenge Nonce 수신 완료")
        
        # 2. 서명할 메타데이터 구성: 파일명|수신크기|해시값|세션키해시|챌린지논스
        session_key_hash = utils.hash_ss(self.session_key)
        metadata_for_sign = f"{self.filename}|{self.sent_size}|{self.file_hash}|{session_key_hash}|{challenge_nonce}".encode("utf-8")

        sign_start_time = time.perf_counter()
        sig_sec_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "client_sig_sec.bin"))
        sig_pub_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "client_sig_pub.bin"))
        
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
                
            # [보안 패치] 개인키 파일은 소유자만 읽고 쓸 수 있도록(0o600) 안전하게 생성
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

        utils.send_with_length(self.socket, sig_public_key)
        utils.log("INFO", "SIGN", "서명 공개키 전송 완료")

        utils.send_with_length(self.socket, signature)
        utils.log("INFO", "SIGN", "서명 전송 완료")

    def finalize_transfer(self):
        """
        [단계 6] 전송 완료 및 종료 처리
        
        서버에게 전송이 모두 완료되었음을 알리는 'CLIENT_DONE' 신호를 전송하고,
        서버의 최종 수신 확인 응답을 대기한 뒤, 사용자에게 결과를 표시합니다.
        """
        utils.send_with_length(self.socket, b"CLIENT_DONE")
        utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 전송 완료")
        
        response = utils.recv_with_length(self.socket).decode("utf-8")
        if response.startswith("ERROR:"):
            raise ValueError(f"서버 거부: {response[6:]}")
        elif response == "SERVER_OK":
            utils.log("PASS", "TRANSFER", "서버가 정상적으로 수신을 완료했습니다")
            utils.show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{self.filename}")


def main():
    """
    클라이언트 프로그램의 진입점(Entry Point)입니다.
    초기 설정을 로깅하고, 사용자로부터 전송할 파일을 선택받아 PQCClient 인스턴스를 실행합니다.
    """
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 클라이언트 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = utils.select_file()

    if not file_path:
        utils.log("INFO", "FILE", "사용자가 파일 선택을 취소했습니다")
        return

    if not os.path.isfile(file_path):
        utils.log("ERROR", "FILE", f"파일을 찾을 수 없거나 디렉토리입니다: {file_path}")
        utils.show_error("파일 오류", f"유효한 파일이 아닙니다.\n\n{file_path}")
        return

    client = PQCClient(file_path)
    client.transfer()

if __name__ == "__main__":
    main()
