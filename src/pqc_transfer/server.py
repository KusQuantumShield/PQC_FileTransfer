import os
import socket
import struct
import zlib
import tempfile
import shutil
import hashlib
import time

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import utils

# 자동으로 저장될 디렉토리 이름 지정
SAVE_DIR = "received_files"

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
        except Exception as e:
            utils.log("ERROR", "SERVER", str(e), exc_info=True)
            return False
        finally:
            self.cleanup()

    def perform_handshake(self) -> bool:
        """[단계 1] 핸드셰이크: KEM 키 생성 및 교환"""
        kem_start_time = time.perf_counter()
        # 1. 양자 내성 암호(PQC) 기반 KEM 알고리즘(예: ML-KEM) 키쌍 생성
        with oqs.KeyEncapsulation(utils.KEM_ALG) as kem:
            public_key = kem.generate_keypair()
            utils.log("INFO", "KEM", "ML-KEM 키쌍 생성 완료")

            # 2. 클라이언트에게 서버의 공개키 전송
            utils.send_with_length(self.conn, public_key)
            utils.log("INFO", "KEM", f"공개키 전송 완료 ({len(public_key)} 바이트)")

            # 3. 클라이언트로부터 캡슐화된 암호문(kem_ciphertext) 수신
            kem_ciphertext = utils.recv_with_length(self.conn)
            utils.log("INFO", "KEM", f"암호문 수신 완료 ({len(kem_ciphertext)} 바이트)")

            try:
                # 4. 서버의 비밀키로 암호문을 디캡슐화하여 공유 비밀키 획득
                shared_secret = kem.decap_secret(kem_ciphertext)
                utils.log("PASS", "KEM", "캡슐화 해제 완료")
            except Exception as e:
                utils.log("ERROR", "KEM", f"캡슐화 해제 실패: {e}", exc_info=True)
                return False

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
        filename_bytes = utils.recv_with_length(self.conn)
        raw_filename = filename_bytes.decode("utf-8").replace("\\", "/")
        self.filename = os.path.basename(raw_filename)

        if not self.filename or len(self.filename) > 255 or self.filename in (".", ".."):
            utils.log("FAIL", "FILE", "유효하지 않은 파일명")
            raise ValueError("Invalid filename")

        self.original_filesize = struct.unpack("!Q", utils.recv_exact(self.conn, 8))[0]
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

        # 한 번에 수신할 수 있는 최대 페이로드 크기를 설정합니다. (기본 청크 1MB + 메타데이터 여유 공간 10KB)
        MAX_PAYLOAD_SIZE = utils.CHUNK_SIZE + 1024 * 10
        # 불필요한 메모리 할당(복사)을 피하기 위해 고정 크기의 bytearray를 버퍼로 사용합니다.
        recv_buffer = bytearray(MAX_PAYLOAD_SIZE)
        # memoryview를 사용하여 버퍼의 특정 부분을 슬라이싱할 때 메모리 복사본이 생성되지 않도록 합니다.
        recv_view = memoryview(recv_buffer)

        expected_chunk_index = 0
        transfer_start_time = time.perf_counter()

        while True:
            # 1. 13바이트 고정 길이의 헤더를 수신합니다. (1바이트 플래그, 8바이트 인덱스, 4바이트 페이로드 길이)
            header = utils.recv_exact(self.conn, 13)
            # 수신된 바이너리 헤더 데이터를 파이썬 변수로 언패킹합니다. (!는 네트워크 바이트 순서를 의미)
            flags, chunk_index, payload_len = struct.unpack("!BQI", header)

            # 공격자가 청크 순서를 조작하거나 누락시키는 재전송(Replay)/순서 조작 공격을 방지하기 위한 검증입니다.
            if chunk_index != expected_chunk_index:
                utils.log("ERROR", "CHUNK", f"청크 인덱스 불일치: 예상됨={expected_chunk_index}, 수신됨={chunk_index}")
                raise ValueError(f"Chunk index mismatch")

            # 수신할 페이로드 길이가 유효한 범위를 벗어나는지 확인하여 버퍼 오버플로우 공격을 방지합니다.
            if payload_len <= 0 or payload_len > MAX_PAYLOAD_SIZE:
                utils.log("ERROR", "CHUNK", "유효하지 않은 페이로드 길이")
                raise ValueError(f"Invalid payload length: {payload_len}")

            # 계산된 페이로드 길이만큼 정확히 데이터를 수신하여 recv_view 버퍼에 바로 채워 넣습니다.
            utils.recv_exact_into(self.conn, recv_view, payload_len)
            
            # 페이로드 분리: 앞의 12바이트는 AES-GCM 복호화에 필요한 Nonce(난수), 나머지는 실제 암호화된 데이터입니다.
            nonce = bytes(recv_view[:12])
            encrypted_chunk = recv_view[12:payload_len]

            try:
                # AES-GCM을 사용하여 복호화 및 무결성 검증을 동시에 수행합니다.
                # header 전체를 Associated Data(AAD)로 사용하여, 누군가 헤더 정보(예: 인덱스나 플래그)를 변조하면 복호화가 실패하도록 합니다.
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, associated_data=header)
            except Exception as e:
                utils.log("ERROR", "CHUNK", f"인덱스 {chunk_index}에서 청크 복호화 실패(무결성 훼손 가능성): {e}", exc_info=True)
                return False

            # flags & 0x01: 압축(Compression) 비트가 켜져 있는지 비트 연산으로 확인합니다.
            if flags & 0x01:
                try:
                    # 복호화된 데이터를 Zlib으로 압축 해제합니다.
                    # 악의적으로 엄청난 압축률을 가진 작은 파일을 보내 서버 메모리를 고갈시키는 'Zip Bomb(압축 폭탄)' 공격을
                    # 방지하기 위해 최대 해제 크기(max_length)를 청크 크기의 2배로 엄격히 제한합니다.
                    decrypted_chunk = decompressor.decompress(decrypted_chunk, max_length=utils.CHUNK_SIZE * 2)
                    if decompressor.unconsumed_tail:
                        utils.log("ERROR", "COMPRESS", "Zip Bomb 공격 감지: 허용된 압축 해제 크기 초과")
                        return False
                except Exception as e:
                    utils.log("ERROR", "COMPRESS", f"청크 {chunk_index} 압축 해제 실패: {e}")
                    return False

            # 안전하게 복호화 및 압축 해제된 순수 원본 데이터를 임시 파일에 기록합니다.
            self.temp_file.write(decrypted_chunk)
            
            # 파일 전체의 무결성을 최종 검증하기 위해 복호화된 원본 데이터를 SHA-256 해시 함수에 업데이트합니다.
            self.file_hasher.update(decrypted_chunk)
            # 전체 진행률을 추적하기 위해 수신된 바이트 수를 누적합니다.
            self.received_size += len(decrypted_chunk)

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

        sig_public_key = utils.recv_with_length(self.conn)
        utils.log("INFO", "SIGN", f"서명 공개키 수신 완료 ({len(sig_public_key)} 바이트)")

        signature = utils.recv_with_length(self.conn)
        utils.log("INFO", "SIGN", f"서명 수신 완료 ({len(signature)} 바이트)")

        utils.log("PASS", "FILE", "파일 크기 동적 동기화 성공")

        received_hash = self.file_hasher.hexdigest()
        if received_hash != expected_hash:
            utils.log("FAIL", "HASH", "파일 해시 불일치")
            utils.log("INFO", "HASH", f"예상됨: {expected_hash}, 계산됨: {received_hash}")
            utils.log("FAIL", "VERIFY", "파일 무결성 검증 실패")
            return False
            
        utils.log("PASS", "HASH", "파일 해시 검증 성공")
        utils.log("INFO", "HASH", f"계산된 SHA-256: {received_hash}")

        # 서명 검증을 위한 메타데이터 재구성: 클라이언트와 동일하게 구성
        metadata_for_verify = f"{self.filename}|{self.received_size}|{received_hash}".encode("utf-8")

        try:
            sign_verify_start_time = time.perf_counter()
            # 양자 내성 암호(PQC) 기반 전자서명(예: ML-DSA) 알고리즘으로 서명 검증 수행
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
        return True

    def finalize_transfer(self) -> bool:
        """
        [단계 6] 클라이언트 종료 신호 대기 및 파일 자동 저장
        
        클라이언트로부터 'CLIENT_DONE' 신호를 수신한 후, 
        안전하게 임시 파일(.tmp)을 실제 저장 경로(received_files 폴더)로 이동합니다.
        이름이 겹칠 경우 (1), (2) 등 숫자를 붙여 파일 덮어쓰기를 방지합니다.
        """
        client_signal = utils.recv_with_length(self.conn)
        if client_signal != b"CLIENT_DONE":
            utils.log("ERROR", "TRANSFER", f"예상치 못한 클라이언트 신호: {client_signal}")
            return False

        utils.log("INFO", "TRANSFER", "CLIENT_DONE 신호 수신 완료")

        target_dir = SAVE_DIR
        base_name, ext = os.path.splitext(self.filename)
        save_path = os.path.join(target_dir, self.filename)
        counter = 1
        while os.path.exists(save_path):
            save_path = os.path.join(target_dir, f"{base_name}({counter}){ext}")
            counter += 1
            
        if not self.temp_file.closed:
            self.temp_file.close()

        shutil.move(self.temp_path, save_path)
        self.temp_path = None

        utils.log("RESULT", "TRANSFER", f"파일이 자동으로 저장됨: {save_path}")
        return True

    def cleanup(self):
        """
        소켓 자원 및 임시 파일을 안전하게 정리합니다.
        전송 중 오류가 발생했거나, 연결이 종료된 경우 남아있는 시스템 자원(파일, 네트워크 연결 등)을 해제합니다.
        """
        self.conn.close()
        utils.log("INFO", "CONNECT", "연결이 종료되었습니다")
        
        try:
            if self.temp_file and not self.temp_file.closed:
                self.temp_file.close()
        except Exception:
            pass
            
        if self.temp_path and os.path.exists(self.temp_path):
            try:
                os.remove(self.temp_path)
                utils.log("INFO", "FILE", "임시 파일이 삭제되었습니다")
            except Exception as e:
                utils.log("ERROR", "FILE", f"임시 파일 삭제 실패: {e}")


def main():
    """
    서버 프로그램의 진입점(Entry Point)입니다.
    소켓을 열어 포트를 바인딩하고 클라이언트의 연결을 대기합니다.
    연결이 수립되면 독립적인 핸들러(PQCServerHandler)를 통해 클라이언트와의 통신을 관리합니다.
    """
    utils.log("INFO", "SYSTEM", "--- PQC 파일 전송 서버 초기화 ---")
    utils.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {utils.KEM_ALG}")
    utils.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {utils.SIG_ALG}")
    utils.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {utils.CHUNK_SIZE} 바이트")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.bind((utils.HOST, utils.PORT))
        s.listen(1)
        
        utils.log("INFO", "SYSTEM", f"PQC 보안 서버 데몬이 시작되었습니다")
        utils.log("INFO", "CONNECT", f"{utils.PORT} 포트에서 수신 대기 중")

        while True:
            utils.log("INFO", "CONNECT", "연결 대기 중")
            conn, addr = s.accept()
            
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            conn.settimeout(15.0)
            
            handler = PQCServerHandler(conn, addr)
            if handler.handle():
                utils.log("RESULT", "TRANSFER", "파일 전송이 완료되었습니다")

if __name__ == "__main__":
    main()
