import os
import struct
import zlib
import time
import tempfile
import socket
import typing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import constants
from .. import exceptions
from ..utils import config, logger, network

class ChunkSender:
    def __init__(self, sock: socket.socket, session_key: bytes, file_hasher: typing.Any) -> None:
        self.sock = sock
        self.aesgcm = AESGCM(session_key)
        self.file_hasher = file_hasher
        
        self.header_struct = struct.Struct(constants.HEADER_FORMAT)
        self.nonce_struct = struct.Struct(constants.NONCE_PREFIX_FORMAT)
        self.header_buffer = bytearray(constants.HEADER_SIZE)
        self.header_view = memoryview(self.header_buffer)
        
        self.nonce_buffer = bytearray(constants.NONCE_SIZE)
        self.base_nonce_suffix = os.urandom(constants.NONCE_SUFFIX_SIZE)
        self.nonce_buffer[constants.NONCE_PREFIX_SIZE:constants.NONCE_SIZE] = self.base_nonce_suffix
        self.nonce_view = memoryview(self.nonce_buffer)

    def _should_compress(self, filename: str) -> bool:
        uncompressible_exts = {'.zip', '.rar', '.7z', '.gz', '.mp4', '.avi', '.mkv', '.jpg', '.jpeg', '.png', '.pdf', '.gif', '.webp'}
        ext = os.path.splitext(filename)[1].lower()
        use_compression = ext not in uncompressible_exts
        if not use_compression:
            logger.log("INFO", "COMPRESS", f"'{ext}' 파일은 이미 압축/암호화되어 있어 Zlib 스트리밍 압축을 생략합니다.")
        return use_compression

    def send(self, file_path: str, filename: str, filesize: int) -> tuple[int, str]:
        use_compression = self._should_compress(filename)
        compressor = zlib.compressobj(level=1, wbits=15, memLevel=9) if use_compression else None
        
        buffer = bytearray(config.CHUNK_SIZE)
        buffer_view = memoryview(buffer)
        
        chunk_index = 0
        sent_size = 0
        
        logger.log("INFO", "CHUNK", f"청크 크기: {config.CHUNK_SIZE} 바이트")
        logger.log("INFO", "CHUNK", "청크 전송 시작")
        transfer_start_time = time.perf_counter()

        with open(file_path, "rb") as f:
            while True:
                bytes_read = f.readinto(buffer)
                if sent_size + bytes_read > filesize:
                    bytes_read = filesize - sent_size

                if bytes_read == 0:
                    flags = constants.FLAG_COMPRESSED | constants.FLAG_EOF if use_compression else constants.FLAG_EOF
                    chunk_data = compressor.flush(zlib.Z_FINISH) if use_compression else b""
                    self._send_chunk(chunk_index, flags, chunk_data)
                    break
                    
                chunk_view = buffer_view[:bytes_read]
                self.file_hasher.update(chunk_view)
                
                flags = constants.FLAG_COMPRESSED if use_compression else 0x00
                chunk_data = compressor.compress(chunk_view) if use_compression else chunk_view

                if len(chunk_data) == 0:
                    sent_size += bytes_read
                    continue

                self._send_chunk(chunk_index, flags, chunk_data)
                
                sent_size += bytes_read
                logger.log("INFO", "CHUNK", f"청크 {chunk_index} 전송 완료 ({sent_size}/{filesize} 바이트)")
                chunk_index += 1

        transfer_end_time = time.perf_counter()
        file_hash = self.file_hasher.hexdigest()
        
        logger.log("PASS", "CHUNK", "모든 청크 전송 완료")
        logger.log("RESULT", "TRANSFER", f"파일 데이터 전송 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")
        logger.log("INFO", "HASH", f"최종 파일 SHA-256: {file_hash}")
        
        return sent_size, file_hash

    def _send_chunk(self, chunk_index: int, flags: int, chunk_data: bytes):
        self.nonce_struct.pack_into(self.nonce_buffer, 0, chunk_index)
        payload_len = constants.NONCE_SIZE + len(chunk_data) + constants.AES_TAG_SIZE
        self.header_struct.pack_into(self.header_buffer, 0, flags, chunk_index, payload_len)
        
        encrypted_chunk = self.aesgcm.encrypt(self.nonce_view, chunk_data, associated_data=self.header_view)
        self.sock.sendall(self.header_buffer + self.nonce_buffer + encrypted_chunk)


class ChunkReceiver:
    def __init__(self, conn: socket.socket, session_key: bytes, file_hasher: typing.Any) -> None:
        self.conn = conn
        self.aesgcm = AESGCM(session_key)
        self.file_hasher = file_hasher
        
        self.decompressor = zlib.decompressobj()
        self.max_payload_size = config.CHUNK_SIZE * 2
        self.recv_buffer = bytearray(self.max_payload_size)
        self.recv_view = memoryview(self.recv_buffer)
        
        self.header_struct = struct.Struct(constants.HEADER_FORMAT)
        self.header_buffer = bytearray(constants.HEADER_SIZE)
        self.header_view = memoryview(self.header_buffer)

    def receive(self, original_filesize: int) -> tuple[str, int]:
        save_dir = config.SAVE_DIR
        os.makedirs(save_dir, exist_ok=True)
        temp_file = tempfile.NamedTemporaryFile(dir=save_dir, delete=False)
        temp_path = temp_file.name
        logger.log("INFO", "FILE", f"임시 파일 생성됨: {temp_path}")

        expected_chunk_index = 0
        received_size = 0
        transfer_start_time = time.perf_counter()

        try:
            while True:
                network.recv_exact_into(self.conn, self.header_view, constants.HEADER_SIZE)
                flags, chunk_index, payload_len = self.header_struct.unpack_from(self.header_buffer, 0)

                if chunk_index != expected_chunk_index:
                    raise exceptions.PQCProtocolError("청크 인덱스 불일치")
                if payload_len <= 0 or payload_len > self.max_payload_size:
                    raise exceptions.PQCProtocolError("유효하지 않은 페이로드 길이")

                network.recv_exact_into(self.conn, self.recv_view, payload_len)
                
                nonce = self.recv_view[:constants.NONCE_SIZE]
                encrypted_chunk = self.recv_view[constants.NONCE_SIZE:payload_len]

                try:
                    decrypted_chunk = self.aesgcm.decrypt(nonce, encrypted_chunk, associated_data=self.header_buffer)
                except Exception:
                    raise exceptions.PQCIntegrityError("청크 무결성 검증 실패 (데이터 변조 또는 키 불일치)")

                if flags & constants.FLAG_COMPRESSED:
                    try:
                        decrypted_chunk = self.decompressor.decompress(decrypted_chunk, max_length=self.max_payload_size)
                        if self.decompressor.unconsumed_tail:
                            raise exceptions.PQCSecurityError("압축 해제 크기 제한 초과 (Zip Bomb 공격 감지)")
                    except Exception as e:
                        if "Zip Bomb" in str(e):
                            raise
                        raise exceptions.PQCIntegrityError("데이터 압축 해제 실패 (데이터 손상 의심)")

                if len(decrypted_chunk) == 0 and not (flags & constants.FLAG_EOF) and not (flags & constants.FLAG_COMPRESSED):
                    raise exceptions.PQCProtocolError("비정상적인 0바이트 청크 데이터")
                    
                temp_file.write(decrypted_chunk)
                self.file_hasher.update(decrypted_chunk)
                
                received_size += len(decrypted_chunk)
                if received_size > original_filesize:
                    raise exceptions.PQCSecurityError("수신 파일 크기 초과")

                logger.log("INFO", "CHUNK", f"청크 {chunk_index} 수신 완료 ({received_size}/{original_filesize} 바이트)")
                expected_chunk_index += 1

                if flags & constants.FLAG_EOF:
                    logger.log("INFO", "CHUNK", "모든 청크 데이터 수신 완료 (EOF 플래그 감지)")
                    break

            transfer_end_time = time.perf_counter()
            logger.log("PASS", "CHUNK", f"모든 청크 수신 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)")
            
        finally:
            temp_file.close()
            
        return temp_path, received_size


