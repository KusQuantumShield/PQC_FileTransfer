import os
import struct
import zlib
import time
import socket
import typing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import constants
from ..utils import logger, connection

class ChunkSender:
    def __init__(self, conn: connection.SecureConnection, session_key: bytes, file_hasher: typing.Any, chunk_size: int = 4 * 1024 * 1024) -> None:
        self.conn = conn
        self.aesgcm = AESGCM(session_key)
        self.file_hasher = file_hasher
        self.chunk_size = chunk_size
        
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
        
        buffer = bytearray(self.chunk_size)
        buffer_view = memoryview(buffer)
        
        chunk_index = 0
        sent_size = 0
        
        logger.log("INFO", "CHUNK", f"청크 크기: {self.chunk_size} 바이트")
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
        self.conn.sock.sendall(self.header_buffer + self.nonce_buffer + encrypted_chunk)
