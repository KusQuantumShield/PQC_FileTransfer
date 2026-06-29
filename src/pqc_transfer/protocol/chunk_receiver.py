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
from ..utils import logger, connection

class ChunkReceiver:
    def __init__(self, conn: connection.SecureConnection, session_key: bytes, file_hasher: typing.Any, chunk_size: int = 4 * 1024 * 1024) -> None:
        self.conn = conn
        self.aesgcm = AESGCM(session_key)
        self.file_hasher = file_hasher
        self.chunk_size = chunk_size
        
        self.decompressor = zlib.decompressobj()
        self.max_payload_size = self.chunk_size * 2
        self.recv_buffer = bytearray(self.max_payload_size)
        self.recv_view = memoryview(self.recv_buffer)
        
        self.header_struct = struct.Struct(constants.HEADER_FORMAT)
        self.header_buffer = bytearray(constants.HEADER_SIZE)
        self.header_view = memoryview(self.header_buffer)

    def receive(self, original_filesize: int, save_dir: str) -> tuple[str, int]:
        os.makedirs(save_dir, exist_ok=True)
        temp_file = tempfile.NamedTemporaryFile(dir=save_dir, delete=False)
        temp_path = temp_file.name
        logger.log("INFO", "FILE", f"임시 파일 생성됨: {temp_path}")

        expected_chunk_index = 0
        received_size = 0
        transfer_start_time = time.perf_counter()

        try:
            while True:
                self.conn.recv_exact_into(self.header_view, constants.HEADER_SIZE)
                flags, chunk_index, payload_len = self.header_struct.unpack_from(self.header_buffer, 0)

                if chunk_index != expected_chunk_index:
                    raise exceptions.PQCProtocolError("청크 인덱스 불일치")
                if payload_len <= 0 or payload_len > self.max_payload_size:
                    raise exceptions.PQCProtocolError("유효하지 않은 페이로드 길이")

                self.conn.recv_exact_into(self.recv_view, payload_len)
                
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
