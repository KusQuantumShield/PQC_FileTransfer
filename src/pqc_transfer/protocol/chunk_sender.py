import os
import struct
import zlib
import time
import typing

from . import constants
from .chunk_base import ChunkProcessorBase
from ..utils import logger, network


class ChunkSender(ChunkProcessorBase):
    """
    파일 데이터를 청크(Chunk) 단위로 분할하여 압축 및 암호화한 뒤 전송하는 클래스입니다.
    """

    def __init__(
        self,
        conn: network.SecureConnection,
        session_key: bytes,
        file_hasher: typing.Any,
        chunk_size: int = 4 * 1024 * 1024,
    ) -> None:
        super().__init__(conn, session_key, file_hasher, chunk_size)

        self.nonce_struct = struct.Struct(constants.NONCE_PREFIX_FORMAT)

        self.nonce_buffer = bytearray(constants.NONCE_SIZE)
        self.base_nonce_suffix = os.urandom(constants.NONCE_SUFFIX_SIZE)
        self.nonce_buffer[constants.NONCE_PREFIX_SIZE : constants.NONCE_SIZE] = (
            self.base_nonce_suffix
        )
        self.nonce_view = memoryview(self.nonce_buffer)

    def _should_compress(self, filename: str) -> bool:
        """
        파일의 확장자를 분석하여 압축 대상인지 여부를 판별합니다.

        이미 압축되었거나 미디어 파일인 경우 압축을 생략하여 CPU 오버헤드를 줄입니다.

        Args:
            filename (str): 검사할 파일의 이름.

        Returns:
            bool: 압축이 필요한 경우 True, 불필요한 경우 False.
        """
        uncompressible_exts = {
            ".zip",
            ".rar",
            ".7z",
            ".gz",
            ".mp4",
            ".avi",
            ".mkv",
            ".jpg",
            ".jpeg",
            ".png",
            ".pdf",
            ".gif",
            ".webp",
        }
        ext = os.path.splitext(filename)[1].lower()
        use_compression = ext not in uncompressible_exts
        if not use_compression:
            logger.log(
                "INFO",
                "COMPRESS",
                f"'{ext}' 파일은 이미 압축/암호화되어 있어 Zlib 스트리밍 압축을 생략합니다.",
            )
        return use_compression

    def send(self, file_path: str, filename: str, filesize: int) -> tuple[int, str]:
        """
        지정된 파일을 읽고 청크 단위로 나누어 압축, 암호화 후 네트워크로 전송합니다.

        전송 중 실시간으로 파일 내용에 대한 무결성 해시(SHA-256)를 계산합니다.

        Args:
            file_path (str): 전송할 원본 파일의 경로.
            filename (str): 전송될 파일의 이름 (메타데이터용).
            filesize (int): 전송할 파일의 총 크기 (바이트).

        Returns:
            tuple[int, str]: 최종 전송된 전체 바이트 수와 계산된 SHA-256 해시값(Hex 문자열).
        """
        use_compression = self._should_compress(filename)
        compressor = (
            zlib.compressobj(level=1, wbits=15, memLevel=9) if use_compression else None
        )

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
                    flags = (
                        constants.FLAG_COMPRESSED | constants.FLAG_EOF
                        if use_compression
                        else constants.FLAG_EOF
                    )
                    chunk_data = (
                        compressor.flush(zlib.Z_FINISH) if use_compression else b""
                    )
                    self._send_chunk(chunk_index, flags, chunk_data)
                    break

                chunk_view = buffer_view[:bytes_read]
                self.file_hasher.update(chunk_view)

                flags = constants.FLAG_COMPRESSED if use_compression else 0x00
                chunk_data = (
                    compressor.compress(chunk_view) if use_compression else chunk_view
                )

                if len(chunk_data) == 0:
                    sent_size += bytes_read
                    continue

                self._send_chunk(chunk_index, flags, chunk_data)

                sent_size += bytes_read
                logger.log(
                    "INFO",
                    "CHUNK",
                    f"청크 {chunk_index} 전송 완료 ({sent_size}/{filesize} 바이트)",
                )
                chunk_index += 1

        transfer_end_time = time.perf_counter()
        file_hash = self.file_hasher.hexdigest()

        logger.log("PASS", "CHUNK", "모든 청크 전송 완료")
        logger.log(
            "RESULT",
            "TRANSFER",
            f"파일 데이터 전송 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)",
        )
        logger.log("INFO", "HASH", f"최종 파일 SHA-256: {file_hash}")

        return sent_size, file_hash

    def _send_chunk(self, chunk_index: int, flags: int, chunk_data: bytes) -> None:
        """
        단일 청크 데이터에 대해 헤더와 Nonce를 생성하고 AES-GCM으로 암호화하여 소켓을 통해 전송합니다.

        Args:
            chunk_index (int): 현재 청크의 순차적인 인덱스 (Replay 방지).
            flags (int): 청크의 압축 상태 및 파일의 끝(EOF) 여부를 나타내는 비트 플래그.
            chunk_data (bytes): 전송할 실제 데이터 페이로드(평문 또는 압축문).
        """
        self.nonce_struct.pack_into(self.nonce_buffer, 0, chunk_index)
        payload_len = constants.NONCE_SIZE + len(chunk_data) + constants.AES_TAG_SIZE
        self.header_struct.pack_into(
            self.header_buffer, 0, flags, chunk_index, payload_len
        )

        encrypted_chunk = self.aesgcm.encrypt(
            self.nonce_view, chunk_data, associated_data=self.header_view
        )
        self.conn.sock.sendall(self.header_buffer + self.nonce_buffer + encrypted_chunk)
