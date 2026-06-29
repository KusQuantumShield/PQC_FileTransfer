import os
import zlib
import time
import tempfile
import typing

from . import constants
from .chunk_base import ChunkProcessorBase
from .. import exceptions
from ..utils import logger, network


class ChunkReceiver(ChunkProcessorBase):
    """
    네트워크로부터 청크 단위로 데이터를 수신하고 AES-GCM 복호화 및 실시간 압축 해제를
    수행하여 임시 파일로 저장하는 클래스입니다.
    """

    def __init__(
        self,
        conn: network.SecureConnection,
        session_key: bytes,
        file_hasher: typing.Any,
        chunk_size: int = 4 * 1024 * 1024,
    ) -> None:
        super().__init__(conn, session_key, file_hasher, chunk_size)

        self.decompressor = zlib.decompressobj()
        self.max_payload_size = self.chunk_size * 2
        self.recv_buffer = bytearray(self.max_payload_size)
        self.recv_view = memoryview(self.recv_buffer)

    def receive(self, original_filesize: int, save_dir: str) -> tuple[str, int]:
        """
        스트림 방식으로 연속적인 청크를 수신, 복호화, 무결성 검증, 압축 해제 후 로컬 파일에 기록합니다.

        Zip Bomb 등의 악의적인 압축 데이터를 방어하기 위한 크기 검증 로직이 포함되어 있습니다.

        Args:
            original_filesize (int): 송신 측이 선언한 원본 파일의 크기(기대값).
            save_dir (str): 수신 중인 파일을 임시로 저장할 디렉토리 경로.

        Returns:
            tuple[str, int]: 임시로 저장된 파일의 절대 경로와 실제 누적된 바이트 수.

        Raises:
            exceptions.PQCProtocolError: 청크 인덱스 오류, 통신 프로토콜 위반 시.
            exceptions.PQCIntegrityError: 복호화 실패(변조), 압축 해제 오류 발생 시.
            exceptions.PQCSecurityError: Zip Bomb 공격 의심 또는 파일 크기가 과도할 경우.
        """
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
                flags, chunk_index, payload_len = self.header_struct.unpack_from(
                    self.header_buffer, 0
                )

                if chunk_index != expected_chunk_index:
                    raise exceptions.PQCProtocolError("청크 인덱스 불일치")
                if payload_len <= 0 or payload_len > self.max_payload_size:
                    raise exceptions.PQCProtocolError("유효하지 않은 페이로드 길이")

                self.conn.recv_exact_into(self.recv_view, payload_len)

                nonce = self.recv_view[: constants.NONCE_SIZE]
                encrypted_chunk = self.recv_view[constants.NONCE_SIZE : payload_len]

                try:
                    decrypted_chunk = self.aesgcm.decrypt(
                        nonce, encrypted_chunk, associated_data=self.header_buffer
                    )
                except Exception:
                    raise exceptions.PQCIntegrityError(
                        "청크 무결성 검증 실패 (데이터 변조 또는 키 불일치)"
                    )

                if flags & constants.FLAG_COMPRESSED:
                    try:
                        decrypted_chunk = self.decompressor.decompress(
                            decrypted_chunk, max_length=self.max_payload_size
                        )
                        if self.decompressor.unconsumed_tail:
                            raise exceptions.PQCSecurityError(
                                "압축 해제 크기 제한 초과 (Zip Bomb 공격 감지)"
                            )
                    except Exception as e:
                        if "Zip Bomb" in str(e):
                            raise
                        raise exceptions.PQCIntegrityError(
                            "데이터 압축 해제 실패 (데이터 손상 의심)"
                        )

                if (
                    len(decrypted_chunk) == 0
                    and not (flags & constants.FLAG_EOF)
                    and not (flags & constants.FLAG_COMPRESSED)
                ):
                    raise exceptions.PQCProtocolError("비정상적인 0바이트 청크 데이터")

                temp_file.write(decrypted_chunk)
                self.file_hasher.update(decrypted_chunk)

                received_size += len(decrypted_chunk)
                if received_size > original_filesize:
                    raise exceptions.PQCSecurityError("수신 파일 크기 초과")

                logger.log(
                    "INFO",
                    "CHUNK",
                    f"청크 {chunk_index} 수신 완료 ({received_size}/{original_filesize} 바이트)",
                )
                expected_chunk_index += 1

                if flags & constants.FLAG_EOF:
                    logger.log(
                        "INFO", "CHUNK", "모든 청크 데이터 수신 완료 (EOF 플래그 감지)"
                    )
                    break

            transfer_end_time = time.perf_counter()
            logger.log(
                "PASS",
                "CHUNK",
                f"모든 청크 수신 완료 (소요 시간: {transfer_end_time - transfer_start_time:.4f} 초)",
            )

        finally:
            temp_file.close()

        return temp_path, received_size
