import struct
import typing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from abc import ABC, abstractmethod

from . import constants
from ..utils import connection

class ChunkProcessorBase(ABC):
    """
    청크 전송/수신기의 공통 로직(암호화 초기화, 구조체 설정)을 관리하는 추상 기저 클래스입니다.
    
    유지보수성과 코드 재사용성을 높이기 위해 공통된 필드들을 상위 클래스로 분리했습니다.
    """
    def __init__(self, conn: connection.SecureConnection, session_key: bytes, file_hasher: typing.Any, chunk_size: int) -> None:
        """
        ChunkProcessorBase 객체를 초기화합니다.
        
        Args:
            conn (connection.SecureConnection): 보안 통신 소켓 래퍼.
            session_key (bytes): AES-GCM 암호화에 사용할 대칭키.
            file_hasher (typing.Any): 파일의 무결성 검증을 위한 해시 객체 (e.g. hashlib.sha256).
            chunk_size (int): 청크를 읽어들일 기본 단위 크기(바이트).
        """
        self.conn = conn
        self.aesgcm = AESGCM(session_key)
        self.file_hasher = file_hasher
        self.chunk_size = chunk_size
        
        self.header_struct = struct.Struct(constants.HEADER_FORMAT)
        self.header_buffer = bytearray(constants.HEADER_SIZE)
        self.header_view = memoryview(self.header_buffer)
