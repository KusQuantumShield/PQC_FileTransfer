import struct
import socket

from . import constants
from ..utils import network, logger
from .. import exceptions

def send_metadata(conn: network.SecureConnection, client_id: str, filename: str, filesize: int) -> None:
    """
    클라이언트가 파일 전송 전에 필요한 메타데이터를 서버로 전송합니다.
    
    Args:
        conn (network.SecureConnection): 서버와 연결된 보안 소켓.
        client_id (str): 클라이언트 고유 식별자.
        filename (str): 전송할 원본 파일의 이름.
        filesize (int): 전송할 파일의 총 바이트 수.
    """
    client_id_bytes = client_id.encode("utf-8")
    conn.send_with_length(client_id_bytes)
    
    filename_bytes = filename.encode("utf-8")
    conn.send_with_length(filename_bytes)
    
    conn.sock.sendall(struct.pack(constants.FILESIZE_FORMAT, filesize))
    logger.log("INFO", "FILE", "초기 파일 메타데이터 전송 완료")

def receive_metadata(conn: network.SecureConnection) -> tuple[str, str, int]:
    """
    서버가 클라이언트로부터 파일의 메타데이터를 수신합니다.
    
    서버 디스크 보호를 위해 최대 허용 파일 크기 초과 여부를 사전에 검증합니다.
    
    Args:
        conn (network.SecureConnection): 클라이언트와 연결된 보안 소켓.
        
    Returns:
        tuple[str, str, int]: 수신된 클라이언트 ID, 파일 이름, 그리고 파일 크기(바이트).
        
    Raises:
        exceptions.PQCProtocolError: 파일 크기가 시스템의 허용 범위를 초과한 경우.
    """
    client_id = conn.recv_with_length(max_len=constants.MAX_CLIENT_ID_LEN).decode("utf-8")
    filename = conn.recv_with_length(max_len=constants.MAX_FILENAME_LEN).decode("utf-8")
    
    filesize_bytes = conn.recv_exact(constants.FILESIZE_SIZE)
    filesize = struct.unpack(constants.FILESIZE_FORMAT, filesize_bytes)[0]
    
    if filesize > constants.MAX_FILE_SIZE:
        logger.log("ERROR", "FILE", f"파일 크기가 너무 큽니다: {filesize} bytes")
        raise exceptions.PQCProtocolError("파일 크기 제한 초과")
        
    logger.log("INFO", "FILE", f"수신 파일 정보 - 이름: {filename}, 크기: {filesize} 바이트, 클라이언트 ID: {client_id}")
    return client_id, filename, filesize
