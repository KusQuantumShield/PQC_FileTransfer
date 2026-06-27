import struct
import socket

from . import constants
from ..utils import network, logger
from .. import exceptions

def send_metadata(sock: socket.socket, client_id: str, filename: str, filesize: int) -> None:
    """
    클라이언트가 서버로 세션 정보(client_id)와 파일 메타데이터(filename, filesize)를 전송합니다.
    """
    client_id_bytes = client_id.encode("utf-8")
    network.send_with_length(sock, client_id_bytes)
    
    filename_bytes = filename.encode("utf-8")
    network.send_with_length(sock, filename_bytes)
    
    sock.sendall(struct.pack(constants.FILESIZE_FORMAT, filesize))
    logger.log("INFO", "FILE", "초기 파일 메타데이터 전송 완료")

def receive_metadata(conn: socket.socket) -> tuple[str, str, int]:
    """
    서버가 클라이언트로부터 세션 정보(client_id)와 파일 메타데이터(filename, filesize)를 수신합니다.
    """
    client_id = network.recv_with_length(conn, max_len=constants.MAX_CLIENT_ID_LEN).decode("utf-8")
    filename = network.recv_with_length(conn, max_len=constants.MAX_FILENAME_LEN).decode("utf-8")
    
    filesize_bytes = network.recv_exact(conn, constants.FILESIZE_SIZE)
    filesize = struct.unpack(constants.FILESIZE_FORMAT, filesize_bytes)[0]
    
    if filesize > constants.MAX_FILE_SIZE:
        logger.log("ERROR", "FILE", f"파일 크기가 너무 큽니다: {filesize} bytes")
        raise exceptions.PQCProtocolError("파일 크기 제한 초과")
        
    logger.log("INFO", "FILE", f"수신 파일 정보 - 이름: {filename}, 크기: {filesize} 바이트, 클라이언트 ID: {client_id}")
    return client_id, filename, filesize
