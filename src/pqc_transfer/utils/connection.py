import socket
import struct
import time

from .. import exceptions

class SecureConnection:
    """
    네트워크 소켓 통신을 캡슐화한 클래스입니다.
    Zero-copy 기반의 효율적인 수신과 길이 기반 가변 데이터(TLV) 송수신 기능을 제공하며,
    Slowloris 방어 로직 등을 내장하여 보안과 유지보수성을 향상시킵니다.
    """
    def __init__(self, sock: socket.socket, is_server: bool = False):
        self.sock = sock
        self.is_server = is_server
        self._configure_socket()

    def _configure_socket(self) -> None:
        """공통 소켓 설정(버퍼 크기, 재사용, Nagle 알고리즘 비활성화)을 적용합니다."""
        if self.is_server:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)

    def recv_exact_into(self, view: memoryview, length: int) -> None:
        pos = 0
        start_time = time.monotonic()
        loop_count = 0
        flags = socket.MSG_WAITALL if hasattr(socket, 'MSG_WAITALL') else 0
        while pos < length:
            packet_len = self.sock.recv_into(view[pos:length], length - pos, flags)
            if not packet_len:
                raise exceptions.PQCNetworkError("네트워크 연결이 예기치 않게 종료되었습니다.")
            pos += packet_len
            loop_count += 1
            if loop_count & 63 == 0:
                if time.monotonic() - start_time > 30.0:
                    raise exceptions.PQCNetworkError("데이터 수신 속도가 너무 느립니다 (Slowloris 방어).")

    def recv_exact(self, length: int) -> bytes:
        buf = bytearray(length)
        view = memoryview(buf)
        self.recv_exact_into(view, length)
        return bytes(buf)

    def recv_with_length(self, max_len: int = 100 * 1024 * 1024) -> bytes:
        data_len_bytes = self.recv_exact(4)
        data_len = struct.unpack("!I", data_len_bytes)[0]
        
        if data_len <= 0 or data_len > max_len:
            raise exceptions.PQCProtocolError(f"유효하지 않거나 허용치를 초과하는 수신 데이터 길이입니다: {data_len} bytes")
            
        return self.recv_exact(data_len)

    def send_with_length(self, data: bytes) -> None:
        self.sock.sendall(struct.pack("!I", len(data)) + data)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
