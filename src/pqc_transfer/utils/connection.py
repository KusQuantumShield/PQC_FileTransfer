import socket
import struct
import time

from .. import exceptions

class SecureConnection:
    """
    네트워크 소켓 통신을 캡슐화한 보안 연결 래퍼(Wrapper) 클래스입니다.
    
    Zero-copy 기반의 효율적인 데이터 수신(memoryview)과 길이 기반 가변 데이터(TLV) 송수신 
    기능을 제공하며, Slowloris 등의 네트워크 공격을 방어하는 타이머 로직이 내장되어 있습니다.
    """
    def __init__(self, sock: socket.socket, is_server: bool = False) -> None:
        """
        SecureConnection 인스턴스를 초기화하고 소켓 옵션을 구성합니다.
        
        Args:
            sock (socket.socket): 원시(Raw) 네트워크 소켓 객체.
            is_server (bool): 현재 객체가 서버 측에서 실행 중인지 여부. 기본값은 False.
        """
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
        """
        주어진 크기(length)만큼 정확히 데이터를 읽어 메모리뷰 버퍼(view)에 직접 기록합니다(Zero-copy).
        
        네트워크 지연이나 조각화(Fragmentation)에 대응하여 루프를 돌며 데이터를 끝까지 모읍니다.
        또한, 30초 이상 데이터 조각 전송이 지속되는 경우 Slowloris 공격으로 간주하고 연결을 차단합니다.
        
        Args:
            view (memoryview): 데이터를 기록할 대상 메모리 뷰.
            length (int): 정확히 수신해야 할 바이트 수.
            
        Raises:
            exceptions.PQCNetworkError: 소켓 연결이 끊어지거나 수신 속도가 너무 느린 경우.
        """
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
        """
        요청한 길이만큼의 데이터를 수신하여 바이트 객체로 반환합니다.
        
        Args:
            length (int): 수신할 바이트 수.
            
        Returns:
            bytes: 수신된 바이트 데이터.
        """
        buf = bytearray(length)
        view = memoryview(buf)
        self.recv_exact_into(view, length)
        return bytes(buf)

    def recv_with_length(self, max_len: int = 100 * 1024 * 1024) -> bytes:
        """
        4바이트(Unsigned Int) 헤더로 전달된 페이로드 길이를 먼저 읽고, 해당 길이만큼 데이터를 이어서 수신합니다.
        
        Args:
            max_len (int): 허용하는 최대 페이로드 크기(OOM 공격 방어). 기본값은 100MB.
            
        Returns:
            bytes: 수신된 가변 길이 페이로드 데이터.
            
        Raises:
            exceptions.PQCProtocolError: 수신 데이터의 선언된 길이가 0 이하거나 max_len을 초과하는 경우.
        """
        data_len_bytes = self.recv_exact(4)
        data_len = struct.unpack("!I", data_len_bytes)[0]
        
        if data_len <= 0 or data_len > max_len:
            raise exceptions.PQCProtocolError(f"유효하지 않거나 허용치를 초과하는 수신 데이터 길이입니다: {data_len} bytes")
            
        return self.recv_exact(data_len)

    def send_with_length(self, data: bytes) -> None:
        """
        전송할 데이터 길이(4바이트 Unsigned Int)를 헤더로 덧붙여 소켓을 통해 전송합니다.
        
        Args:
            data (bytes): 전송할 페이로드 데이터.
        """
        self.sock.sendall(struct.pack("!I", len(data)) + data)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
