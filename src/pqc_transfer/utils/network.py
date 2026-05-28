import socket
import struct

def recv_exact_into(sock: socket.socket, view: memoryview, length: int) -> None:
    """
    미리 할당된 memoryview 버퍼에 지정된 length 바이트만큼 데이터를 수신하여 저장
    새로운 메모리 객체를 생성하지 않으므로(Zero-copy) 대용량 수신 시 메모리 효율이 매우 높음
    """
    pos = 0
    while pos < length:
        packet_len = sock.recv_into(view[pos:length])
        if not packet_len:
            raise ConnectionError("네트워크 연결이 예기치 않게 종료되었습니다.")
        pos += packet_len

def recv_exact(sock: socket.socket, length: int) -> bytes:
    """
    소켓 버퍼에서 정확히 지정된 length 바이트만큼의 데이터를 읽어올 때까지 대기하며 수신
    스트림 기반인 TCP 소켓 특성상 데이터가 잘려서 도착할 수 있으므로 이 함수가 필요
    """
    buf = bytearray(length)
    view = memoryview(buf)
    pos = 0
    while pos < length:
        packet_len = sock.recv_into(view[pos:])
        if not packet_len:
            # 상대방이 연결을 정상적으로 종료했거나 네트워크가 끊어진 경우 예외 발생
            raise ConnectionError("네트워크 연결이 예기치 않게 종료되었습니다.")
        pos += packet_len
    # 수정: liboqs-python 등 암호 모듈이 순수 bytes 객체를 요구하므로 변환하여 반환
    return bytes(buf)

def recv_with_length(sock: socket.socket, max_len: int = 100 * 1024 * 1024) -> bytes:
    """
    가변 길이의 데이터를 수신하기 위한 래퍼 함수
    데이터의 첫 4바이트에는 이후 수신할 데이터의 실제 길이가 부호 없는 정수 형태로 들어있음
    먼저 4바이트를 읽어 전체 길이를 파악한 후 그 길이만큼 정확히 데이터를 더 읽어옴
    """
    # 1. 4바이트 길이 정보(헤더) 먼저 수신
    data_len_bytes = recv_exact(sock, 4)
    # 2. 바이트 배열을 파이썬 정수형으로 변환 (!I = Network byte order, Unsigned Integer)
    data_len = struct.unpack("!I", data_len_bytes)[0]
    
    # 3. 비정상적으로 큰 데이터(예: 100MB 초과)가 요청된 경우 메모리 초과 공격(OOM)을 방지
    if data_len <= 0 or data_len > max_len:
        raise ValueError(f"유효하지 않거나 허용치를 초과하는 수신 데이터 길이입니다: {data_len} bytes")
        
    # 4. 파악된 길이만큼 실제 데이터 페이로드 수신
    return recv_exact(sock, data_len)

def send_with_length(sock: socket.socket, data: bytes) -> None:
    """
    가변 길이의 데이터를 전송하기 위한 래퍼 함수
    데이터 본문을 보내기 직전에, 해당 데이터의 길이(바이트 수)를 4바이트 헤더로 먼저 전송
    """
    # 1. 전송할 데이터의 길이(4바이트 헤더)와 실제 데이터를 합쳐 한 번의 시스템 콜로 전송
    sock.sendall(struct.pack("!I", len(data)) + data)
