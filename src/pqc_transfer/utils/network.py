import socket
import struct

import time

def recv_exact_into(sock: socket.socket, view: memoryview, length: int) -> None:
    """
    미리 할당된 memoryview 버퍼(view)에 정확히 지정된 length 바이트만큼 데이터를 수신하여 직접 저장합니다.
    이 함수는 새로운 메모리 객체를 매번 생성하지 않고 기존 버퍼를 재사용하므로(Zero-copy),
    대용량 청크 데이터를 빠르게 수신할 때 메모리 효율과 속도가 매우 높습니다.
    """
    pos = 0
    start_time = time.monotonic()
    loop_count = 0
    flags = socket.MSG_WAITALL if hasattr(socket, 'MSG_WAITALL') else 0
    while pos < length:
        packet_len = sock.recv_into(view[pos:length], length - pos, flags)
        if not packet_len:
            raise ConnectionError("네트워크 연결이 예기치 않게 종료되었습니다.")
        pos += packet_len
        loop_count += 1
        # Slowloris 방어: 단일 청크 수신에 30초 이상 걸리면 강제 차단
        # 최적화: 매 루프마다 시간 확인을 하지 않고 64번마다 확인하여 syscall 오버헤드 감소
        if loop_count & 63 == 0:
            if time.monotonic() - start_time > 30.0:
                raise TimeoutError("데이터 수신 속도가 너무 느립니다 (Slowloris 방어).")

def recv_exact(sock: socket.socket, length: int) -> bytes:
    """
    소켓 버퍼에서 정확히 지정된 length 바이트만큼의 데이터를 읽어올 때까지 대기하며 수신합니다.
    """
    buf = bytearray(length)
    view = memoryview(buf)
    pos = 0
    start_time = time.monotonic()
    loop_count = 0
    flags = socket.MSG_WAITALL if hasattr(socket, 'MSG_WAITALL') else 0
    while pos < length:
        packet_len = sock.recv_into(view[pos:], length - pos, flags)
        if not packet_len:
            raise ConnectionError("네트워크 연결이 예기치 않게 종료되었습니다.")
        pos += packet_len
        loop_count += 1
        # Slowloris 방어 및 최적화
        if loop_count & 63 == 0:
            if time.monotonic() - start_time > 30.0:
                raise TimeoutError("데이터 수신 속도가 너무 느립니다 (Slowloris 방어).")
    
    return bytes(buf)

def recv_with_length(sock: socket.socket, max_len: int = 100 * 1024 * 1024) -> bytes:
    """
    가변 길이의 데이터를 안전하고 정확하게 수신하기 위한 래퍼 함수입니다.
    네트워크 패킷의 첫 4바이트에는 이후 수신할 실제 데이터의 길이(Payload Length)가 들어있습니다.
    """
    # 1. 먼저 4바이트 크기의 헤더(길이 정보)를 고정적으로 수신
    data_len_bytes = recv_exact(sock, 4)
    # 2. 수신된 4바이트 바이너리를 파이썬 정수형으로 언패킹
    # '!I' 포맷: 네트워크 바이트 순서(Big Endian, '!'), 부호 없는 4바이트 정수('I')
    data_len = struct.unpack("!I", data_len_bytes)[0]
    
    # 3. 비정상적으로 큰 데이터(예: 100MB 초과)가 요청된 경우 검증
    # 서버 메모리를 고갈시키기 위한 메모리 초과 공격(OOM Attack)을 사전에 차단
    if data_len <= 0 or data_len > max_len:
        raise ValueError(f"유효하지 않거나 허용치를 초과하는 수신 데이터 길이입니다: {data_len} bytes")
        
    # 4. 검증을 통과한 안전한 길이(data_len)만큼만 실제 데이터 페이로드(Payload)를 수신하여 반환
    return recv_exact(sock, data_len)

def send_with_length(sock: socket.socket, data: bytes) -> None:
    """
    가변 길이의 데이터를 네트워크로 전송하기 위한 래퍼 함수입니다.
    데이터 본문을 보내기 직전에, 해당 데이터의 전체 길이(바이트 수)를 4바이트 헤더로 먼저 덧붙여 전송합니다.
    """
    # 1. len(data)로 전체 길이를 구한 뒤, struct.pack("!I", ...)를 통해 4바이트 네트워크 바이트 순서로 패킹
    # 2. 4바이트 헤더와 실제 데이터를 바이트 연결(+)하여 전송. sendmsg는 short write 위험이 있어 sendall 사용
    sock.sendall(struct.pack("!I", len(data)) + data)
