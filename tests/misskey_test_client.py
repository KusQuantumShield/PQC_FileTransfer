import os
import pytest
from unittest.mock import patch
from pqc_transfer.core.client import PQCClient
from pqc_transfer.utils import network

def test_misskey_test(dummy_file):
    """
    KEM 암호문(kem_ciphertext)이 변조되었을 때 
    서버가 이를 감지하고 연결을 차단하는지 테스트합니다.
    """
    client = PQCClient(dummy_file)
    
    # 원래의 network.send_with_length 함수 저장
    original_send = network.send_with_length

    import oqs
    from pqc_transfer.utils import config
    
    with oqs.KeyEncapsulation(config.KEM_ALG) as kem:
        ct_len = kem.details['length_ciphertext']

    def mocked_send(sock, data):
        # KEM 암호문 길이를 동적으로 가져와 변조를 시도합니다.
        if isinstance(data, bytes) and len(data) == ct_len:
            # 첫 번째 바이트 변조 (KEM 암호문 변조 시뮬레이션)
            modified_data = bytearray(data)
            modified_data[0] ^= 0xFF
            return original_send(sock, bytes(modified_data))
        return original_send(sock, data)

    # network.send_with_length를 모킹하여 전송 가로채기
    with patch('pqc_transfer.utils.network.send_with_length', side_effect=mocked_send):
        with pytest.raises(Exception):
            client.transfer()
        
    # KEM 변조 시 클라이언트는 정상적으로 파일 전송을 완료(finalize_transfer)할 수 없습니다.
    # 만약 예외가 발생하지 않았다면 테스트가 실패(pytest.raises)합니다.
