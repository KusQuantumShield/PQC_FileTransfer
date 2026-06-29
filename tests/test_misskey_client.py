import os
import pytest
from unittest.mock import patch
from pqc_transfer.core.client import PQCClient
from pqc_transfer.utils.connection import SecureConnection

def test_misskey_client(dummy_file):
    """
    KEM 암호문(kem_ciphertext)이 중간에 변조되었을 때(MitM 공격 시뮬레이션),
    서버와 클라이언트가 이를 감지하고 연결을 안전하게 차단(예외 발생)하는지 검증합니다.
    
    네트워크 전송 함수(`send_with_length`)를 모킹(Mocking)하여,
    전송되는 KEM 암호문의 첫 바이트를 강제로 변조한 뒤 테스트를 수행합니다.
    
    Args:
        dummy_file (str): 'conftest.py'에서 제공하는 임시 테스트 파일의 경로.
    """
    client = PQCClient.from_config(dummy_file)
    
    # 원래의 network.send_with_length 함수 저장
    original_send = SecureConnection.send_with_length

    import oqs
    from pqc_transfer.utils import config
    
    with oqs.KeyEncapsulation(config.default_config.kem_alg) as kem:
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
    with patch('pqc_transfer.utils.connection.SecureConnection.send_with_length', side_effect=mocked_send, autospec=True):
        with pytest.raises(Exception):
            client.transfer()
        
    # KEM 변조 시 클라이언트는 정상적으로 파일 전송을 완료(finalize_transfer)할 수 없습니다.
    # 만약 예외가 발생하지 않았다면 테스트가 실패(pytest.raises)합니다.
