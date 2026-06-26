import os
import pytest
from unittest.mock import patch
from pqc_transfer.core.client import PQCClient
from pqc_transfer.utils import network

def test_misssign_test(dummy_file):
    """
    파일 해시(file_hash)가 포함된 서명 데이터가 변조되었을 때 
    서버가 이를 감지하고 연결을 차단하는지 테스트합니다.
    """
    client = PQCClient.from_config(dummy_file)
    
    # 원래의 network.send_with_length 함수 저장
    original_send = network.send_with_length

    # 시그니처가 전송되는 시점인지 파악하기 위한 플래그
    # PQCClient는 공개키를 먼저 보내고 그 다음 시그니처를 보냅니다.
    state = {"pk_sent": False}

    import oqs
    from pqc_transfer.utils import config
    
    with oqs.Signature(config.SIG_ALG) as signer:
        pk_len = signer.details['length_public_key']
        sig_len = signer.details['length_signature']

    def mocked_send(sock, data):
        if isinstance(data, bytes) and len(data) == pk_len:
            state["pk_sent"] = True
            
        if isinstance(data, bytes) and len(data) == sig_len and state["pk_sent"]:
            # 시그니처 바이트 변조
            modified_data = bytearray(data)
            modified_data[0] = (modified_data[0] + 1) % 256
            # 변조된 시그니처 전송
            return original_send(sock, bytes(modified_data))
            
        return original_send(sock, data)

    # 모킹 적용
    with patch('pqc_transfer.utils.network.send_with_length', side_effect=mocked_send):
        with pytest.raises(Exception):
            client.transfer()
            
    # 서명 변조 시 서버는 CLIENT_DONE 수신 시 SERVER_OK를 보내면 안 됨
    # 정상적으로 종료되지 않았음을 확인 (예외 발생)
