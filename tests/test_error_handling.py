import pytest
from unittest.mock import patch, MagicMock

from pqc_transfer.core.client import PQCClient
from pqc_transfer.utils.config import AppConfig
from pqc_transfer.utils.key_manager import KeyManager
from pqc_transfer import exceptions

def test_client_connection_refused_error(dummy_file):
    """
    서버가 열려있지 않은 상태에서 클라이언트가 접속을 시도할 때,
    명확한 Custom Exception(PQCNetworkError)이 버블링되어 발생하는지 테스트합니다.
    """
    km = KeyManager(key_dir="dummy_keys", sig_alg="ML-DSA-65")
    config = AppConfig(port=9998) # 존재하지 않는 포트 사용
    client = PQCClient(file_path=dummy_file, app_config=config, key_manager=km)
    
    with pytest.raises(exceptions.PQCNetworkError, match="서버에 연결할 수 없습니다"):
        client.transfer()

@patch('socket.socket')
def test_client_unexpected_exception(mock_socket, dummy_file):
    """
    통신 중 예상치 못한 Exception이 발생했을 때 안전하게 상위로 버블링되는지 검증합니다.
    """
    mock_sock_instance = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    
    # 강제로 알 수 없는 에러 발생
    mock_sock_instance.connect.side_effect = RuntimeError("Unknown critical error")
    
    km = KeyManager(key_dir="dummy_keys", sig_alg="ML-DSA-65")
    config = AppConfig(port=9999)
    client = PQCClient(file_path=dummy_file, app_config=config, key_manager=km)
    
    with pytest.raises(RuntimeError, match="Unknown critical error"):
        client.transfer()
