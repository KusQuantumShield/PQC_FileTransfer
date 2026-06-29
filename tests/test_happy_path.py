import os
import filecmp
from pqc_transfer.core.client import PQCClient

def test_successful_transfer(dummy_file):
    """
    정상적인 조건(Happy Path)에서 클라이언트가 서버로 파일을 전송했을 때,
    파일이 변조 없이 원본과 동일하게 서버에 저장되는지 검증합니다.
    
    Args:
        dummy_file (str): 'conftest.py'에서 제공하는 임시 테스트 파일의 경로.
    """
    client = PQCClient.from_config(dummy_file)
    client.transfer()
    
    from pqc_transfer.utils import config
    
    filename = os.path.basename(dummy_file)
    save_dir = config.default_config.save_dir
    received_file_path = os.path.join(config.default_config.save_dir, filename)
    
    assert os.path.exists(config.default_config.save_dir), "저장 디렉토리가 생성되어야 합니다."
    assert filecmp.cmp(dummy_file, received_file_path, shallow=False), "수신된 파일의 내용이 원본과 다릅니다."
