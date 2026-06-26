import os
import filecmp
from pqc_transfer.core.client import PQCClient

def test_successful_transfer(dummy_file):
    """
    정상적인 조건에서 클라이언트가 서버로 파일을 전송했을 때,
    파일이 변조 없이 원본과 동일하게 서버에 저장되는지 검증하는 Happy Path 테스트입니다.
    """
    client = PQCClient.from_config(dummy_file)
    client.transfer()
    
    from pqc_transfer.utils import config
    
    # 서버가 파일을 저장한 경로 확인
    filename = os.path.basename(dummy_file)
    save_dir = config.SAVE_DIR
    received_file_path = os.path.join(save_dir, filename)
    
    # 파일이 존재하는지 확인
    assert os.path.exists(received_file_path), "서버에 파일이 저장되지 않았습니다."
    
    # 원본 파일과 수신된 파일의 내용이 동일한지 (무결성) 검증
    assert filecmp.cmp(dummy_file, received_file_path, shallow=False), "수신된 파일의 내용이 원본과 다릅니다."
