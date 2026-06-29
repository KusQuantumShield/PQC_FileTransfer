import pytest
import subprocess
import time
import os
import sys

@pytest.fixture(scope="session", autouse=True)
def start_server():
    """
    모든 테스트가 실행되기 전에 한 번만 PQC 백그라운드 서버를 서브프로세스로 구동합니다.
    
    서버는 테스트 세션이 종료되면 안전하게 자동(terminate)으로 종료됩니다.
    
    Yields:
        None: 이 지점에서 각 테스트 함수들이 실행됩니다.
    """
    env = os.environ.copy()
    src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
    if 'PYTHONPATH' in env:
        env['PYTHONPATH'] = f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
    else:
        env['PYTHONPATH'] = src_path
    
    cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    process = subprocess.Popen([sys.executable, "-m", "pqc_transfer", "server"], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    
    time.sleep(1.0)
    
    yield
    
    process.terminate()
    process.wait(timeout=2.0)

@pytest.fixture
def dummy_file(tmp_path):
    """
    테스트에 사용할 더미 파일을 임시 폴더에 생성하고 그 절대 경로를 반환하는 Fixture입니다.
    
    Args:
        tmp_path (pathlib.Path): pytest 내장 임시 디렉토리 픽스처.
        
    Returns:
        str: 생성된 임시 더미 파일의 절대 경로.
    """
    file_path = tmp_path / "test.txt"
    file_path.write_text("This is a dummy test file for testing.")
    return str(file_path)
