import pytest
import subprocess
import time
import os

@pytest.fixture(scope="session", autouse=True)
def start_server():
    # 서버 서브프로세스로 실행 (-m 방식)
    env = os.environ.copy()
    src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
    if 'PYTHONPATH' in env:
        env['PYTHONPATH'] = f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
    else:
        env['PYTHONPATH'] = src_path
    
    cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    process = subprocess.Popen(["python3", "-m", "pqc_transfer", "server"], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    
    # 서버가 바인딩 될 때까지 잠시 대기
    time.sleep(1.0)
    
    yield  # 이 지점에서 테스트 실행
    
    # 테스트 종료 후 서버 강제 종료
    process.terminate()
    process.wait(timeout=2.0)

@pytest.fixture
def dummy_file(tmp_path):
    """
    테스트에 사용할 더미 파일을 임시 폴더에 생성하고 반환하는 Fixture입니다.
    이전 테스트 파일들 간에 중복으로 존재하던 파일 생성 로직을 제거하고 중앙화합니다.
    """
    file_path = tmp_path / "test.txt"
    file_path.write_text("This is a dummy test file for testing.")
    return str(file_path)
