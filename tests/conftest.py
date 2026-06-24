import pytest
import subprocess
import time
import os

@pytest.fixture(scope="session", autouse=True)
def start_server():
    # 현재 디렉토리에서 한 단계 위의 src/run_server.py 실행
    server_script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'run_server.py'))
    cwd = os.path.dirname(server_script)
    
    # 서버 서브프로세스로 실행
    process = subprocess.Popen(["python3", server_script], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # 서버가 바인딩 될 때까지 잠시 대기
    time.sleep(1.0)
    
    yield  # 이 지점에서 테스트 실행
    
    # 테스트 종료 후 서버 강제 종료
    process.terminate()
    process.wait(timeout=2.0)
