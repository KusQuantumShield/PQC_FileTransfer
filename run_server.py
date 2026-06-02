import sys
import os
# src 디렉토리를 파이썬 모듈 검색 경로에 추가하여 pqc_transfer 패키지를 임포트할 수 있게 함
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

# 서버 메인 함수 임포트
from pqc_transfer.server import main

if __name__ == "__main__":
    main()
