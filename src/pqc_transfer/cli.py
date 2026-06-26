import argparse
import sys
import os

from .core.client import PQCClient
from .utils import config, logger, key_manager
from .ui import gui


def _log_initialization(mode: str) -> None:
    logger.log("INFO", "SYSTEM", f"--- PQC 파일 전송 {mode} 초기화 ---")
    logger.log("INFO", "SYSTEM", f"설정된 KEM 알고리즘: {config.KEM_ALG}")
    logger.log("INFO", "SYSTEM", f"설정된 서명 알고리즘: {config.SIG_ALG}")
    logger.log("INFO", "SYSTEM", f"청크(Chunk) 크기: {config.CHUNK_SIZE} 바이트")

def run_server(host: str | None = None, port: int | None = None) -> None:
    """
    서버 프로그램의 진입점(Entry Point)입니다.
    """
    host = host if host is not None else config.HOST
    port = port if port is not None else config.PORT

    _log_initialization("서버")
    from .core.server import PQCServer
    
    server = PQCServer.from_config(host=host, port=port)
    server.start()


def run_client(file_path: str | None = None) -> None:
    """
    클라이언트 실행 함수입니다.
    초기 설정을 로깅하고, 사용자로부터 전송할 파일을 선택받아 PQCClient 인스턴스를 실행합니다.
    """
    _log_initialization("클라이언트")
    
    if not file_path:
        # CLI에서 파일 경로 없이 실행 시 더 이상 GUI 폴더 선택창을 띄우지 않고 명시적인 에러 반환 (관심사 분리)
        logger.log("ERROR", "CLI", "전송할 파일 경로가 지정되지 않았습니다. 사용법: python -m pqc_transfer client <파일경로>")
        return
        
    if not os.path.isfile(file_path):
        logger.log("ERROR", "CLI", f"파일을 찾을 수 없습니다: {file_path}")
        return

    try:
        from .core.client import PQCClient
        
        client = PQCClient.from_config(file_path=file_path)
        client.transfer()
        logger.log("INFO", "CLI", f"파일 전송이 완료되었습니다: {client.filename}")
    except Exception as e:
        logger.log("ERROR", "CLI", f"전송 실패: {str(e)}")
        sys.exit(1)


def main_server():
    """Entry point for pqc-server script"""
    run_server()


def main_client():
    """Entry point for pqc-client script"""
    file_path = sys.argv[1] if len(sys.argv) > 1 else None
    run_client(file_path)


def main():
    """Entry point for python -m pqc_transfer"""
    parser = argparse.ArgumentParser(description="PQC File Transfer (Quantum-Safe)")
    parser.add_argument("mode", choices=["client", "server"], help="실행 모드를 선택하세요: client 또는 server")
    parser.add_argument("file_path", nargs="?", help="클라이언트 모드일 경우 전송할 파일의 경로")

    args = parser.parse_args()

    if args.mode == "server":
        run_server()
    elif args.mode == "client":
        run_client(args.file_path)
