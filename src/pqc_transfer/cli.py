import argparse
import sys
import os

from .core.client import PQCClient
from .utils import config, logger
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
    server = PQCServer(host, port)
    server.start()


def run_client(file_path: str | None = None) -> None:
    """
    클라이언트 실행 함수입니다.
    초기 설정을 로깅하고, 사용자로부터 전송할 파일을 선택받아 PQCClient 인스턴스를 실행합니다.
    """
    _log_initialization("클라이언트")

    if not file_path:
        file_path = gui.select_file()

    if not file_path:
        logger.log("INFO", "FILE", "사용자가 파일 선택을 취소했습니다")
        return

    if not os.path.isfile(file_path):
        logger.log("ERROR", "FILE", f"파일을 찾을 수 없거나 디렉토리입니다: {file_path}")
        gui.show_error("파일 오류", f"유효한 파일이 아닙니다.\n\n{file_path}")
        return

    try:
        client = PQCClient(file_path)
        client.transfer()
        gui.show_info("전송 완료", f"파일 전송이 완료되었습니다.\n\n{client.filename}")
    except Exception as e:
        gui.show_error("전송 실패", str(e))
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
