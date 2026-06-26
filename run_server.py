import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))
from pqc_transfer.cli import main_server

if __name__ == "__main__":
    sys.exit(main_server())
