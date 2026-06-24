import os
import threading
import stat
import oqs

from . import config
from . import logger

_server_sig_lock = threading.Lock()
_server_sig_pk = None
_server_sig_sk = None

_client_sig_lock = threading.Lock()
_client_sig_pk = None
_client_sig_sk = None

_tofu_lock = threading.Lock()
TRUSTED_KEYS = {}

def get_server_sig_keys():
    """
    서버의 서명용 공개키(Public Key) 및 비밀키(Secret Key) 쌍을 로드하거나 새로 생성합니다.
    """
    global _server_sig_pk, _server_sig_sk
    
    if _server_sig_pk is not None:
        return _server_sig_pk, _server_sig_sk
        
    with _server_sig_lock:
        if _server_sig_pk is not None:
            return _server_sig_pk, _server_sig_sk
            
        server_key_dir = os.path.expanduser("~/.pqc_transfer_keys")
        os.makedirs(server_key_dir, exist_ok=True)
        
        sig_sec_file = os.path.join(server_key_dir, "server_sig_sec.bin")
        sig_pub_file = os.path.join(server_key_dir, "server_sig_pub.bin")
        
        if os.path.exists(sig_sec_file) and os.path.exists(sig_pub_file):
            with open(sig_sec_file, "rb") as f:
                _server_sig_sk = f.read()
            with open(sig_pub_file, "rb") as f:
                _server_sig_pk = f.read()
        else:
            with oqs.Signature(config.SIG_ALG) as signer:
                _server_sig_pk = signer.generate_keypair()
                _server_sig_sk = signer.export_secret_key()
            
            fd = os.open(sig_sec_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb") as f:
                f.write(_server_sig_sk)
            
            with open(sig_pub_file, "wb") as f:
                f.write(_server_sig_pk)
                
        return _server_sig_pk, _server_sig_sk

def get_client_sig_keys():
    """
    클라이언트의 서명용 공개키(Public Key) 및 비밀키(Secret Key) 쌍을 로드하거나 새로 생성합니다.
    """
    global _client_sig_pk, _client_sig_sk
    
    if _client_sig_pk is not None:
        return _client_sig_pk, _client_sig_sk
        
    with _client_sig_lock:
        if _client_sig_pk is not None:
            return _client_sig_pk, _client_sig_sk
            
        key_dir = os.path.expanduser("~/.pqc_transfer_keys")
        os.makedirs(key_dir, exist_ok=True)
        
        sig_sec_file = os.path.join(key_dir, "client_sig_sec.bin")
        sig_pub_file = os.path.join(key_dir, "client_sig_pub.bin")
        
        if os.path.exists(sig_sec_file) and os.path.exists(sig_pub_file):
            with open(sig_sec_file, "rb") as f:
                _client_sig_sk = f.read()
            with open(sig_pub_file, "rb") as f:
                _client_sig_pk = f.read()
        else:
            with oqs.Signature(config.SIG_ALG) as signer:
                _client_sig_pk = signer.generate_keypair()
                _client_sig_sk = signer.export_secret_key()
                
            fd = os.open(sig_sec_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb") as f:
                f.write(_client_sig_sk)
                
            with open(sig_pub_file, "wb") as f:
                f.write(_client_sig_pk)
                
        return _client_sig_pk, _client_sig_sk

def verify_and_trust_client(client_id: str, sig_public_key: bytes) -> bool:
    """
    TOFU 기반으로 클라이언트의 공개키를 검증하고 신뢰 목록에 등록합니다.
    """
    client_id_dir = os.path.expanduser("~/.pqc_transfer_keys")
    os.makedirs(client_id_dir, exist_ok=True)
    trusted_client_file = os.path.join(client_id_dir, f"trusted_client_sig_{client_id}.bin")

    with _tofu_lock:
        if client_id in TRUSTED_KEYS:
            trusted_pub = TRUSTED_KEYS[client_id]
            if trusted_pub != sig_public_key:
                return False
        else:
            if os.path.exists(trusted_client_file):
                with open(trusted_client_file, "rb") as f:
                    trusted_pub = f.read()
                if trusted_pub != sig_public_key:
                    return False
                TRUSTED_KEYS[client_id] = trusted_pub
            else:
                with open(trusted_client_file, "wb") as f:
                    f.write(sig_public_key)
                TRUSTED_KEYS[client_id] = sig_public_key
                logger.log("INFO", "VERIFY", f"새로운 클라이언트({client_id[:8]}) 공개키를 신뢰 목록에 등록했습니다 (TOFU)")
    return True

def verify_and_trust_server(server_ip: str, server_sig_pk: bytes) -> bool:
    """
    TOFU 기반으로 서버의 서명 공개키를 검증하고 신뢰 목록에 등록합니다.
    """
    server_id_dir = os.path.expanduser("~/.pqc_transfer_keys")
    os.makedirs(server_id_dir, exist_ok=True)
    trusted_server_file = os.path.join(server_id_dir, f"trusted_server_sig_{server_ip}.bin")
    
    if os.path.exists(trusted_server_file):
        with open(trusted_server_file, "rb") as f:
            trusted_pub = f.read()
        if trusted_pub != server_sig_pk:
            return False
    else:
        with open(trusted_server_file, "wb") as f:
            f.write(server_sig_pk)
        logger.log("INFO", "VERIFY", "새로운 서버의 서명 공개키를 신뢰 목록에 등록했습니다 (TOFU)")
    return True

def get_client_id() -> str:
    """
    클라이언트 고유 식별자(UUID)를 생성하거나 불러옵니다.
    """
    import uuid
    key_dir = os.path.expanduser("~/.pqc_transfer_keys")
    os.makedirs(key_dir, exist_ok=True)
    id_file = os.path.join(key_dir, "client_id.txt")
    if os.path.exists(id_file):
        with open(id_file, "r") as f:
            return f.read().strip()
    else:
        client_id = str(uuid.uuid4())
        with open(id_file, "w") as f:
            f.write(client_id)
        return client_id
