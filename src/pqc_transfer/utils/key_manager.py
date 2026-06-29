import os
import stat
import threading
import uuid

import oqs

from . import logger


class KeyStore:
    """
    서명 키쌍(공개키/비밀키)의 생성, 로컬 디스크 저장, 메모리 로드를 전담하는 클래스입니다.
    단일 책임 원칙(SRP)을 준수합니다.
    """

    def __init__(self, key_dir: str, sig_alg: str):
        self._key_dir = key_dir
        self.sig_alg = sig_alg
        self._server_sig_lock = threading.Lock()
        self._server_sig_pk = None
        self._server_sig_sk = None

        self._client_sig_lock = threading.Lock()
        self._client_sig_pk = None
        self._client_sig_sk = None
        os.makedirs(self._key_dir, exist_ok=True)

    def _get_or_generate_sig_keys(self, prefix: str) -> tuple[bytes, bytes]:
        sig_sec_file = os.path.join(self._key_dir, f"{prefix}_sig_sec.bin")
        sig_pub_file = os.path.join(self._key_dir, f"{prefix}_sig_pub.bin")

        if os.path.exists(sig_sec_file) and os.path.exists(sig_pub_file):
            with open(sig_sec_file, "rb") as f:
                sk = f.read()
            with open(sig_pub_file, "rb") as f:
                pk = f.read()
        else:
            with oqs.Signature(self.sig_alg) as signer:
                pk = signer.generate_keypair()
                sk = signer.export_secret_key()

            fd = os.open(
                sig_sec_file,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            with os.fdopen(fd, "wb") as f:
                f.write(sk)

            with open(sig_pub_file, "wb") as f:
                f.write(pk)

        return pk, sk

    def get_server_sig_keys(self) -> tuple[bytes, bytes]:
        if self._server_sig_pk is not None:
            return self._server_sig_pk, self._server_sig_sk
        with self._server_sig_lock:
            if self._server_sig_pk is not None:
                return self._server_sig_pk, self._server_sig_sk
            self._server_sig_pk, self._server_sig_sk = self._get_or_generate_sig_keys(
                "server"
            )
            return self._server_sig_pk, self._server_sig_sk

    def get_client_sig_keys(self) -> tuple[bytes, bytes]:
        if self._client_sig_pk is not None:
            return self._client_sig_pk, self._client_sig_sk
        with self._client_sig_lock:
            if self._client_sig_pk is not None:
                return self._client_sig_pk, self._client_sig_sk
            self._client_sig_pk, self._client_sig_sk = self._get_or_generate_sig_keys(
                "client"
            )
            return self._client_sig_pk, self._client_sig_sk


class TrustStore:
    """
    TOFU(Trust On First Use) 기반의 신뢰할 수 있는 공개키 목록을 디스크에 저장 및 관리하는 클래스입니다.
    단일 책임 원칙(SRP)을 준수합니다.
    """

    def __init__(self, key_dir: str):
        self._key_dir = key_dir
        self._tofu_lock = threading.Lock()
        self._trusted_keys = {}
        os.makedirs(self._key_dir, exist_ok=True)

    def verify_and_trust_client(self, client_id: str, sig_public_key: bytes) -> bool:
        trusted_client_file = os.path.join(
            self._key_dir, f"trusted_client_sig_{client_id}.bin"
        )
        with self._tofu_lock:
            if client_id in self._trusted_keys:
                trusted_pub = self._trusted_keys[client_id]
                if trusted_pub != sig_public_key:
                    return False
            else:
                if os.path.exists(trusted_client_file):
                    with open(trusted_client_file, "rb") as f:
                        trusted_pub = f.read()
                    if trusted_pub != sig_public_key:
                        return False
                    self._trusted_keys[client_id] = trusted_pub
                else:
                    with open(trusted_client_file, "wb") as f:
                        f.write(sig_public_key)
                    self._trusted_keys[client_id] = sig_public_key
                    logger.log(
                        "INFO",
                        "VERIFY",
                        f"새로운 클라이언트({client_id[:8]}) 공개키를 신뢰 목록에 등록했습니다 (TOFU)",
                    )
        return True

    def verify_and_trust_server(self, server_ip: str, server_sig_pk: bytes) -> bool:
        trusted_server_file = os.path.join(
            self._key_dir, f"trusted_server_sig_{server_ip}.bin"
        )
        if os.path.exists(trusted_server_file):
            with open(trusted_server_file, "rb") as f:
                trusted_pub = f.read()
            if trusted_pub != server_sig_pk:
                return False
        else:
            with open(trusted_server_file, "wb") as f:
                f.write(server_sig_pk)
            logger.log(
                "INFO",
                "VERIFY",
                "새로운 서버의 서명 공개키를 신뢰 목록에 등록했습니다 (TOFU)",
            )
        return True


class IdentityManager:
    """
    클라이언트 고유 식별자(Client ID) 생성을 전담하는 클래스입니다.
    단일 책임 원칙(SRP)을 준수합니다.
    """

    def __init__(self, key_dir: str):
        self._key_dir = key_dir
        os.makedirs(self._key_dir, exist_ok=True)

    def get_client_id(self) -> str:
        id_file = os.path.join(self._key_dir, "client_id.txt")
        if os.path.exists(id_file):
            with open(id_file, "r") as f:
                return f.read().strip()
        else:
            client_id = str(uuid.uuid4())
            with open(id_file, "w") as f:
                f.write(client_id)
            return client_id


class KeyManager:
    """
    PQC 서명 키 및 클라이언트/서버 신원 정보를 통합 관리하는 파사드(Facade) 클래스입니다.

    실제 파일 입출력 및 메모리 관리 로직은 내부의 KeyStore, TrustStore, IdentityManager로 위임하여
    코드의 결합도를 낮추고 응집도를 높였습니다.
    """

    def __init__(self, key_dir: str, sig_alg: str):
        self._key_store = KeyStore(key_dir, sig_alg)
        self._trust_store = TrustStore(key_dir)
        self._identity_manager = IdentityManager(key_dir)

    def get_server_sig_keys(self) -> tuple[bytes, bytes]:
        return self._key_store.get_server_sig_keys()

    def get_client_sig_keys(self) -> tuple[bytes, bytes]:
        return self._key_store.get_client_sig_keys()

    def verify_and_trust_client(self, client_id: str, sig_public_key: bytes) -> bool:
        return self._trust_store.verify_and_trust_client(client_id, sig_public_key)

    def verify_and_trust_server(self, server_ip: str, server_sig_pk: bytes) -> bool:
        return self._trust_store.verify_and_trust_server(server_ip, server_sig_pk)

    def get_client_id(self) -> str:
        return self._identity_manager.get_client_id()
