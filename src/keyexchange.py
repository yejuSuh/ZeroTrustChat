import os
import socket
import time
import secrets
from Crypto.Hash import SHA256

G = 2
P = int(
    "00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6ce"
    "dcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b940"
    "9e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaec"
    "ae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb306"
    "0b",
    16,
)


class DHKeyExchange:
    KEY_EXPIRY_SECONDS = 3600

    def __init__(self):
        self.private_key: int = None
        self.public_key: int = None
        self.shared_secret: int = None
        self.session_id: str = None
        self.K_conf: bytes = None
        self.K_auth: bytes = None
        self.created_at: float = None

    def generate_keypair(self) -> bytes:
        self.private_key = secrets.randbelow(P - 1) + 1
        self.public_key = pow(G, self.private_key, P)
        self.session_id = os.urandom(16).hex()
        return (str(self.public_key) + "\n").encode("utf-8")

    def compute_shared_secret(self, peer_public_key_bytes: bytes):
        peer_public_key = int(peer_public_key_bytes.decode("utf-8").strip())
        self.shared_secret = pow(peer_public_key, self.private_key, P)
        self._kdf(self.shared_secret)
        self.created_at = time.time()

    def _kdf(self, shared_secret: int):
        secret_bytes = str(shared_secret).encode()
        h_conf = SHA256.new()
        h_conf.update(secret_bytes + b"confidentiality")
        self.K_conf = h_conf.digest()

        h_auth = SHA256.new()
        h_auth.update(secret_bytes + b"authenticity")
        self.K_auth = h_auth.digest()

    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.KEY_EXPIRY_SECONDS

    def perform_exchange(self, sock: socket.socket) -> tuple[bytes, bytes]:
        sock.sendall(self.generate_keypair())

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed during key exchange")
            data += chunk

        self.compute_shared_secret(data.split(b"\n")[0])
        return (self.K_conf, self.K_auth)
