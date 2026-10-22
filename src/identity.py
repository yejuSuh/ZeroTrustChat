import argparse
import binascii
import os
import struct

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class SignatureError(Exception):
    pass


class Identity:
    def __init__(self, node_id: str, keys_dir: str = "keys/"):
        self.node_id = node_id
        self.keys_dir = keys_dir
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        key = RSA.generate(4096)
        os.makedirs(self.keys_dir, exist_ok=True)

        priv_path = os.path.join(self.keys_dir, "myprivkey.pem")
        pub_path = os.path.join(self.keys_dir, "mypubkey.pem")

        with open(priv_path, "wb") as f:
            f.write(key.export_key("PEM"))
        os.chmod(priv_path, 0o600)

        with open(pub_path, "wb") as f:
            f.write(key.publickey().export_key("PEM"))

        self.private_key = key
        self.public_key = key.publickey()

        print(self.get_fingerprint())

    def load_keys(self):
        priv_path = os.path.join(self.keys_dir, "myprivkey.pem")
        pub_path = os.path.join(self.keys_dir, "mypubkey.pem")

        if not os.path.exists(priv_path) or not os.path.exists(pub_path):
            raise FileNotFoundError("Keys not found. Run --genkey first.")

        with open(priv_path, "rb") as f:
            self.private_key = RSA.import_key(f.read())
        with open(pub_path, "rb") as f:
            self.public_key = RSA.import_key(f.read())

    def sign(self, message: bytes) -> bytes:
        h = SHA256.new(message)
        return pkcs1_15.new(self.private_key).sign(h)

    def verify(self, message: bytes, signature: bytes, peer_pubkey) -> bool:
        h = SHA256.new(message)
        try:
            pkcs1_15.new(peer_pubkey).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def get_fingerprint(self) -> str:
        der = self.public_key.export_key("DER")
        digest = SHA256.new(der).digest()
        pairs = [f"{b:02X}" for b in digest]
        return ":".join(pairs[:8])

    def export_public_key(self) -> bytes:
        return self.public_key.export_key("PEM")

    def sign_message_packet(self, plaintext: bytes) -> bytes:
        signature = self.sign(plaintext)
        signature_hex = binascii.hexlify(signature)
        return (
            struct.pack(">I", len(plaintext))
            + plaintext
            + struct.pack(">I", len(signature_hex))
            + signature_hex
        )

    def verify_message_packet(self, packet: bytes, peer_pubkey) -> bytes:
        offset = 0

        msg_len = struct.unpack(">I", packet[offset:offset + 4])[0]
        offset += 4

        plaintext = packet[offset:offset + msg_len]
        offset += msg_len

        sig_len = struct.unpack(">I", packet[offset:offset + 4])[0]
        offset += 4

        signature_hex = packet[offset:offset + sig_len]
        signature = binascii.unhexlify(signature_hex)

        if not self.verify(plaintext, signature, peer_pubkey):
            raise SignatureError(
                "ERROR: Signature verification failed — message may be forged"
            )

        return plaintext


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Identity key management")
    parser.add_argument("--genkey", action="store_true", help="Generate a new keypair")
    parser.add_argument("--fingerprint", action="store_true", help="Print public key fingerprint")
    parser.add_argument("--node-id", default="node", help="Node identifier")
    args = parser.parse_args()

    identity = Identity(args.node_id)

    if args.genkey:
        identity.generate_keypair()
    elif args.fingerprint:
        identity.load_keys()
        print(identity.get_fingerprint())
