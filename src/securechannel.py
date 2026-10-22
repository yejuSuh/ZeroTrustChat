import struct

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AuthenticationError(Exception):
    pass


class ReplayError(Exception):
    pass


class SessionMismatchError(Exception):
    pass


class SecureChannel:
    def __init__(self, K_conf: bytes, K_auth: bytes, session_id: str):
        self.K_conf = K_conf
        self.K_auth = K_auth
        self.session_id = session_id
        self.send_seq = 0
        self.recv_seen = set()

    def encrypt_message(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(16)

        length_block = struct.pack('>I', len(plaintext))
        enc_length = AES.new(self.K_conf, AES.MODE_CBC, iv).encrypt(pad(length_block, AES.block_size))
        enc_message = AES.new(self.K_conf, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))

        session_id_bytes = bytes.fromhex(self.session_id)
        seq_bytes = struct.pack('>I', self.send_seq)

        hmac1 = self._hmac(session_id_bytes + iv + enc_length)
        hmac2 = self._hmac(enc_message)

        self.send_seq += 1

        return (
            session_id_bytes
            + seq_bytes
            + iv
            + enc_length
            + hmac1
            + enc_message
            + hmac2
        )

    def decrypt_message(self, packet: bytes) -> bytes:
        offset = 0

        session_id_bytes = packet[offset:offset + 16]
        offset += 16

        seq_bytes = packet[offset:offset + 4]
        seq_num = struct.unpack('>I', seq_bytes)[0]
        offset += 4

        iv = packet[offset:offset + 16]
        offset += 16

        enc_length = packet[offset:offset + 16]
        offset += 16

        hmac1 = packet[offset:offset + 32]
        offset += 32

        enc_message = packet[offset:len(packet) - 32]
        hmac2 = packet[len(packet) - 32:]

        if session_id_bytes != bytes.fromhex(self.session_id):
            raise SessionMismatchError("Session ID mismatch")

        if seq_num in self.recv_seen:
            raise ReplayError(f"Duplicate sequence number: {seq_num}")

        expected_hmac1 = self._hmac(session_id_bytes + iv + enc_length)
        if not self._constant_compare(hmac1, expected_hmac1):
            raise AuthenticationError("ERROR: HMAC verification failed")

        length_plaintext = unpad(AES.new(self.K_conf, AES.MODE_CBC, iv).decrypt(enc_length), AES.block_size)
        original_length = struct.unpack('>I', length_plaintext)[0]

        expected_hmac2 = self._hmac(enc_message)
        if not self._constant_compare(hmac2, expected_hmac2):
            raise AuthenticationError("ERROR: HMAC verification failed")

        plaintext = unpad(AES.new(self.K_conf, AES.MODE_CBC, iv).decrypt(enc_message), AES.block_size)
        plaintext = plaintext[:original_length]

        self.recv_seen.add(seq_num)

        return plaintext

    def _hmac(self, data: bytes) -> bytes:
        h = HMAC.new(self.K_auth, data, SHA256)
        return h.digest()

    @staticmethod
    def _constant_compare(a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
