import binascii
import datetime
import json
import os
import struct
import time

from Crypto.Hash import SHA256

EVENT_SESSION_START     = "SESSION_START"
EVENT_SESSION_END       = "SESSION_END"
EVENT_KEY_EXCHANGE_OK   = "KEY_EXCHANGE_OK"
EVENT_KEY_EXCHANGE_FAIL = "KEY_EXCHANGE_FAIL"
EVENT_KEY_EXPIRED       = "KEY_EXPIRED"
EVENT_MSG_SENT          = "MESSAGE_SENT"
EVENT_MSG_RECEIVED      = "MESSAGE_RECEIVED"
EVENT_HMAC_FAILURE      = "HMAC_FAILURE"
EVENT_REPLAY_DETECTED   = "REPLAY_DETECTED"
EVENT_SIG_FAILURE       = "SIGNATURE_FAILURE"
EVENT_SCAN_DETECTED     = "SCAN_DETECTED"
EVENT_PEER_CONNECTED    = "PEER_CONNECTED"
EVENT_PEER_DISCONNECTED = "PEER_DISCONNECTED"
EVENT_KEY_REVOKED       = "KEY_REVOKED"


class AuditLog:
    def __init__(self, log_path: str = "logs/audit.log", identity=None):
        self.log_path = log_path
        self.identity = identity
        self.last_hash = "0" * 64

        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        if os.path.exists(log_path):
            last_line = self._read_last_line()
            if last_line:
                try:
                    json.loads(last_line)
                    self.last_hash = SHA256.new(last_line.encode()).hexdigest()
                except (json.JSONDecodeError, KeyError):
                    pass

    def log(self, event_type: str, details: dict):
        entry = {
            "seq":       self._next_seq(),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event":     event_type,
            "details":   details,
            "prev_hash": self.last_hash,
            "signature": None,
        }

        if self.identity is not None:
            unsigned_json = json.dumps(entry, sort_keys=True)
            sig_bytes = self.identity.sign(unsigned_json.encode())
            entry["signature"] = binascii.hexlify(sig_bytes).decode()

        line = json.dumps(entry, sort_keys=True)
        self.last_hash = SHA256.new(line.encode()).hexdigest()

        with open(self.log_path, "a") as f:
            f.write(line + "\n")

    def verify_chain(self) -> bool:
        if not os.path.exists(self.log_path):
            return True

        lines = self._read_lines()
        if not lines:
            return True

        prev_hash = "0" * 64
        valid = True

        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Entry {i}: invalid JSON — {e}")
                valid = False
                continue

            if entry.get("prev_hash") != prev_hash:
                print(f"Entry {i} (seq={entry.get('seq')}): broken hash chain")
                valid = False

            if self.identity is not None and entry.get("signature") is not None:
                sig_hex = entry["signature"]
                check_entry = dict(entry)
                check_entry["signature"] = None
                unsigned_json = json.dumps(check_entry, sort_keys=True)
                try:
                    sig_bytes = binascii.unhexlify(sig_hex)
                    if not self.identity.verify(
                        unsigned_json.encode(), sig_bytes, self.identity.public_key
                    ):
                        print(f"Entry {i} (seq={entry.get('seq')}): signature invalid")
                        valid = False
                except Exception as e:
                    print(f"Entry {i} (seq={entry.get('seq')}): signature error — {e}")
                    valid = False

            prev_hash = SHA256.new(line.encode()).hexdigest()

        return valid

    def tail(self, n: int = 20) -> list:
        lines = self._read_lines()
        result = []
        for line in lines[-n:]:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return result

    def _next_seq(self) -> int:
        last_line = self._read_last_line()
        if not last_line:
            return 0
        try:
            entry = json.loads(last_line)
            return entry["seq"] + 1
        except (json.JSONDecodeError, KeyError):
            return 0

    def _read_last_line(self) -> str:
        if not os.path.exists(self.log_path):
            return ""
        last = ""
        with open(self.log_path, "r") as f:
            for line in f:
                stripped = line.rstrip("\n")
                if stripped:
                    last = stripped
        return last

    def _read_lines(self) -> list:
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path, "r") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
