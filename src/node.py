import argparse
import select
import socket
import struct
import sys
import time
import uuid

from Crypto.Hash import SHA256

from .keyexchange import DHKeyExchange
from .securechannel import SecureChannel, AuthenticationError, ReplayError
from .auditlog import (
    AuditLog,
    EVENT_KEY_EXCHANGE_OK,
    EVENT_KEY_EXCHANGE_FAIL,
    EVENT_MSG_SENT,
    EVENT_MSG_RECEIVED,
    EVENT_HMAC_FAILURE,
    EVENT_REPLAY_DETECTED,
    EVENT_PEER_CONNECTED,
    EVENT_PEER_DISCONNECTED,
)

MSG_PING      = 0x01
MSG_PONG      = 0x02
MSG_HANDSHAKE = 0x03
MSG_DATA      = 0x04
MSG_ROUTE     = 0x05
MSG_ERROR     = 0x06

_HEADER_SIZE = 4 + 1 + 16  # total_len(4) + msg_type(1) + session_id(16)


class Node:
    def __init__(
        self,
        mode: str,
        hostname: str = None,
        port: int = 9999,
        node_id: str = None,
        identity=None,
        audit_log=None,
    ):
        self.mode = mode
        self.hostname = hostname
        self.port = port
        self.node_id = node_id or uuid.uuid4().hex
        self.identity = identity
        self.audit_log = audit_log

        # { node_id: { "socket": sock, "address": (host, port),
        #              "last_seen": float, "session_ids": [] } }
        self.routing_table = {}

        # { session_id: { "channel": SecureChannel, "peer_id": str,
        #                 "peer_pubkey": ... } }
        self.sessions = {}

        self._sock_to_session = {}  # fileno → session_id
        self._server_sock = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        inputs = [sys.stdin]

        if self.mode in ("server", "relay"):
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("", self.port))
            self._server_sock.listen(5)
            inputs.append(self._server_sock)
            print(f"[*] Listening on :{self.port}")

        if self.mode in ("client", "relay"):
            host = self.hostname or "127.0.0.1"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, self.port))
            session_id = self._perform_handshake(sock)
            self._register_peer(sock, session_id, (host, self.port))
            print(f"[*] Connected to {host}:{self.port}  session={session_id[:8]}")

        try:
            last_heartbeat = time.time()
            while True:
                now = time.time()
                if now - last_heartbeat > 30:
                    self.send_heartbeat()
                    last_heartbeat = now

                peer_socks = [p["socket"] for p in self.routing_table.values()]
                watch = inputs + peer_socks
                try:
                    readable, _, exceptional = select.select(watch, [], watch, 1.0)
                except (ValueError, OSError):
                    break

                for s in readable:
                    if s is sys.stdin:
                        line = sys.stdin.readline()
                        if not line:
                            raise KeyboardInterrupt
                        text = line.rstrip("\r\n")
                        if text and self.sessions:
                            for sid in list(self.sessions.keys()):
                                try:
                                    self.send(text.encode("utf-8"), sid)
                                except Exception as e:
                                    print(f"[!] Send error ({sid[:8]}): {e}")

                    elif s is self._server_sock:
                        conn, addr = self._server_sock.accept()
                        try:
                            session_id = self._perform_handshake(conn)
                            self._register_peer(conn, session_id, addr)
                            print(f"[+] {addr[0]}:{addr[1]}  session={session_id[:8]}")
                        except Exception as e:
                            print(f"[!] Handshake failed from {addr}: {e}")
                            if self.audit_log:
                                self.audit_log.log(EVENT_KEY_EXCHANGE_FAIL, {
                                    "address": f"{addr[0]}:{addr[1]}",
                                    "error": str(e),
                                })
                            conn.close()

                    else:
                        session_id = self._sock_to_session.get(s.fileno())
                        if session_id is None:
                            continue
                        try:
                            msg_type, recv_sid, payload = self._recv_envelope(s)
                            self._handle_message(s, msg_type, recv_sid, payload, session_id)
                        except (ConnectionError, OSError, struct.error):
                            print(f"[-] Peer disconnected  session={session_id[:8]}")
                            self._remove_peer(s)

                for s in exceptional:
                    self._remove_peer(s)

        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        finally:
            self._cleanup()

    def send(self, plaintext: bytes, session_id: str):
        session = self.sessions[session_id]
        channel = session["channel"]

        signed = (
            self.identity.sign_message_packet(plaintext)
            if self.identity is not None
            else plaintext
        )
        encrypted = channel.encrypt_message(signed)

        sock = self._get_sock_for_session(session_id)
        if sock is None:
            raise RuntimeError(f"No socket for session {session_id}")
        self._send_envelope(sock, MSG_DATA, session_id, encrypted)

        if self.audit_log:
            self.audit_log.log(EVENT_MSG_SENT, {
                "session_id": session_id,
                "length": len(plaintext),
            })

    def _perform_handshake(self, sock: socket.socket) -> str:
        dh = DHKeyExchange()
        K_conf, K_auth = dh.perform_exchange(sock)

        # Derive a shared session_id deterministically so both sides agree
        # without an additional round-trip.  SHA256(K_conf || K_auth) gives
        # the same 32-hex-char value on both ends of the exchange.
        session_id = SHA256.new(K_conf + K_auth).hexdigest()[:32]

        channel = SecureChannel(K_conf, K_auth, session_id)
        self.sessions[session_id] = {
            "channel": channel,
            "peer_id": None,
            "peer_pubkey": None,
        }

        if self.audit_log:
            self.audit_log.log(EVENT_KEY_EXCHANGE_OK, {"session_id": session_id})

        return session_id

    def _send_envelope(
        self, sock: socket.socket, msg_type: int, session_id: str, payload: bytes
    ):
        session_id_bytes = bytes.fromhex(session_id)
        header = struct.pack(">I", len(payload)) + bytes([msg_type]) + session_id_bytes
        sock.sendall(header + payload)

    def _recv_envelope(self, sock: socket.socket) -> tuple:
        header = self._recv_exact(sock, _HEADER_SIZE)
        total_len = struct.unpack(">I", header[:4])[0]
        msg_type = header[4]
        session_id = header[5:21].hex()
        payload = self._recv_exact(sock, total_len)
        return (msg_type, session_id, payload)

    def send_heartbeat(self):
        now = time.time()
        stale = []

        for node_id, peer in list(self.routing_table.items()):
            if now - peer["last_seen"] > 40:
                stale.append(node_id)
                continue
            for sid in peer["session_ids"]:
                try:
                    self._send_envelope(peer["socket"], MSG_PING, sid, b"")
                except Exception:
                    stale.append(node_id)
                    break

        for node_id in stale:
            peer = self.routing_table.pop(node_id, None)
            if peer:
                try:
                    peer["socket"].close()
                except OSError:
                    pass
                if self.audit_log:
                    self.audit_log.log(EVENT_PEER_DISCONNECTED, {"node_id": node_id})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _register_peer(self, sock: socket.socket, session_id: str, address: tuple):
        node_id = session_id  # placeholder until identity exchange
        self.routing_table[node_id] = {
            "socket": sock,
            "address": address,
            "last_seen": time.time(),
            "session_ids": [session_id],
        }
        self._sock_to_session[sock.fileno()] = session_id
        if self.audit_log:
            self.audit_log.log(EVENT_PEER_CONNECTED, {
                "node_id": node_id,
                "address": f"{address[0]}:{address[1]}",
            })

    def _handle_message(
        self,
        sock: socket.socket,
        msg_type: int,
        recv_sid: str,
        payload: bytes,
        session_id: str,
    ):
        for peer in self.routing_table.values():
            if peer["socket"] is sock:
                peer["last_seen"] = time.time()
                break

        if msg_type == MSG_PING:
            self._send_envelope(sock, MSG_PONG, session_id, b"")

        elif msg_type == MSG_PONG:
            pass  # last_seen updated above

        elif msg_type == MSG_DATA:
            session = self.sessions.get(session_id)
            if session is None:
                return
            channel = session["channel"]
            try:
                decrypted = channel.decrypt_message(payload)
                peer_pubkey = session.get("peer_pubkey")
                if self.identity is not None and peer_pubkey is not None:
                    plaintext = self.identity.verify_message_packet(decrypted, peer_pubkey)
                else:
                    plaintext = decrypted
                print(f"[Peer]: {plaintext.decode('utf-8', errors='replace')}")
                if self.audit_log:
                    self.audit_log.log(EVENT_MSG_RECEIVED, {
                        "session_id": session_id,
                        "length": len(plaintext),
                    })
            except AuthenticationError as e:
                print(f"[!] HMAC failure: {e}")
                if self.audit_log:
                    self.audit_log.log(EVENT_HMAC_FAILURE, {"session_id": session_id})
            except ReplayError as e:
                print(f"[!] Replay detected: {e}")
                if self.audit_log:
                    self.audit_log.log(EVENT_REPLAY_DETECTED, {"session_id": session_id})
            except Exception as e:
                print(f"[!] Decrypt error: {e}")

        elif msg_type == MSG_ERROR:
            print(f"[!] Peer error: {payload.decode('utf-8', errors='replace')}")

    def _get_sock_for_session(self, session_id: str):
        for peer in self.routing_table.values():
            if session_id in peer["session_ids"]:
                return peer["socket"]
        return None

    def _remove_peer(self, sock: socket.socket):
        session_id = self._sock_to_session.pop(sock.fileno(), None)

        node_id_to_remove = None
        for node_id, peer in self.routing_table.items():
            if peer["socket"] is sock:
                node_id_to_remove = node_id
                break

        if node_id_to_remove:
            self.routing_table.pop(node_id_to_remove)
            if self.audit_log:
                self.audit_log.log(EVENT_PEER_DISCONNECTED, {
                    "node_id": node_id_to_remove,
                })

        if session_id:
            self.sessions.pop(session_id, None)

        try:
            sock.close()
        except OSError:
            pass

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed during recv")
            buf += chunk
        return buf

    def _cleanup(self):
        for peer in list(self.routing_table.values()):
            try:
                peer["socket"].close()
            except OSError:
                pass
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Trust Chat Node")
    parser.add_argument("--s", action="store_true", help="Run as server")
    parser.add_argument("--c", metavar="hostname", help="Connect to host as client")
    parser.add_argument("--id", dest="node_id", help="Node ID")
    args = parser.parse_args()

    if args.s:
        node = Node(mode="server", node_id=args.node_id)
    elif args.c:
        node = Node(mode="client", hostname=args.c, node_id=args.node_id)
    else:
        parser.print_help()
        sys.exit(1)

    node.start()
