import argparse
import base64
import os
import select
import socket
import time


class KeyDirectory:
    def __init__(self, port: int = 9998):
        self.port = port
        self.directory = {}  # { node_id: { "pubkey_pem": str, "registered_at": float } }
        self.cache_dir = "keys/peers/"
        os.makedirs(self.cache_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def start_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", self.port))
        server_sock.listen(10)
        server_sock.setblocking(False)
        print(f"[*] KeyDirectory listening on :{self.port}")

        client_bufs = {}  # socket → accumulated read buffer
        inputs = [server_sock]

        try:
            while True:
                readable, _, exceptional = select.select(inputs, [], inputs, 1.0)

                for s in readable:
                    if s is server_sock:
                        conn, addr = server_sock.accept()
                        conn.setblocking(False)
                        inputs.append(conn)
                        client_bufs[conn] = b""
                    else:
                        try:
                            chunk = s.recv(4096)
                        except OSError:
                            chunk = b""
                        if not chunk:
                            self._close_client(s, inputs, client_bufs)
                            continue

                        client_bufs[s] += chunk
                        if b"\n" in client_bufs[s]:
                            line, remainder = client_bufs[s].split(b"\n", 1)
                            client_bufs[s] = remainder
                            response = self._handle_command(
                                line.decode("utf-8", errors="replace").strip()
                            )
                            try:
                                s.sendall((response + "\n").encode())
                            except OSError:
                                pass
                            self._close_client(s, inputs, client_bufs)

                for s in exceptional:
                    self._close_client(s, inputs, client_bufs)

        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
        finally:
            server_sock.close()

    def _handle_command(self, line: str) -> str:
        parts = line.split(" ", 2)
        cmd = parts[0].upper() if parts else ""

        if cmd == "REGISTER" and len(parts) == 3:
            node_id = parts[1]
            try:
                pubkey_pem = base64.b64decode(parts[2])
            except Exception:
                return "ERROR"
            self.directory[node_id] = {
                "pubkey_pem": pubkey_pem.decode(),
                "registered_at": time.time(),
            }
            self._cache_key(node_id, pubkey_pem)
            return "OK"

        if cmd == "LOOKUP" and len(parts) == 2:
            node_id = parts[1]
            entry = self.directory.get(node_id)
            if entry is None:
                return "NOTFOUND"
            encoded = base64.b64encode(entry["pubkey_pem"].encode()).decode()
            return encoded

        return "ERROR"

    @staticmethod
    def _close_client(sock, inputs, bufs):
        if sock in inputs:
            inputs.remove(sock)
        bufs.pop(sock, None)
        try:
            sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Client-side API
    # ------------------------------------------------------------------

    def register(
        self,
        node_id: str,
        pubkey_pem: bytes,
        directory_host: str,
        directory_port: int,
    ):
        encoded = base64.b64encode(pubkey_pem).decode()
        cmd = f"REGISTER {node_id} {encoded}\n"
        with socket.create_connection((directory_host, directory_port)) as s:
            s.sendall(cmd.encode())
            response = self._recv_line(s)
        if response != "OK":
            raise RuntimeError(f"Registration failed: {response!r}")

    def lookup(
        self,
        node_id: str,
        directory_host: str,
        directory_port: int,
    ) -> "bytes | None":
        cache_path = os.path.join(self.cache_dir, f"{node_id}.pem")
        if os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                return f.read()

        cmd = f"LOOKUP {node_id}\n"
        with socket.create_connection((directory_host, directory_port)) as s:
            s.sendall(cmd.encode())
            response = self._recv_line(s)

        if response == "NOTFOUND":
            return None

        try:
            pubkey_pem = base64.b64decode(response)
        except Exception:
            return None

        self._cache_key(node_id, pubkey_pem)
        return pubkey_pem

    def _cache_key(self, node_id: str, pubkey_pem: bytes):
        path = os.path.join(self.cache_dir, f"{node_id}.pem")
        with open(path, "wb") as f:
            f.write(pubkey_pem)

    @staticmethod
    def _recv_line(sock: socket.socket) -> str:
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.split(b"\n", 1)[0].decode().strip()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Trust Key Directory")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--start", action="store_true", help="Start directory server")
    mode.add_argument("--register", action="store_true", help="Register a public key")
    mode.add_argument("--lookup", action="store_true", help="Look up a public key")
    parser.add_argument("--port", type=int, default=9998, help="Directory port")
    parser.add_argument("--host", default="127.0.0.1", help="Directory host")
    parser.add_argument("--node-id", help="Node ID")
    parser.add_argument("--pubkey", help="Path to public key PEM file")
    args = parser.parse_args()

    kd = KeyDirectory(port=args.port)

    if args.start:
        kd.start_server()

    elif args.register:
        if not args.node_id or not args.pubkey:
            parser.error("--register requires --node-id and --pubkey")
        with open(args.pubkey, "rb") as f:
            pem = f.read()
        kd.register(args.node_id, pem, args.host, args.port)
        print("Registered.")

    elif args.lookup:
        if not args.node_id:
            parser.error("--lookup requires --node-id")
        pem = kd.lookup(args.node_id, args.host, args.port)
        if pem is None:
            print("NOTFOUND")
        else:
            print(pem.decode())
