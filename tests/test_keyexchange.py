import time
import socket
import threading

from src.keyexchange import DHKeyExchange


def test_keypair_generation():
    dh = DHKeyExchange()
    pub_bytes = dh.generate_keypair()

    assert isinstance(dh.public_key, int)
    assert dh.public_key > 1
    assert isinstance(dh.session_id, str)
    assert len(dh.session_id) == 32
    assert all(c in "0123456789abcdef" for c in dh.session_id)
    assert pub_bytes.endswith(b"\n")


def test_shared_secret_matches():
    alice = DHKeyExchange()
    bob = DHKeyExchange()

    alice_pub = alice.generate_keypair()
    bob_pub = bob.generate_keypair()

    alice.compute_shared_secret(bob_pub)
    bob.compute_shared_secret(alice_pub)

    assert alice.shared_secret == bob.shared_secret
    assert alice.K_conf == bob.K_conf
    assert alice.K_auth == bob.K_auth


def test_keys_are_independent():
    alice = DHKeyExchange()
    bob = DHKeyExchange()

    alice.generate_keypair()
    alice.compute_shared_secret(bob.generate_keypair())

    assert alice.K_conf != alice.K_auth
    assert len(alice.K_conf) == 32
    assert len(alice.K_auth) == 32


def test_key_expiry():
    dh = DHKeyExchange()
    dh.generate_keypair()
    dh.created_at = time.time() - 7200

    assert dh.is_expired() is True

    dh.created_at = time.time()
    assert dh.is_expired() is False


def test_perform_exchange_via_loopback():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    bob = DHKeyExchange()
    bob_result = {}
    bob_error = {}

    def server_side():
        try:
            conn, _ = server_sock.accept()
            with conn:
                bob_result["keys"] = bob.perform_exchange(conn)
        except Exception as exc:
            bob_error["exc"] = exc

    thread = threading.Thread(target=server_side, daemon=True)
    thread.start()

    alice = DHKeyExchange()
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with client_sock:
        client_sock.connect(("127.0.0.1", port))
        alice_keys = alice.perform_exchange(client_sock)

    thread.join(timeout=5)
    server_sock.close()

    if "exc" in bob_error:
        raise bob_error["exc"]

    assert "keys" in bob_result, "server thread did not complete"
    assert alice_keys[0] == bob_result["keys"][0], "K_conf mismatch"
    assert alice_keys[1] == bob_result["keys"][1], "K_auth mismatch"
    assert alice.K_conf == bob.K_conf
