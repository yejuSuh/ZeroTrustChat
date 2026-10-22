# Zero-Trust Secure Chat Network

A peer-to-peer chat network built on zero-trust security principles: every connection is mutually authenticated, all traffic is end-to-end encrypted, and every security event is logged to a tamper-evident audit trail.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Node                             │
│  stdin → send()  →  Identity.sign  →  SecureChannel     │
│  recv()  ←  Identity.verify  ←  SecureChannel           │
│                  ↕ TCP socket                           │
└─────────────────────────────────────────────────────────┘
        ↕ REGISTER / LOOKUP
┌──────────────────┐          ┌──────────────────┐
│   KeyDirectory   │          │    AuditLog      │
│   (port 9998)    │          │  (logs/audit.log)│
└──────────────────┘          └──────────────────┘
```

| Module | Purpose |
|---|---|
| `node.py` | TCP networking layer; server, client, and relay modes |
| `keyexchange.py` | Diffie-Hellman key exchange; derives `K_conf` and `K_auth` |
| `securechannel.py` | AES-CBC encryption + HMAC-SHA256 authentication per message |
| `identity.py` | RSA-4096 key generation, message signing, and verification |
| `keydirectory.py` | Central public-key registry; register and look up peer keys |
| `guardian.py` | Port-scan detection daemon and authorized port scanner |
| `auditlog.py` | Hash-chained, optionally signed JSON audit log |

## Security Model

- **Key exchange** — Diffie-Hellman over a 512-bit prime. Each connection derives two independent 256-bit keys: one for confidentiality (`K_conf`) and one for authenticity (`K_auth`). Session keys expire after one hour.
- **Encryption** — AES-128-CBC with a random IV per message. The plaintext length is independently encrypted to prevent length oracle attacks.
- **Integrity** — Each ciphertext carries two HMAC-SHA256 tags: one over the session header and IV, one over the encrypted body. Tags are compared in constant time.
- **Replay protection** — Each message carries a sequence number; the receiver rejects any sequence number it has seen before.
- **Message authentication** — Messages are signed with RSA-4096 / PKCS#1 v1.5 before encryption. Signers are identified by a SHA-256 fingerprint of their public key.
- **Audit log** — Every security event (key exchange, HMAC failure, replay, port scan, …) is written as a JSON entry that chains to the previous entry via SHA-256. Entries may also carry an RSA signature so the chain cannot be silently rewritten.

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`scapy` (required by `guardian.py --detect`) needs raw socket access. On Linux, run with `sudo` or grant `CAP_NET_RAW`. On macOS, run with `sudo`.

## Quick Start

### 1. Generate an identity keypair

```bash
python -m src.identity --genkey
# Prints the SHA-256 fingerprint of the new public key.
# Keys are written to keys/myprivkey.pem and keys/mypubkey.pem
```

### 2. Start the key directory (optional but recommended)

```bash
python -m src.keydirectory --start          # default port 9998
```

### 3. Start a server node

```bash
python -m src.node --s
# Listening on :9999
```

### 4. Connect a client

```bash
python -m src.node --c 127.0.0.1
# Type messages and press Enter to send.
```

Type in either terminal; messages appear as `[Peer]: ...` on the other side. Press `Ctrl-C` to disconnect.

## CLI Reference

### node.py

```
python -m src.node --s                  # server mode (listens on :9999)
python -m src.node --c <host>           # client mode
python -m src.node --id <id>            # set an explicit node ID
```

### identity.py

```
python -m src.identity --genkey
python -m src.identity --fingerprint
python -m src.identity --node-id <id>   # default: "node"
```

### keydirectory.py

```
python -m src.keydirectory --start [--port 9998]
python -m src.keydirectory --register --node-id <id> --pubkey keys/mypubkey.pem --host 127.0.0.1
python -m src.keydirectory --lookup  --node-id <id>  --host 127.0.0.1
```

### guardian.py

```
sudo python -m src.guardian --detect [--interface lo]   # requires CAP_NET_RAW
     python -m src.guardian --scan <host> [--ports 1-1024]
```

Scan reports are written to `logs/scan_<host>_<timestamp>.txt`. Port-scan alerts are appended to `logs/alerts.txt`.

## Running Tests

```bash
pytest
```

## File Layout

```
src/
  node.py           # networking + message loop
  keyexchange.py    # Diffie-Hellman
  securechannel.py  # AES-CBC + HMAC
  identity.py       # RSA signing / verification
  keydirectory.py   # public-key registry
  guardian.py       # scan detection / authorized scanner
  auditlog.py       # hash-chained audit log

tests/
  test_securechannel.py
  test_identity.py
  test_auditlog.py
  test_keyexchange.py

keys/               # generated key material (gitignored)
logs/               # audit.log, scan reports, alerts (gitignored)
```

## Dependencies

| Package | Use |
|---|---|
| `pycryptodome >= 3.20` | AES, HMAC-SHA256, RSA, SHA-256 |
| `scapy >= 2.5` | Packet sniffing for scan detection |
| `pytest >= 8.0` | Test runner |
