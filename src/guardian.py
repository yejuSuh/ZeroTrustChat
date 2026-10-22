import argparse
import os
import random
import socket
import time

from .auditlog import EVENT_SCAN_DETECTED

try:
    from scapy.all import sniff, IP, TCP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


class Guardian:
    def __init__(self, interface: str = "lo", audit_log=None):
        self.interface = interface
        self.audit_log = audit_log
        self.connection_log = {}  # { source_ip: [(port, timestamp), ...] }
        self.known_peers = set()
        self.WINDOW_SECONDS = 300
        self.CONSECUTIVE_THRESHOLD = 15

    # ------------------------------------------------------------------
    # Detection daemon (requires sudo / CAP_NET_RAW)
    # ------------------------------------------------------------------

    def start_detection(self):
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("scapy is not installed; cannot start detection")
        print(f"[*] Sniffing on {self.interface} for TCP SYN packets ...")
        sniff(
            iface=self.interface,
            filter="tcp",
            prn=self._process_packet,
            store=False,
        )

    def _process_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        if pkt[TCP].flags != "S":
            return

        source_ip = pkt[IP].src
        dest_port = pkt[TCP].dport
        now = time.time()

        log = self.connection_log.setdefault(source_ip, [])
        log.append((dest_port, now))

        cutoff = now - self.WINDOW_SECONDS
        self.connection_log[source_ip] = [(p, t) for p, t in log if t >= cutoff]

        self._check_for_scan(source_ip)

    def _check_for_scan(self, source_ip: str):
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        ports = [
            p for p, t in self.connection_log.get(source_ip, []) if t >= cutoff
        ]

        if not self._is_consecutive(ports):
            return

        severity = (
            "COMPROMISED_NODE_SCAN" if source_ip in self.known_peers else "EXTERNAL_SCAN"
        )

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        alert_line = f"[{timestamp}] ALERT: Port scan detected from {source_ip}\n"

        os.makedirs("logs", exist_ok=True)
        with open("logs/alerts.txt", "a") as f:
            f.write(alert_line)

        if self.audit_log:
            self.audit_log.log(EVENT_SCAN_DETECTED, {
                "source_ip": source_ip,
                "severity": severity,
            })

        # Clear to avoid duplicate alerts for the same burst
        self.connection_log[source_ip] = []

    # ------------------------------------------------------------------
    # Authorized port scanner
    # ------------------------------------------------------------------

    def scan(self, target: str, port_range: tuple = (0, 65535)) -> list:
        start_port, end_port = port_range
        ports = list(range(start_port, end_port + 1))
        random.shuffle(ports)

        open_ports = []
        t_start = time.time()

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "NA"
                open_ports.append((port, service))
            sock.close()

        t_end = time.time()
        elapsed = t_end - t_start
        n_scanned = len(ports)
        per_scan = elapsed / n_scanned if n_scanned else 0.0

        timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        os.makedirs("logs", exist_ok=True)
        report_path = f"logs/scan_{target}_{timestamp}.txt"
        with open(report_path, "w") as f:
            for port, service in sorted(open_ports):
                f.write(f"{port} ({service}) was open\n")
            f.write(f"time elapsed = {elapsed:.1f}s\n")
            f.write(f"time per scan = {per_scan:.4f}s\n")

        return open_ports

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_consecutive(self, ports: list) -> bool:
        if len(ports) < self.CONSECUTIVE_THRESHOLD:
            return False
        unique = sorted(set(ports))
        run = 1
        for i in range(1, len(unique)):
            if unique[i] == unique[i - 1] + 1:
                run += 1
                if run >= self.CONSECUTIVE_THRESHOLD:
                    return True
            else:
                run = 1
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Trust Guardian")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--detect", action="store_true", help="Start detection daemon (requires sudo)")
    mode.add_argument("--scan", metavar="target", help="Scan target host")
    parser.add_argument("--interface", default="lo", help="Network interface for detection")
    parser.add_argument("--ports", metavar="START-END", help="Port range, e.g. 1-1024")
    args = parser.parse_args()

    if args.detect:
        Guardian(interface=args.interface).start_detection()
    else:
        port_range = (0, 65535)
        if args.ports:
            lo, hi = args.ports.split("-")
            port_range = (int(lo), int(hi))
        results = Guardian().scan(args.scan, port_range)
        for port, service in sorted(results):
            print(f"  {port:5d}  {service}")
