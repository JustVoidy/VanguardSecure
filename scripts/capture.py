"""
DDoS Detection — Local Capture & Flow Builder
=============================================
Captures packets from a network adapter, tracks bidirectional flows,
computes all 47 features, and sends them to the inference server via HTTP.

Usage:
    sudo python capture.py --iface eth0 --server http://<your-server>:8001
    sudo python capture.py --iface eth0 --server http://<your-server>:8001 --window 5

Requirements:
    pip install scapy requests

Notes:
    - Must be run as root (or with CAP_NET_RAW) to capture packets
    - Server must be running server.py before starting this script
    - Flows originating from this device are automatically ignored
"""

import argparse
import fcntl
import json
import os
import socket
import struct
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

import requests

warnings.filterwarnings("ignore")

_SETTINGS_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.json"


def _load_settings() -> dict:
    try:
        return json.loads(_SETTINGS_PATH.read_text())
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — must match trainer.py and server.py exactly
# ─────────────────────────────────────────────────────────────────────────────

SCAPY_FEATURES = [
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Header Length", "Bwd Header Length",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Destination Port", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Down/Up Ratio",
]

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK HELPERS
# ─────────────────────────────────────────────────────────────────────────────

FlowKey = Tuple[str, str, int, int, int]


def get_local_ip(iface: str) -> str:
    """
    Get the local IPv4 address of the given network interface.
    Uses the SIOCGIFADDR ioctl to read the IP directly from the kernel.
    Returns None if the interface has no IP or the call fails.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface[:15].encode())
        )[20:24])
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# FLOW TRACKING
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """Accumulates per-packet stats for one bidirectional flow."""

    start_time: float = 0.0

    # Forward (attacker → victim) packet data
    fwd_lengths:    List[int]   = field(default_factory=list)
    fwd_timestamps: List[float] = field(default_factory=list)
    fwd_header_len: int         = 0
    init_win_fwd:   int         = -1

    # Backward (victim → attacker) packet data
    bwd_lengths:    List[int]   = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)
    bwd_header_len: int         = 0
    init_win_bwd:   int         = -1

    # TCP flag counts
    fin: int = 0
    syn: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    urg: int = 0

    dst_port: int = 0


def _safe_stats(values: List[float]):
    """Return (max, min, mean, std) or zeros if list is empty."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    import numpy as np
    a = np.array(values, dtype=np.float64)
    return float(a.max()), float(a.min()), float(a.mean()), float(a.std())


def _iat(timestamps: List[float]) -> List[float]:
    """Compute inter-arrival times from a sorted list of timestamps."""
    if len(timestamps) < 2:
        return []
    ts = sorted(timestamps)
    return [ts[i+1] - ts[i] for i in range(len(ts) - 1)]


def extract_features(flow: FlowRecord, duration: float) -> List[float]:
    """
    Convert a FlowRecord into the 47-feature list expected by the server.
    Feature order must match SCAPY_FEATURES exactly.
    """
    dur = max(duration, 1e-6)

    all_lengths = flow.fwd_lengths + flow.bwd_lengths
    all_ts      = flow.fwd_timestamps + flow.bwd_timestamps

    fwd_max, fwd_min, fwd_mean, fwd_std = _safe_stats(flow.fwd_lengths)
    bwd_max, bwd_min, bwd_mean, bwd_std = _safe_stats(flow.bwd_lengths)
    pkt_max, pkt_min, pkt_mean, pkt_std = _safe_stats(all_lengths)
    pkt_var = pkt_std ** 2

    total_fwd_bytes = sum(flow.fwd_lengths)
    total_bwd_bytes = sum(flow.bwd_lengths)
    total_bytes     = total_fwd_bytes + total_bwd_bytes
    total_pkts      = len(all_lengths)
    fwd_pkts        = len(flow.fwd_lengths)
    bwd_pkts        = len(flow.bwd_lengths)

    flow_bytes_s = total_bytes / dur
    flow_pkts_s  = total_pkts  / dur
    fwd_pkts_s   = fwd_pkts    / dur
    bwd_pkts_s   = bwd_pkts    / dur

    flow_iats = _iat(all_ts)
    flow_iat_max, flow_iat_min, flow_iat_mean, flow_iat_std = _safe_stats(flow_iats)

    fwd_iats      = _iat(flow.fwd_timestamps)
    fwd_iat_total = sum(fwd_iats)
    fwd_iat_max, fwd_iat_min, fwd_iat_mean, fwd_iat_std = _safe_stats(fwd_iats)

    bwd_iats      = _iat(flow.bwd_timestamps)
    bwd_iat_total = sum(bwd_iats)
    bwd_iat_max, bwd_iat_min, bwd_iat_mean, bwd_iat_std = _safe_stats(bwd_iats)

    down_up      = total_bwd_bytes / max(total_fwd_bytes, 1)
    init_win_fwd = flow.init_win_fwd if flow.init_win_fwd >= 0 else 0
    init_win_bwd = flow.init_win_bwd if flow.init_win_bwd >= 0 else 0

    return [
        fwd_pkts, bwd_pkts,
        total_fwd_bytes, total_bwd_bytes,
        fwd_max, fwd_min, fwd_mean, fwd_std,
        bwd_max, bwd_min, bwd_mean, bwd_std,
        pkt_min, pkt_max, pkt_mean, pkt_std, pkt_var,
        flow_bytes_s, flow_pkts_s, fwd_pkts_s, bwd_pkts_s,
        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
        float(flow.fwd_header_len), float(flow.bwd_header_len),
        float(flow.fin), float(flow.syn), float(flow.rst),
        float(flow.psh), float(flow.ack), float(flow.urg),
        float(flow.dst_port),
        float(init_win_fwd), float(init_win_bwd),
        down_up,
    ]


# ─────────────────────────────────────────────────────────────────────────────
# FLOW TRACKER
# ─────────────────────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Maintains a table of active flows. Each flow is keyed by the canonical
    5-tuple of the initiating direction. Packets in the reverse direction are
    recognised as backward traffic for the same flow.
    """

    def __init__(self, window_seconds: float = 5.0):
        self.window       = window_seconds
        self.flows:       Dict[FlowKey, FlowRecord] = {}
        self.reverse_map: Dict[FlowKey, FlowKey]    = {}
        self.completed:   List[Tuple[FlowKey, FlowRecord, float]] = []

    def _canonical_key(self, pkt) -> Tuple[FlowKey, bool]:
        from scapy.layers.inet import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return None, None

        ip    = pkt[IP]
        src   = ip.src
        dst   = ip.dst
        proto = ip.proto

        sport, dport = 0, 0
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        fwd_key = (src, dst, sport, dport, proto)
        rev_key = (dst, src, dport, sport, proto)

        if fwd_key in self.flows:
            return fwd_key, True
        if rev_key in self.flows:
            return rev_key, False
        if fwd_key in self.reverse_map:
            return self.reverse_map[fwd_key], False

        # New flow
        self.flows[fwd_key]       = FlowRecord()
        self.reverse_map[rev_key] = fwd_key
        return fwd_key, True

    def process(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP

        now = time.time()
        key, is_fwd = self._canonical_key(pkt)
        if key is None:
            return

        flow = self.flows[key]

        if not flow.fwd_timestamps and not flow.bwd_timestamps:
            flow.start_time = now
            flow.dst_port   = (pkt[TCP].dport if pkt.haslayer(TCP) else
                               pkt[UDP].dport if pkt.haslayer(UDP) else 0)

        pkt_len = len(pkt)

        if pkt.haslayer(TCP):
            tcp   = pkt[TCP]
            flags = tcp.flags
            if flags & 0x01: flow.fin += 1
            if flags & 0x02: flow.syn += 1
            if flags & 0x04: flow.rst += 1
            if flags & 0x08: flow.psh += 1
            if flags & 0x10: flow.ack += 1
            if flags & 0x20: flow.urg += 1

        if is_fwd:
            flow.fwd_lengths.append(pkt_len)
            flow.fwd_timestamps.append(now)
            if pkt.haslayer(TCP):
                flow.fwd_header_len += pkt[TCP].dataofs * 4
                if flow.init_win_fwd < 0:
                    flow.init_win_fwd = pkt[TCP].window
            elif pkt.haslayer(UDP):
                flow.fwd_header_len += 8
        else:
            flow.bwd_lengths.append(pkt_len)
            flow.bwd_timestamps.append(now)
            if pkt.haslayer(TCP):
                flow.bwd_header_len += pkt[TCP].dataofs * 4
                if flow.init_win_bwd < 0:
                    flow.init_win_bwd = pkt[TCP].window
            elif pkt.haslayer(UDP):
                flow.bwd_header_len += 8

        self._expire(now)

    def _expire(self, now: float):
        expired = [
            k for k, f in self.flows.items()
            if f.fwd_timestamps and (now - f.start_time) >= self.window
        ]
        for k in expired:
            flow     = self.flows.pop(k)
            rev      = (k[1], k[0], k[3], k[2], k[4])
            self.reverse_map.pop(rev, None)
            duration = now - flow.start_time
            if flow.fwd_lengths:
                self.completed.append((k, flow, duration))

    def drain(self) -> List[Tuple[FlowKey, FlowRecord, float]]:
        out = self.completed
        self.completed = []
        return out


# ─────────────────────────────────────────────────────────────────────────────
# SERVER COMMUNICATION
# ─────────────────────────────────────────────────────────────────────────────

def send_to_server(
    server_url:  str,
    features:    List[float],
    flow_key:    FlowKey,
    flow_record: FlowRecord,
    duration:    float,
) -> dict:
    src_ip, dst_ip, sport, dport, proto = flow_key
    proto_name = "TCP" if proto == 6 else "UDP"

    payload = {
        "features": features,
        "flow_meta": {
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    sport,
            "dst_port":    dport,
            "protocol":    proto_name,
            "duration":    round(duration, 4),
            "fwd_packets": len(flow_record.fwd_lengths),
            "bwd_packets": len(flow_record.bwd_lengths),
        },
    }

    try:
        resp = requests.post(
            f"{server_url}/predict",
            json=payload,
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        print(f"[!] Cannot reach server at {server_url} — is the backend running?")
        return None
    except requests.exceptions.Timeout:
        print(f"[!] Server request timed out for flow {src_ip}:{sport} → {dst_ip}:{dport}")
        return None
    except Exception as e:
        print(f"[!] Server error: {e}")
        return None


def print_result(result: dict, flow_key: FlowKey, flow_record: FlowRecord):
    if result is None:
        return

    src_ip, dst_ip, sport, dport, proto = flow_key
    proto_name = "TCP" if proto == 6 else "UDP"
    fwd  = len(flow_record.fwd_lengths)
    bwd  = len(flow_record.bwd_lengths)
    prob = result.get("probability", 0.0)

    if result.get("is_attack"):
        attack_type = result.get("attack_type", "DDoS ATTACK")
        print(
            f"🚨 {attack_type} DETECTED | "
            f"{src_ip}:{sport} → {dst_ip}:{dport} ({proto_name}) | "
            f"confidence: {prob:.2%} | "
            f"pkts: {fwd}↑ {bwd}↓"
        )
    else:
        if fwd + bwd > 10:
            print(
                f"✅ BENIGN | "
                f"{src_ip}:{sport} → {dst_ip}:{dport} ({proto_name}) | "
                f"confidence: {prob:.2%} | "
                f"pkts: {fwd}↑ {bwd}↓"
            )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CAPTURE LOOP
# ─────────────────────────────────────────────────────────────────────────────

def run(iface: str, server_url: str, window: float):
    from scapy.all import sniff

    cfg         = _load_settings()
    min_packets = int(cfg.get("min_packets_to_score", 5))
    server_url  = server_url.rstrip("/")

    # Verify backend is reachable before starting capture
    try:
        resp = requests.get(f"{server_url}/predict/health", timeout=5)
        resp.raise_for_status()
        info = resp.json()
        print(f"[*] Backend connected — {info.get('message', 'OK')}")
    except Exception:
        print(f"[!] Cannot reach backend at {server_url}")
        print(f"    Make sure the backend is running.")
        raise SystemExit(1)

    print(f"[*] Capturing on interface : {iface}")
    print(f"[*] Flow window            : {window}s")
    print(f"[*] Min packets per flow   : {min_packets}")
    print(f"[*] Backend URL            : {server_url}")
    print("-" * 60)

    tracker = FlowTracker(window_seconds=window)

    def packet_callback(pkt):
        tracker.process(pkt)

        for flow_key, flow_record, duration in tracker.drain():
            total_pkts = len(flow_record.fwd_lengths) + len(flow_record.bwd_lengths)
            if total_pkts < min_packets:
                continue

            features = extract_features(flow_record, duration)
            result   = send_to_server(server_url, features, flow_key, flow_record, duration)
            print_result(result, flow_key, flow_record)

    sniff(
        iface=iface,
        filter="tcp or udp",
        prn=packet_callback,
        store=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    cfg = _load_settings()
    default_server = cfg.get("backend_url", "http://localhost:8000")
    default_window = float(cfg.get("flow_timeout", 5.0))

    parser = argparse.ArgumentParser(description="DDoS local capture and flow builder")
    parser.add_argument("--iface",   required=True,  help="Network interface to sniff (e.g. eth0, wlan0)")
    parser.add_argument("--server",  default=default_server, help="Backend URL")
    parser.add_argument("--window",  type=float, default=default_window, help="Flow window in seconds")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] This script requires root privileges to capture packets.")
        print("    Run with: sudo python capture.py --iface <iface>")
        raise SystemExit(1)

    run(args.iface, args.server, args.window)


if __name__ == "__main__":
    main()
