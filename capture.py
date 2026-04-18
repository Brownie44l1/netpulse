"""
Real scapy packet capture + 3 injected abuser devices for demo purposes.

Requirements:
    pip install scapy
    Run with: sudo python app.py   (scapy needs root to sniff)

Usage in app.py:
    from capture import NetworkCapture   # was: from simulator import NetworkSimulator
    capture = NetworkCapture()           # was: simulator = NetworkSimulator()
"""

import threading
import time
import socket
import random
from datetime import datetime
from collections import deque, defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, conf

# ── Suppress scapy runtime warnings ──────────────────────────────────────────
conf.verb = 0


# ── Port → service name map ───────────────────────────────────────────────────
PORT_SERVICES = {
    80:   "HTTP",
    443:  "HTTPS",
    53:   "DNS",
    22:   "SSH",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6881: "BitTorrent",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    1935: "RTMP/Stream",
    554:  "RTSP",
    67:   "DHCP",
    68:   "DHCP",
    123:  "NTP",
    161:  "SNMP",
    179:  "BGP",
    5353: "mDNS",
}

def _port_to_service(port):
    return PORT_SERVICES.get(port, f"Port {port}")

def _reverse_dns(ip):
    """Best-effort reverse DNS. Falls back to IP string."""
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]  # short hostname only
    except Exception:
        return ip

def _now():
    return datetime.now().strftime("%H:%M:%S")


# ── Injected abuser profiles ──────────────────────────────────────────────────
ABUSER_PROFILES = [
    {
        "mac":      "DE:AD:BE:EF:00:01",
        "ip":       "192.168.43.101",
        "hostname": "Torrent_Client",
        "type":     "desktop",
        "behavior": "abusive",
        # Constant heavy UDP — typical torrent peer traffic
        "pattern":  "steady",
        "mbps_range": (8.0, 14.0),
        "protocol_weights": {"TCP": 20, "UDP": 78, "ICMP": 2},
        "services": ["BitTorrent", "P2P Upload", "P2P Download", "DHT Lookup"],
    },
    {
        "mac":      "DE:AD:BE:EF:00:02",
        "ip":       "192.168.43.102",
        "hostname": "Video_Dumper",
        "type":     "laptop",
        "behavior": "abusive",
        # Calm for first 10 ticks then sudden massive TCP spikes
        "pattern":  "bursty",
        "mbps_range": (0.1, 20.0),
        "protocol_weights": {"TCP": 90, "UDP": 9, "ICMP": 1},
        "services": ["YouTube 4K", "Video Dump", "Bulk Stream", "CDN Pull"],
    },
    {
        "mac":      "DE:AD:BE:EF:00:03",
        "ip":       "192.168.43.103",
        "hostname": "Bulk_Downloader",
        "type":     "phone",
        "behavior": "abusive",
        # Slow ramp — starts normal, gradually escalates
        "pattern":  "ramp",
        "mbps_range": (0.5, 18.0),
        "protocol_weights": {"TCP": 75, "UDP": 23, "ICMP": 2},
        "services": ["HTTP Download", "FTP Bulk", "Cloud Sync", "Archive Pull"],
    },
]


class NetworkCapture:
    """
    Drop-in replacement for NetworkSimulator.
    Sniffs real packets off the default interface and injects 3 abuser devices.
    Exposes the same API surface: get_devices(), get_alerts(),
    get_protocol_stats(), get_bandwidth_stats(), get_summary_stats().
    """

    def __init__(self, interface=None):
        self.interface = interface  # None = scapy picks default
        self.lock = threading.Lock()
        self.tick = 0

        # Real devices discovered by sniffing — keyed by IP
        self._real_devices: dict[str, dict] = {}

        # Injected abuser devices — keyed by IP
        self._abuser_devices: dict[str, dict] = {
            p["ip"]: self._init_abuser(p) for p in ABUSER_PROFILES
        }

        # Protocol byte counters
        self._protocol_bytes = {"TCP": 0, "UDP": 0, "ICMP": 0}

        # Alert feed (newest first)
        self.alerts: deque = deque(maxlen=100)

        # Per-IP bandwidth window: list of (timestamp, bytes) tuples
        self._bw_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=60))

        self._add_alert("info", "NetPulse started — listening on real interface + 3 simulated abusers")

    # ── Initialisation helpers ─────────────────────────────────────────────────

    def _init_abuser(self, profile: dict) -> dict:
        return {
            "mac":             profile["mac"],
            "ip":              profile["ip"],
            "hostname":        profile["hostname"],
            "type":            profile["type"],
            "behavior":        profile["behavior"],
            "status":          "active",
            "connected_since": _now(),
            "total_mb":        0.0,
            "current_mbps":    0.0,
            "protocol":        "TCP",
            "service":         profile["services"][0],
            "packet_count":    0,
            "anomaly_score":   0,
            "flagged":         False,
            # internal
            "_profile":        profile,
            "_ramp_factor":    1.0,
        }

    def _init_real_device(self, ip: str) -> dict:
        return {
            "mac":             "unknown",
            "ip":              ip,
            "hostname":        _reverse_dns(ip),
            "type":            "unknown",
            "behavior":        "normal",
            "status":          "active",
            "connected_since": _now(),
            "total_mb":        0.0,
            "current_mbps":    0.0,
            "protocol":        "TCP",
            "service":         "unknown",
            "packet_count":    0,
            "anomaly_score":   0,
            "flagged":         False,
        }

    # ── Scapy packet handler ───────────────────────────────────────────────────

    def _handle_packet(self, pkt):
        if IP not in pkt:
            return

        src = pkt[IP].src
        size_bytes = len(pkt)
        proto = (
            "TCP"  if TCP  in pkt else
            "UDP"  if UDP  in pkt else
            "ICMP" if ICMP in pkt else
            None
        )

        # Determine service from port
        service = "Unknown"
        if TCP in pkt:
            service = _port_to_service(pkt[TCP].dport)
        elif UDP in pkt:
            service = _port_to_service(pkt[UDP].dport)

        with self.lock:
            # Ensure device record exists
            if src not in self._real_devices:
                self._real_devices[src] = self._init_real_device(src)
                self._add_alert("info", f"New device seen: {src}")

            dev = self._real_devices[src]
            size_mb = size_bytes / (1024 * 1024)

            dev["total_mb"]     = round(dev["total_mb"] + size_mb, 4)
            dev["packet_count"] += 1
            dev["status"]       = "active"

            if proto:
                dev["protocol"] = proto
                self._protocol_bytes[proto] = round(
                    self._protocol_bytes.get(proto, 0) + size_bytes, 0
                )

            if service != "Unknown":
                dev["service"] = service

            # MAC from Ethernet layer
            if Ether in pkt and dev["mac"] == "unknown":
                dev["mac"] = pkt[Ether].src

            # Bandwidth window
            self._bw_window[src].append((time.time(), size_bytes))

    # ── Bandwidth calculation (rolling 5s window) ─────────────────────────────

    def _calc_mbps(self, ip: str) -> float:
        now = time.time()
        window = self._bw_window[ip]
        # Keep only last 5 seconds
        recent = [b for ts, b in window if now - ts <= 5.0]
        if not recent:
            return 0.0
        return round(sum(recent) / (1024 * 1024) / 5.0, 3)

    # ── Anomaly detection for real devices ────────────────────────────────────

    def _score_real_device(self, dev: dict):
        mbps = dev["current_mbps"]
        if mbps > 5.0:
            dev["anomaly_score"] = min(dev["anomaly_score"] + 10, 100)
        elif mbps > 2.0:
            dev["anomaly_score"] = min(dev["anomaly_score"] + 3, 100)
        else:
            dev["anomaly_score"] = max(dev["anomaly_score"] - 1, 0)

        if dev["anomaly_score"] > 60 and not dev["flagged"]:
            dev["flagged"] = True
            dev["behavior"] = "abusive"
            self._add_alert(
                "critical",
                f"🚨 {dev['hostname']} ({dev['ip']}) flagged — {mbps:.2f} Mbps sustained"
            )

    # ── Abuser tick ───────────────────────────────────────────────────────────

    def _tick_abuser(self, dev: dict):
        profile = dev["_profile"]
        lo, hi = profile["mbps_range"]
        pattern = profile["pattern"]

        if pattern == "steady":
            mbps = round(random.uniform(lo, hi), 2)

        elif pattern == "bursty":
            # Quiet for first 10 ticks, then random spikes
            if self.tick < 10:
                mbps = round(random.uniform(0.1, 0.5), 2)
            else:
                # 30% chance of a big spike
                if random.random() < 0.3:
                    mbps = round(random.uniform(hi * 0.7, hi), 2)
                else:
                    mbps = round(random.uniform(lo, lo * 3), 2)

        elif pattern == "ramp":
            # Gradual ramp over 30 ticks
            progress = min(self.tick / 30.0, 1.0)
            effective_hi = lo + (hi - lo) * progress
            mbps = round(random.uniform(lo, max(lo + 0.1, effective_hi)), 2)

        else:
            mbps = round(random.uniform(lo, hi), 2)

        # Update protocol weights
        weights = profile["protocol_weights"]
        proto = random.choices(
            list(weights.keys()),
            weights=list(weights.values())
        )[0]

        dev["current_mbps"]  = mbps
        dev["total_mb"]      = round(dev["total_mb"] + mbps * 2, 2)  # 2s tick
        dev["packet_count"] += random.randint(50, 300)
        dev["protocol"]      = proto
        dev["service"]       = random.choice(profile["services"])

        self._protocol_bytes[proto] = round(
            self._protocol_bytes.get(proto, 0) + mbps * 1024 * 1024, 0
        )

        # Anomaly scoring
        dev["anomaly_score"] = min(dev["anomaly_score"] + random.randint(3, 8), 100)

        if dev["anomaly_score"] > 60 and not dev["flagged"]:
            dev["flagged"] = True
            self._add_alert(
                "critical",
                f"🚨 {dev['hostname']} ({dev['ip']}) flagged for abnormal bandwidth — {mbps:.1f} Mbps"
            )

        if dev["total_mb"] > 512:
            self._add_alert(
                "warning",
                f"⚠️ {dev['hostname']} consumed {dev['total_mb']/1024:.2f} GB this session"
            )

    # ── Background tick loop ──────────────────────────────────────────────────

    def _tick_loop(self):
        """Runs every 2 seconds: updates mbps for real devices + ticks abusers."""
        while True:
            self.tick += 1
            with self.lock:
                # Update mbps for real devices
                for ip, dev in self._real_devices.items():
                    dev["current_mbps"] = self._calc_mbps(ip)
                    self._score_real_device(dev)

                # Tick all abusers
                for dev in self._abuser_devices.values():
                    self._tick_abuser(dev)

                # Periodic info alerts
                if self.tick % 15 == 0 and self._real_devices:
                    sample = random.choice(list(self._real_devices.values()))
                    self._add_alert("info", f"ℹ️ {sample['hostname']} — normal traffic pattern")

                if self.tick % 25 == 0:
                    flagged_abusers = [
                        d for d in self._abuser_devices.values() if d["flagged"]
                    ]
                    for a in flagged_abusers:
                        self._add_alert(
                            "critical",
                            f"🚨 ML Anomaly: {a['hostname']} rate {a['current_mbps']:.1f} Mbps — {a['total_mb']:.0f} MB consumed"
                        )

            time.sleep(2)

    # ── Alert helper ──────────────────────────────────────────────────────────

    def _add_alert(self, level: str, message: str):
        """Must be called with self.lock held, or before threads start."""
        self.alerts.appendleft({
            "time":    _now(),
            "level":   level,
            "message": message,
        })

    # ── Public run method (called by app.py thread) ───────────────────────────

    def run(self):
        # Start the periodic tick loop in its own thread
        ticker = threading.Thread(target=self._tick_loop, daemon=True)
        ticker.start()

        # Block on scapy sniff — this is the main capture loop
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            filter="ip",        # only IP packets, skip ARP noise etc.
        )

    # ── API getters (same surface as NetworkSimulator) ────────────────────────

    def get_devices(self):
        with self.lock:
            real    = list(self._real_devices.values())
            abusers = list(self._abuser_devices.values())
            # Strip internal keys before returning
            cleaned_abusers = [
                {k: v for k, v in d.items() if not k.startswith("_")}
                for d in abusers
            ]
            return real + cleaned_abusers

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    def get_protocol_stats(self):
        with self.lock:
            return self._protocol_bytes.copy()

    def get_bandwidth_stats(self):
        with self.lock:
            all_devices = (
                list(self._real_devices.values()) +
                list(self._abuser_devices.values())
            )
            return [
                {
                    "hostname":     d["hostname"],
                    "current_mbps": d["current_mbps"],
                    "total_mb":     d["total_mb"],
                    "behavior":     d["behavior"],
                    "flagged":      d["flagged"],
                }
                for d in all_devices
            ]

    def get_summary_stats(self):
        with self.lock:
            all_devices = (
                list(self._real_devices.values()) +
                list(self._abuser_devices.values())
            )
            return {
                "total_mb":       round(sum(d["total_mb"] for d in all_devices), 1),
                "active_devices": sum(1 for d in all_devices if d["status"] == "active"),
                "flagged_devices":sum(1 for d in all_devices if d["flagged"]),
                "total_alerts":   len(self.alerts),
            }