"""
capture.py — Real-time packet sniffer using Scapy.

What this file does in simple terms:
  - Listens on a network interface (WiFi/Ethernet) for all IP packets
  - Tracks every device that sends a packet (by IP address)
  - Measures how much bandwidth each device is using right now
  - Flags devices that seem to be using too much bandwidth (anomaly detection)
  - Exposes clean data to app.py via simple getter methods

Run with: sudo python app.py   (Scapy requires root to open raw sockets)
"""

import threading
import time
import socket
import random
from datetime import datetime
from collections import deque, defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, conf

# Suppress Scapy's noisy startup warnings
conf.verb = 0


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maps well-known port numbers → human-readable service names.
# Used to label what a device is doing (e.g. port 443 → "HTTPS").
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


# ---------------------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------------------

def _port_to_service(port: int) -> str:
    """Return a service label for a port number, e.g. 443 → 'HTTPS'."""
    return PORT_SERVICES.get(port, f"Port {port}")


def _reverse_dns(ip: str) -> str:
    """
    Try to resolve an IP address to a short hostname.
    Example: '192.168.1.10' → 'my-laptop'
    Falls back to the raw IP string if DNS lookup fails.
    """
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except Exception:
        return ip


def _now() -> str:
    """Return the current time as a human-readable string (HH:MM:SS)."""
    return datetime.now().strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class NetworkCapture:
    """
    Sniffs live network packets and tracks per-device statistics.

    Architecture overview:
      - One Scapy sniff() loop (blocking) processes every incoming IP packet.
      - One background thread (_tick_loop) wakes every 2 s to recalculate
        rolling bandwidth and run anomaly scoring.
      - All shared state is protected by self.lock (a threading.Lock).
      - app.py calls the get_*() methods from Flask request threads.
    """

    def __init__(self, interface: str | None = None):
        """
        Parameters
        ----------
        interface : str or None
            Network interface to sniff on (e.g. 'wlan0', 'eth0').
            Pass None to let Scapy pick the default interface.
        """
        self.interface = interface
        self.lock = threading.Lock()   # guards all mutable state below
        self.tick = 0                  # incremented every 2 s by _tick_loop

        # Devices discovered from live packets, keyed by source IP address.
        self._devices: dict[str, dict] = {}

        # Running byte totals per transport protocol (for the protocol chart).
        self._protocol_bytes: dict[str, float] = {"TCP": 0, "UDP": 0, "ICMP": 0}

        # Alert feed — newest entry at index 0. Capped at 100 items.
        self.alerts: deque = deque(maxlen=100)

        # Per-IP sliding window of (timestamp, byte_count) tuples.
        # Used to compute a rolling 5-second bandwidth average.
        self._bw_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=60))

        self._add_alert("info", "NetPulse started — listening on real interface")

    # -----------------------------------------------------------------------
    # Device record factory
    # -----------------------------------------------------------------------

    def _init_device(self, ip: str) -> dict:
        """
        Create a blank device record for a newly seen IP address.
        All numeric fields start at zero; strings start as 'unknown'.
        """
        return {
            "mac":             "unknown",   # filled in when Ethernet header is present
            "ip":              ip,
            "hostname":        _reverse_dns(ip),
            "type":            "unknown",
            "behavior":        "normal",    # changes to "abusive" if flagged
            "status":          "active",
            "connected_since": _now(),
            "total_mb":        0.0,         # cumulative data transferred this session
            "current_mbps":    0.0,         # rolling 5-second average
            "protocol":        "TCP",
            "service":         "unknown",
            "packet_count":    0,
            "anomaly_score":   0,           # 0–100; flagged when it exceeds 60
            "flagged":         False,
        }

    # -----------------------------------------------------------------------
    # Scapy packet callback
    # -----------------------------------------------------------------------

    def _handle_packet(self, pkt) -> None:
        """
        Called by Scapy for every captured packet.

        What we do here:
          1. Ignore non-IP packets (ARP, etc.).
          2. Extract source IP, packet size, protocol, and destination port.
          3. Create a new device record if we haven't seen this IP before.
          4. Update that device's running totals.
          5. Append to the bandwidth sliding window for later Mbps calculation.
        """
        if IP not in pkt:
            return  # only care about IP packets

        src        = pkt[IP].src
        size_bytes = len(pkt)

        # Identify the transport-layer protocol
        proto = (
            "TCP"  if TCP  in pkt else
            "UDP"  if UDP  in pkt else
            "ICMP" if ICMP in pkt else
            None
        )

        # Identify the application-layer service from the destination port
        service = "Unknown"
        if TCP in pkt:
            service = _port_to_service(pkt[TCP].dport)
        elif UDP in pkt:
            service = _port_to_service(pkt[UDP].dport)

        with self.lock:
            # Register device on first sighting
            if src not in self._devices:
                self._devices[src] = self._init_device(src)
                self._add_alert("info", f"New device seen: {src}")

            dev      = self._devices[src]
            size_mb  = size_bytes / (1024 * 1024)

            # Update cumulative stats
            dev["total_mb"]     = round(dev["total_mb"] + size_mb, 4)
            dev["packet_count"] += 1
            dev["status"]       = "active"

            if proto:
                dev["protocol"] = proto
                # Add to global protocol byte counter (for the protocol pie/bar chart)
                self._protocol_bytes[proto] = round(
                    self._protocol_bytes.get(proto, 0) + size_bytes, 0
                )

            if service != "Unknown":
                dev["service"] = service

            # Grab MAC address from the Ethernet frame if available
            if Ether in pkt and dev["mac"] == "unknown":
                dev["mac"] = pkt[Ether].src

            # Append to bandwidth window so _calc_mbps can average over 5 s
            self._bw_window[src].append((time.time(), size_bytes))

    # -----------------------------------------------------------------------
    # Bandwidth calculation
    # -----------------------------------------------------------------------

    def _calc_mbps(self, ip: str) -> float:
        """
        Return the current bandwidth for an IP in Mbps.

        Method: sum all bytes seen in the last 5 seconds, then divide by 5.
        This is a rolling average — it smooths out burst noise.
        """
        now    = time.time()
        window = self._bw_window[ip]
        recent = [b for ts, b in window if now - ts <= 5.0]
        if not recent:
            return 0.0
        return round(sum(recent) / (1024 * 1024) / 5.0, 3)

    # -----------------------------------------------------------------------
    # Anomaly detection
    # -----------------------------------------------------------------------

    def _score_device(self, dev: dict) -> None:
        """
        Incrementally update a device's anomaly score based on its current Mbps.

        Scoring logic (runs every 2 s):
          - Using > 5 Mbps  → score rises quickly (+10)
          - Using 2–5 Mbps  → score rises slowly  (+3)
          - Below 2 Mbps    → score decays        (-1)

        When the score passes 60/100 the device is flagged as "abusive"
        and a critical alert is raised.
        """
        mbps = dev["current_mbps"]

        if mbps > 5.0:
            dev["anomaly_score"] = min(dev["anomaly_score"] + 10, 100)
        elif mbps > 2.0:
            dev["anomaly_score"] = min(dev["anomaly_score"] + 3, 100)
        else:
            dev["anomaly_score"] = max(dev["anomaly_score"] - 1, 0)

        if dev["anomaly_score"] > 60 and not dev["flagged"]:
            dev["flagged"]   = True
            dev["behavior"]  = "abusive"
            self._add_alert(
                "critical",
                f"🚨 {dev['hostname']} ({dev['ip']}) flagged — "
                f"{mbps:.2f} Mbps sustained"
            )

    # -----------------------------------------------------------------------
    # Background tick loop
    # -----------------------------------------------------------------------

    def _tick_loop(self) -> None:
        """
        Runs in its own daemon thread, waking every 2 seconds.

        Responsibilities:
          - Recalculate current_mbps for every known device.
          - Run the anomaly scorer on each device.
          - Emit a periodic "still normal" info alert for a random device
            (every 30 s) so the alert feed shows some activity even on a
            quiet network.
        """
        while True:
            self.tick += 1
            with self.lock:
                for ip, dev in self._devices.items():
                    dev["current_mbps"] = self._calc_mbps(ip)
                    self._score_device(dev)

                # Periodic heartbeat alert so the feed isn't completely silent
                if self.tick % 15 == 0 and self._devices:
                    sample = random.choice(list(self._devices.values()))
                    self._add_alert(
                        "info",
                        f"ℹ️  {sample['hostname']} — normal traffic pattern"
                    )

            time.sleep(2)

    # -----------------------------------------------------------------------
    # Alert helper
    # -----------------------------------------------------------------------

    def _add_alert(self, level: str, message: str) -> None:
        """
        Prepend a new alert to the feed.

        Must be called with self.lock already held (or before threads start).
        level is one of: 'info', 'warning', 'critical'.
        """
        self.alerts.appendleft({
            "time":    _now(),
            "level":   level,
            "message": message,
        })

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the capture.  Blocks until Scapy's sniff() returns (which it
        normally never does — it runs until the process is killed).

        Call this from a daemon thread in app.py so Flask can keep serving.
        """
        # Start the tick loop in the background
        threading.Thread(target=self._tick_loop, daemon=True).start()

        # Block here, processing packets as they arrive
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,   # don't buffer packets in memory
            filter="ip",   # BPF filter: only pass IP packets, ignore ARP etc.
        )

    # -----------------------------------------------------------------------
    # Public API (called by Flask route handlers in app.py)
    # -----------------------------------------------------------------------

    def get_devices(self) -> list[dict]:
        """Return a snapshot of all known devices."""
        with self.lock:
            return list(self._devices.values())

    def get_alerts(self) -> list[dict]:
        """Return the alert feed (newest first)."""
        with self.lock:
            return list(self.alerts)

    def get_protocol_stats(self) -> dict[str, float]:
        """Return cumulative byte counts keyed by protocol name."""
        with self.lock:
            return self._protocol_bytes.copy()

    def get_bandwidth_stats(self) -> list[dict]:
        """
        Return a lightweight list suitable for the bandwidth leaderboard.
        Only includes the fields the frontend actually needs.
        """
        with self.lock:
            return [
                {
                    "hostname":     d["hostname"],
                    "current_mbps": d["current_mbps"],
                    "total_mb":     d["total_mb"],
                    "behavior":     d["behavior"],
                    "flagged":      d["flagged"],
                }
                for d in self._devices.values()
            ]

    def get_summary_stats(self) -> dict:
        """Return the four headline numbers shown in the stat cards."""
        with self.lock:
            devs = list(self._devices.values())
            return {
                "total_mb":        round(sum(d["total_mb"] for d in devs), 1),
                "active_devices":  sum(1 for d in devs if d["status"] == "active"),
                "flagged_devices": sum(1 for d in devs if d["flagged"]),
                "total_alerts":    len(self.alerts),
            }