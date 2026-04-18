import random
import time
import threading
from datetime import datetime, timedelta
from collections import deque

DEVICES = [
    {
        "mac": "A4:C3:F0:12:34:56",
        "ip": "192.168.43.2",
        "hostname": "Prof_Laptop",
        "type": "laptop",
        "behavior": "normal",
        "emoji": "💻"
    },
    {
        "mac": "B8:27:EB:45:67:89",
        "ip": "192.168.43.3",
        "hostname": "Student_Phone_1",
        "type": "phone",
        "behavior": "normal",
        "emoji": "📱"
    },
    {
        "mac": "DC:A6:32:78:9A:BC",
        "ip": "192.168.43.4",
        "hostname": "Student_Phone_2",
        "type": "phone",
        "behavior": "normal",
        "emoji": "📱"
    },
    {
        "mac": "F0:18:98:AB:CD:EF",
        "ip": "192.168.43.5",
        "hostname": "Abuser_Device",
        "type": "phone",
        "behavior": "abusive",
        "emoji": "🚨"
    },
    {
        "mac": "12:34:56:78:9A:BC",
        "ip": "192.168.43.6",
        "hostname": "Guest_Tablet",
        "type": "tablet",
        "behavior": "moderate",
        "emoji": "📟"
    },
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
SERVICES = {
    "normal": ["HTTP Browse", "DNS Lookup", "WhatsApp", "YouTube 480p", "Instagram"],
    "moderate": ["YouTube 720p", "Spotify Stream", "Google Meet", "File Sync"],
    "abusive": ["Torrent Download", "100GB File Download", "Video Dump", "Bulk Download"],
}

# MB per second ranges per behavior
BANDWIDTH_PROFILES = {
    "normal":   (0.05, 0.5),
    "moderate": (0.5, 2.0),
    "abusive":  (8.0, 15.0),
}


class NetworkSimulator:
    def __init__(self):
        self.devices = {d["mac"]: self._init_device(d) for d in DEVICES}
        self.alerts = deque(maxlen=100)
        self.protocol_bytes = {"TCP": 0, "UDP": 0, "ICMP": 0}
        self.lock = threading.Lock()
        self.tick = 0

        # Seed initial alert
        self.alerts.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": "info",
            "message": "NetPulse started — monitoring 5 devices on hotspot"
        })

    def _init_device(self, d):
        return {
            "mac": d["mac"],
            "ip": d["ip"],
            "hostname": d["hostname"],
            "type": d["type"],
            "behavior": d["behavior"],
            "emoji": d["emoji"],
            "status": "active",
            "connected_since": datetime.now().strftime("%H:%M:%S"),
            "total_mb": 0.0,
            "current_mbps": 0.0,
            "protocol": random.choice(PROTOCOLS),
            "service": random.choice(SERVICES[d["behavior"]]),
            "packet_count": 0,
            "anomaly_score": 0,
            "flagged": False,
        }

    def _simulate_tick(self):
        self.tick += 1
        with self.lock:
            for mac, device in self.devices.items():
                behavior = device["behavior"]
                lo, hi = BANDWIDTH_PROFILES[behavior]

                # Abuser ramps up every 10 ticks
                if behavior == "abusive":
                    ramp = min(1.0 + self.tick * 0.05, 3.0)
                    lo *= ramp
                    hi *= ramp

                mbps = round(random.uniform(lo, hi), 2)
                device["current_mbps"] = mbps
                device["total_mb"] = round(device["total_mb"] + mbps * 2, 2)  # 2s tick
                device["packet_count"] += random.randint(5, 50 if behavior != "abusive" else 300)
                device["service"] = random.choice(SERVICES[behavior])
                device["protocol"] = random.choices(
                    PROTOCOLS,
                    weights=[70, 25, 5] if behavior != "abusive" else [85, 14, 1]
                )[0]

                # Update protocol stats
                proto = device["protocol"]
                self.protocol_bytes[proto] = round(
                    self.protocol_bytes.get(proto, 0) + mbps * 1024 * 1024, 0
                )

                # Anomaly scoring
                if behavior == "abusive":
                    device["anomaly_score"] = min(device["anomaly_score"] + random.randint(3, 8), 100)
                elif behavior == "moderate":
                    device["anomaly_score"] = min(device["anomaly_score"] + random.randint(0, 2), 40)
                else:
                    device["anomaly_score"] = max(device["anomaly_score"] - 1, 0)

                # Flagging logic
                if device["anomaly_score"] > 60 and not device["flagged"]:
                    device["flagged"] = True
                    self._add_alert(
                        "critical",
                        f"🚨 {device['hostname']} ({device['ip']}) flagged for abnormal bandwidth usage — {mbps:.1f} Mbps"
                    )

                if device["total_mb"] > 1024 and behavior == "abusive":
                    self._add_alert(
                        "warning",
                        f"⚠️ {device['hostname']} has consumed over {device['total_mb']/1024:.1f} GB on this session"
                    )

            # Occasional info alerts for realism
            if self.tick % 15 == 0:
                normal_devices = [d for d in self.devices.values() if d["behavior"] == "normal"]
                if normal_devices:
                    d = random.choice(normal_devices)
                    self._add_alert("info", f"ℹ️ {d['hostname']} connected — normal traffic pattern")

            if self.tick % 20 == 0:
                abuser = next((d for d in self.devices.values() if d["behavior"] == "abusive"), None)
                if abuser:
                    self._add_alert(
                        "critical",
                        f"🚨 ML Anomaly: {abuser['hostname']} download rate {abuser['current_mbps']:.1f} Mbps — {abuser['total_mb']:.0f} MB consumed"
                    )

    def _add_alert(self, level, message):
        self.alerts.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message
        })

    def run(self):
        while True:
            self._simulate_tick()
            time.sleep(2)

    # ── API getters ──────────────────────────────────────────

    def get_devices(self):
        with self.lock:
            return list(self.devices.values())

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    def get_protocol_stats(self):
        with self.lock:
            return self.protocol_bytes.copy()

    def get_bandwidth_stats(self):
        with self.lock:
            return [
                {
                    "hostname": d["hostname"],
                    "current_mbps": d["current_mbps"],
                    "total_mb": d["total_mb"],
                    "behavior": d["behavior"],
                    "flagged": d["flagged"],
                }
                for d in self.devices.values()
            ]

    def get_summary_stats(self):
        with self.lock:
            total_mb = sum(d["total_mb"] for d in self.devices.values())
            active = sum(1 for d in self.devices.values() if d["status"] == "active")
            flagged = sum(1 for d in self.devices.values() if d["flagged"])
            alerts_count = len(self.alerts)
            return {
                "total_mb": round(total_mb, 1),
                "active_devices": active,
                "flagged_devices": flagged,
                "total_alerts": alerts_count,
            }