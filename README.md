# NetPulse

A real-time network monitoring tool built with Scapy and Flask. Sniffs live IP traffic off one or more network interfaces, tracks per-device bandwidth consumption, and flags anomalous devices using a rolling anomaly score.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                      app.py                         │
│  Flask dev server — serves dashboard + REST routes  │
│                                                     │
│  GET /api/devices       → capture.get_devices()     │
│  GET /api/alerts        → capture.get_alerts()      │
│  GET /api/protocol      → capture.get_protocol_stats│
│  GET /api/bandwidth     → capture.get_bandwidth_stats│
│  GET /api/summary       → capture.get_summary_stats │
└────────────────────┬────────────────────────────────┘
                     │ shared NetworkCapture instance
┌────────────────────▼────────────────────────────────┐
│                  capture.py                         │
│                                                     │
│  Thread 1 — scapy sniff()                           │
│    └─ _handle_packet()  per-packet callback         │
│                                                     │
│  Thread 2 — _tick_loop()  fires every 2 s           │
│    └─ _calc_mbps()      rolling 5 s bandwidth avg   │
│    └─ _score_device()   anomaly scoring             │
│                                                     │
│  Shared state (protected by threading.Lock)         │
│    _devices        dict[ip → device record]         │
│    _protocol_bytes dict[proto → bytes]              │
│    _bw_window      dict[ip → deque of (ts, bytes)]  │
│    alerts          deque[alert dicts], maxlen=100   │
└─────────────────────────────────────────────────────┘
```

## Requirements

- Python 3.10+
- Root / sudo (Scapy requires raw socket access)

```bash
pip install scapy flask
```

## Running

```bash
sudo python app.py
```

## Anomaly Detection

Scoring runs every 2 seconds per device:

| Condition      | Score delta |
|----------------|-------------|
| > 5 Mbps       | +10         |
| 2 – 5 Mbps     | +3          |
| < 2 Mbps       | −1          |

A device is flagged as `abusive` once its score exceeds **60/100** — roughly 24 seconds of sustained traffic above 5 Mbps, or ~4 minutes above 2 Mbps. The score decays passively when the device calms down, so a brief spike will not trigger a flag.