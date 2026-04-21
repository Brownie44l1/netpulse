"""
app.py — Flask web server for NetPulse.

What this file does in simple terms:
  - Starts a background thread that sniffs live network packets (via capture.py).
  - Serves a dashboard HTML page at http://0.0.0.0:5000.
  - Exposes a JSON API that the dashboard polls every 2 seconds to refresh charts.
  - Supports switching the capture interface at runtime without restarting the server.

Run with:
    sudo python app.py              # auto-detect interface
    sudo python app.py -i wlan0     # specify interface manually
"""

import argparse
import os
import sys
import threading
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from capture import NetworkCapture


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="NetPulse — Network Monitor")
parser.add_argument(
    "--iface", "-i",
    default=None,
    help=(
        "Network interface to sniff (default: Scapy auto-detect). "
        "Examples: wlan0, eth0, lo, any"
    ),
)
args, _ = parser.parse_known_args()


# ---------------------------------------------------------------------------
# Root check — Scapy needs raw socket access, which requires root on Linux/macOS
# ---------------------------------------------------------------------------

if os.name != "nt" and os.geteuid() != 0:
    print(
        "\n[!] Scapy requires root to capture packets.\n"
        "    Re-run with: sudo python app.py\n",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Flask app setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)  # allow the dashboard to call the API even when served from a different origin


# ---------------------------------------------------------------------------
# Capture lifecycle management
# ---------------------------------------------------------------------------

# These three globals are protected by _capture_lock.
_capture_lock   = threading.Lock()
_capture:         NetworkCapture | None = None
_capture_thread:  threading.Thread | None = None
_capture_error:   str | None = None   # last error message from the capture thread


def _start_capture(iface: str | None) -> tuple[NetworkCapture, threading.Thread]:
    """
    Create a new NetworkCapture for the given interface and start it in a
    background daemon thread.

    The thread is daemon=True so it dies automatically when the main process
    exits — no explicit teardown needed.
    """
    cap = NetworkCapture(interface=iface)

    def _run():
        global _capture_error
        try:
            cap.run()  # blocks inside Scapy's sniff() until the process dies
        except PermissionError:
            _capture_error = "Permission denied — is the server running as root?"
        except OSError as exc:
            # Raised when the interface name doesn't exist on this machine
            _capture_error = f"Interface error: {exc}"
        except Exception as exc:
            _capture_error = f"Capture stopped unexpectedly: {exc}"

    t = threading.Thread(
        target=_run,
        daemon=True,
        name=f"capture-{iface or 'auto'}",
    )
    t.start()
    return cap, t


def _get_capture() -> NetworkCapture:
    """
    Return the active NetworkCapture, or raise RuntimeError if none is running.
    Used by every API route handler.
    """
    with _capture_lock:
        if _capture is None:
            raise RuntimeError("Capture not initialised")
        return _capture


# ---------------------------------------------------------------------------
# Start the initial capture when the server boots
# ---------------------------------------------------------------------------

with _capture_lock:
    _capture, _capture_thread = _start_capture(args.iface)


# ---------------------------------------------------------------------------
# Interface discovery helpers
# ---------------------------------------------------------------------------

# These prefixes identify virtual / container interfaces.
# We hide them from the UI — users care about physical NICs.
_VIRTUAL_PREFIXES = (
    "veth",    # Docker per-container virtual ethernet
    "br-",     # Docker bridge networks
    "docker",  # docker0 etc.
    "virbr",   # libvirt/KVM bridges
    "lxc",     # LXC containers
    "lxd",     # LXD containers
    "tun",     # VPN tunnels
    "tap",     # TAP virtual devices
    "vmnet",   # VMware virtual networks
    "vbox",    # VirtualBox virtual networks
)

# Maps raw interface name prefixes → human-readable labels shown in the UI.
_IFACE_LABELS = {
    "lo":   "Loopback (this machine only)",
    "enp":  "Ethernet (cable)",
    "eth":  "Ethernet (cable)",
    "eno":  "Ethernet (cable)",
    "ens":  "Ethernet (cable)",
    "wlp":  "WiFi",
    "wlan": "WiFi",
    "wlo":  "WiFi",
    "any":  "Everything (all interfaces)",
}


def _label_for(iface: str) -> str:
    """Return a plain-English label for a raw interface name."""
    if iface in _IFACE_LABELS:
        return _IFACE_LABELS[iface]
    # Try longest-prefix match so 'wlp2s0' → 'WiFi'
    for prefix in sorted(_IFACE_LABELS, key=len, reverse=True):
        if iface.startswith(prefix):
            return _IFACE_LABELS[prefix]
    return iface  # fallback: show the raw name


def _is_virtual(iface: str) -> bool:
    """Return True if this interface should be hidden from the UI."""
    return any(iface.startswith(p) for p in _VIRTUAL_PREFIXES)


def _list_interfaces() -> list[dict]:
    """
    Discover physical network interfaces on the machine.

    Returns a list like:
        [{"name": "wlp2s0", "label": "WiFi"}, ...]
    Always appends the special "any" pseudo-interface at the end.

    Virtual/container interfaces (Docker, VPN tunnels, etc.) are excluded
    because they would confuse non-technical users.
    """
    raw: list[str] = []

    # psutil is the most portable way to list interfaces; fall back to /proc
    try:
        import psutil
        raw = list(psutil.net_if_addrs().keys())
    except ImportError:
        try:
            with open("/proc/net/dev") as f:
                lines = f.readlines()[2:]  # skip the two header lines
            raw = [l.split(":")[0].strip() for l in lines if ":" in l]
        except Exception:
            raw = []

    # Keep physical interfaces; always keep 'lo' (useful for local-only demos)
    filtered = [
        {"name": iface, "label": _label_for(iface)}
        for iface in raw
        if not _is_virtual(iface) or iface == "lo"
    ]

    # Deduplicate while preserving order
    seen, unique = set(), []
    for item in filtered:
        if item["name"] not in seen:
            seen.add(item["name"])
            unique.append(item)

    unique.append({"name": "any", "label": _label_for("any")})
    return unique


# ---------------------------------------------------------------------------
# Routes — HTML
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the dashboard HTML page."""
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes — JSON API (polled every 2 s by the dashboard)
# ---------------------------------------------------------------------------

@app.route("/api/devices")
def get_devices():
    """All known devices with their current stats."""
    try:
        return jsonify(_get_capture().get_devices())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/alerts")
def get_alerts():
    """Alert feed, newest first."""
    try:
        return jsonify(_get_capture().get_alerts())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/protocols")
def get_protocols():
    """Cumulative byte counts per protocol (TCP / UDP / ICMP)."""
    try:
        return jsonify(_get_capture().get_protocol_stats())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/bandwidth")
def get_bandwidth():
    """Lightweight bandwidth list for the leaderboard widget."""
    try:
        return jsonify(_get_capture().get_bandwidth_stats())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/stats")
def get_stats():
    """Four headline numbers for the stat cards."""
    try:
        return jsonify(_get_capture().get_summary_stats())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/interfaces", methods=["GET"])
def list_interfaces():
    """
    List physical interfaces available on this machine.

    Response format:
        {
          "interfaces": [{"name": "wlp2s0", "label": "WiFi"}, ...],
          "current": "wlp2s0"
        }
    """
    return jsonify({
        "interfaces": _list_interfaces(),
        "current":    _capture.interface if _capture else None,
    })


@app.route("/api/interface", methods=["GET"])
def get_interface():
    """Return the currently active interface and whether its thread is alive."""
    with _capture_lock:
        iface        = _capture.interface if _capture else None
        thread_alive = _capture_thread.is_alive() if _capture_thread else False
    return jsonify({
        "interface":    iface,
        "thread_alive": thread_alive,
        "error":        _capture_error,
    })


@app.route("/api/interface", methods=["POST"])
def set_interface():
    """
    Switch packet capture to a different interface without restarting the server.

    Request body: { "iface": "eth0" }

    The old capture thread is abandoned (it's a daemon thread, so the OS will
    reclaim its resources). A fresh NetworkCapture is started on the new interface.
    """
    global _capture, _capture_thread, _capture_error

    data      = request.get_json(silent=True) or {}
    new_iface = data.get("iface")

    if not new_iface:
        return jsonify({"error": "Missing field: iface"}), 400

    # Soft-validate against known interfaces (user may know better than us)
    known_names = [i["name"] for i in _list_interfaces()]
    if new_iface not in known_names and new_iface != "any":
        return jsonify({
            "error":     f"Interface '{new_iface}' not found",
            "available": known_names,
        }), 404

    with _capture_lock:
        _capture_error            = None
        _capture, _capture_thread = _start_capture(new_iface)

    return jsonify({
        "status":    "ok",
        "interface": new_iface,
        "message":   f"Switched capture to {new_iface}",
    })


@app.route("/api/health", methods=["GET"])
def health():
    """
    Lightweight liveness probe.

    Returns 200 OK when the capture thread is alive, 503 when it has died
    (e.g. permission error or bad interface name).
    """
    with _capture_lock:
        thread_alive = _capture_thread.is_alive() if _capture_thread else False
        iface        = _capture.interface if _capture else None

    status = "ok" if thread_alive else "degraded"
    return jsonify({
        "status":       status,
        "interface":    iface,
        "thread_alive": thread_alive,
        "error":        _capture_error,
    }), 200 if status == "ok" else 503


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    iface_display = args.iface or "auto"
    print(f"[*] NetPulse starting — capture interface: {iface_display}")
    print(f"[*] Dashboard → http://0.0.0.0:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)