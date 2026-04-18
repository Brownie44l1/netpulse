from flask import Flask, jsonify, render_template
from flask_cors import CORS
from capture import NetworkCapture
import threading

app = Flask(__name__)
CORS(app)

simulator = NetworkCapture()

def run_simulator():
    simulator.run()

thread = threading.Thread(target=run_simulator, daemon=True)
thread.start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/devices")
def get_devices():
    return jsonify(simulator.get_devices())

@app.route("/api/alerts")
def get_alerts():
    return jsonify(simulator.get_alerts())

@app.route("/api/protocols")
def get_protocols():
    return jsonify(simulator.get_protocol_stats())

@app.route("/api/bandwidth")
def get_bandwidth():
    return jsonify(simulator.get_bandwidth_stats())

@app.route("/api/stats")
def get_stats():
    return jsonify(simulator.get_summary_stats())

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)