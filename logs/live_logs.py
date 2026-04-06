"""
Security-Log-Analyser — Live Log Streaming Server
Generates security logs in real-time and exposes them via a Flask API.

Features:
    - Generates logs continuously at a configurable rate
    - REST API to read the live log stream
    - SSE (Server-Sent Events) endpoint for real-time browser/client consumption
    - Logs are also written to a file that the analyser can ingest

Endpoints:
    GET  /              — Health check & info
    GET  /stream        — SSE stream of live logs (real-time)
    GET  /api/recent    — Get the N most recent log entries (default 50)
    GET  /api/status    — Server status, total logs generated, etc.
    POST /api/start     — Start log generation
    POST /api/stop      — Stop log generation

Usage:
    python logs/live_logs.py                      # Defaults: port 5001, 1 log/sec
    python logs/live_logs.py --rate 5             # 5 logs per second
    python logs/live_logs.py --port 5001          # Custom port
    python logs/live_logs.py --output logs/live_feed.md  # Write to file too
"""

import argparse
import json
import os
import sys
import time
import random
import threading
from datetime import datetime
from collections import deque
from typing import Optional

from flask import Flask, Response, jsonify, request

# ── Log Generation Data (reuse from generate_logs.py) ────────────────

IP_ADDRESSES = [
    "192.168.1.1", "192.168.1.100", "10.0.0.1", "10.0.0.150",
    "172.16.0.1", "172.16.0.150", "198.51.100.2", "203.0.113.1",
    "203.0.113.50", "198.51.100.10", "10.10.10.5", "172.16.5.25",
    "192.168.10.44", "45.33.32.156", "104.26.10.78", "185.220.101.1",
]

USERS = [
    "admin", "root", "guest", "user", "john", "bob", "alice",
    "sysadmin", "operator", "service_account", "deploy_bot", "monitor",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH", "HEAD"]

ENDPOINTS = [
    "/login", "/admin", "/index.html", "/api/data", "/api/users",
    "/uploads/file1.jpg", "/api/config", "/dashboard", "/api/logs",
    "/api/health", "/api/tokens", "/settings", "/reset-password",
    "/api/export", "/wp-admin", "/phpmyadmin", "/.env", "/api/v2/auth",
]

USER_AGENTS = [
    "Mozilla/5.0", "curl/7.68.0", "Python-urllib/3.8",
    "PostmanRuntime/7.26.8", "Wget/1.20.3", "python-requests/2.28.0",
    "Googlebot/2.1", "sqlmap/1.6", "Nikto/2.1.6", "Nmap Scripting Engine",
]

NORMAL_RESPONSES = [
    "200 OK", "201 Created", "301 Moved Permanently",
    "304 Not Modified", "400 Bad Request", "401 Unauthorized",
    "403 Forbidden", "404 Not Found", "500 Internal Server Error",
    "502 Bad Gateway", "503 Service Unavailable",
]

ATTACK_EVENTS = [
    "Brute force attack detected from {attacker_ip}",
    "SQL Injection attempt on {endpoint}",
    "DDoS attack pattern detected from {attacker_ip}",
    "Suspicious file upload detected: /uploads/shell.php",
    "Remote code execution attempt detected on {endpoint}",
    "XSS attack attempt on {endpoint}",
    "Directory traversal attempt: /../../etc/passwd",
    "Credential stuffing attack from {attacker_ip}",
    "Port scanning detected from {attacker_ip}",
    "Privilege escalation attempt by {user}",
    "Command injection attempt on {endpoint}",
    "Session hijacking attempt detected",
    "DNS tunneling activity detected from {attacker_ip}",
]

ATTACKER_IPS = ["203.0.113.1", "198.51.100.2", "185.220.101.1", "45.33.32.156"]


# ── Live Log Engine ──────────────────────────────────────────────────

class LiveLogEngine:
    """Continuously generates logs at a configurable rate."""

    def __init__(self, rate=1.0, attack_ratio=0.15, output_file=None, buffer_size=1000):
        self.rate = rate  # logs per second
        self.attack_ratio = attack_ratio
        self.output_file = output_file
        self.buffer = deque(maxlen=buffer_size)
        self.total_generated = 0
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._subscribers: list[deque] = []
        self._lock = threading.Lock()

        # Initialize output file
        if self.output_file:
            os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
            with open(self.output_file, "w", encoding="utf-8") as f:
                f.write("# Live Security Logs\n\n")

    def _generate_one(self):
        """Generate a single structured log entry."""
        ts = datetime.now()
        ip = random.choice(IP_ADDRESSES)
        user = random.choice(USERS)
        method = random.choice(HTTP_METHODS)
        endpoint = random.choice(ENDPOINTS)
        is_attack = random.random() < self.attack_ratio

        if is_attack:
            template = random.choice(ATTACK_EVENTS)
            description = template.format(
                attacker_ip=random.choice(ATTACKER_IPS),
                endpoint=endpoint,
                user=user,
            )
            severity = "HIGH"
        else:
            response = random.choice(NORMAL_RESPONSES)
            agent = random.choice(USER_AGENTS)
            description = f'"{response}" "{agent}"'
            # Assign severity based on response code
            if response.startswith(("5", "4")):
                severity = "MEDIUM" if response.startswith("5") else "LOW"
            else:
                severity = "INFO"

        entry = {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "user": user,
            "method": method,
            "endpoint": endpoint,
            "description": description,
            "is_attack": is_attack,
            "severity": severity,
            "raw": f"- {ts.strftime('%Y-%m-%d %H:%M:%S')} {ip} - {user} [{method} {endpoint}] {description}",
        }

        return entry

    def _run_loop(self):
        """Background thread loop that generates logs."""
        while self.running:
            entry = self._generate_one()

            with self._lock:
                self.buffer.append(entry)
                self.total_generated += 1

                # Notify SSE subscribers
                dead = []
                for q in self._subscribers:
                    try:
                        q.append(entry)
                    except Exception:
                        dead.append(q)
                for q in dead:
                    self._subscribers.remove(q)

            # Write to file
            if self.output_file:
                try:
                    with open(self.output_file, "a", encoding="utf-8") as f:
                        f.write(entry["raw"] + "\n")
                except Exception:
                    pass

            time.sleep(1.0 / self.rate)

    def start(self):
        """Start generating logs."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop generating logs."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)

    def subscribe(self):
        """Subscribe to the live log stream. Returns a deque that receives new entries."""
        q = deque(maxlen=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        """Remove a subscriber."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def get_recent(self, n=50):
        """Get the N most recent log entries."""
        with self._lock:
            items = list(self.buffer)
        return items[-n:]

    def get_status(self):
        """Get engine status."""
        return {
            "running": self.running,
            "rate": self.rate,
            "attack_ratio": self.attack_ratio,
            "total_generated": self.total_generated,
            "buffer_size": len(self.buffer),
            "subscribers": len(self._subscribers),
            "output_file": self.output_file,
        }


# ── Flask API ────────────────────────────────────────────────────────

app = Flask(__name__)
engine: Optional[LiveLogEngine] = None


@app.route("/")
def index():
    """Health check and info."""
    return jsonify({
        "service": "Security-Log-Analyser — Live Log Stream",
        "status": "running" if engine and engine.running else "stopped",
        "endpoints": {
            "GET /stream": "SSE stream of live logs",
            "GET /api/recent": "Recent log entries (?n=50)",
            "GET /api/status": "Server status",
            "POST /api/start": "Start log generation",
            "POST /api/stop": "Stop log generation",
            "POST /api/config": "Update rate/attack_ratio",
        },
    })


@app.route("/stream")
def stream():
    """SSE endpoint — streams logs in real-time to the client."""
    def generate():
        q = engine.subscribe()
        try:
            while True:
                if q:
                    entry = q.popleft()
                    data = json.dumps(entry, default=str)
                    yield f"data: {data}\n\n"
                else:
                    # Send heartbeat to keep connection alive
                    yield ": heartbeat\n\n"
                    time.sleep(0.5)
        except GeneratorExit:
            engine.unsubscribe(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/recent")
def recent():
    """Get the N most recent log entries."""
    n = request.args.get("n", 50, type=int)
    entries = engine.get_recent(n)
    return jsonify({"count": len(entries), "entries": entries})


@app.route("/api/status")
def status():
    """Get engine status."""
    return jsonify(engine.get_status())


@app.route("/api/start", methods=["POST"])
def start_engine():
    """Start log generation."""
    engine.start()
    return jsonify({"message": "Log generation started", "status": engine.get_status()})


@app.route("/api/stop", methods=["POST"])
def stop_engine():
    """Stop log generation."""
    engine.stop()
    return jsonify({"message": "Log generation stopped", "status": engine.get_status()})


@app.route("/api/config", methods=["POST"])
def update_config():
    """Update engine configuration (rate, attack_ratio)."""
    data = request.get_json() or {}
    if "rate" in data:
        engine.rate = max(0.1, min(100, float(data["rate"])))
    if "attack_ratio" in data:
        engine.attack_ratio = max(0.0, min(1.0, float(data["attack_ratio"])))
    return jsonify({"message": "Configuration updated", "status": engine.get_status()})


# ── Main ─────────────────────────────────────────────────────────────

def main():
    global engine

    parser = argparse.ArgumentParser(
        description="Security-Log-Analyser — Live Log Streaming Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python logs/live_logs.py
  python logs/live_logs.py --rate 5 --port 5001
  python logs/live_logs.py --output logs/live_feed.md --attack-ratio 0.3
  
To consume the stream:
  curl http://localhost:5001/stream
  curl http://localhost:5001/api/recent?n=20
        """,
    )
    parser.add_argument("--port", "-p", type=int, default=5001,
                        help="Port to run the server on (default: 5001)")
    parser.add_argument("--rate", "-r", type=float, default=1.0,
                        help="Logs per second (default: 1.0)")
    parser.add_argument("--attack-ratio", "-a", type=float, default=0.15,
                        help="Ratio of attack events 0.0-1.0 (default: 0.15)")
    parser.add_argument("--output", "-o", default=None,
                        help="Also write live logs to this file (for analyser ingestion)")
    parser.add_argument("--auto-start", action="store_true", default=True,
                        help="Start generating logs immediately (default: True)")
    parser.add_argument("--buffer-size", "-b", type=int, default=1000,
                        help="Max entries to keep in memory buffer (default: 1000)")

    args = parser.parse_args()

    # Resolve output path
    output_file = args.output
    if output_file is None:
        output_file = os.path.join(os.path.dirname(__file__), "live_feed.md")

    engine = LiveLogEngine(
        rate=args.rate,
        attack_ratio=args.attack_ratio,
        output_file=output_file,
        buffer_size=args.buffer_size,
    )

    if args.auto_start:
        engine.start()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         Security-Log-Analyser — Live Log Server             ║
╠══════════════════════════════════════════════════════════════╣
║  Stream:  http://localhost:{args.port}/stream                    ║
║  Recent:  http://localhost:{args.port}/api/recent                ║
║  Status:  http://localhost:{args.port}/api/status                ║
║  Rate:    {args.rate} logs/sec                                     ║
║  Output:  {os.path.basename(output_file):<40}         ║
╚══════════════════════════════════════════════════════════════╝
""")

    app.run(host="0.0.0.0", port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
