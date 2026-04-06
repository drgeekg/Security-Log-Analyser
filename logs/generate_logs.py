"""
Security-Log-Analyser — Log Generator
Generates synthetic security log files matching the project's log format.

Usage:
    python logs/generate_logs.py                        # Generate with defaults
    python logs/generate_logs.py --count 1000           # 1000 log entries
    python logs/generate_logs.py --output my_logs.md    # Custom filename
    python logs/generate_logs.py --attack-ratio 0.3     # 30% attack events
    python logs/generate_logs.py --start-date 2024-09-01 --days 7
"""

import argparse
import random
import os
from datetime import datetime, timedelta

# ── Configurable Data Pools ──────────────────────────────────────────

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
    '"200 OK"', '"201 Created"', '"301 Moved Permanently"',
    '"304 Not Modified"', '"400 Bad Request"', '"401 Unauthorized"',
    '"403 Forbidden"', '"404 Not Found"', '"500 Internal Server Error"',
    '"502 Bad Gateway"', '"503 Service Unavailable"',
]

# Attack event templates — these simulate real security threats
ATTACK_EVENTS = [
    "Brute force attack detected from {attacker_ip}",
    "SQL Injection attempt on {endpoint}",
    "DDoS attack pattern detected from {attacker_ip}",
    "Suspicious file upload detected: /uploads/shell.php",
    "Suspicious file upload detected: /uploads/backdoor.jsp",
    "Remote code execution attempt detected on {endpoint}",
    "XSS attack attempt on {endpoint}",
    "Directory traversal attempt: /../../etc/passwd",
    "Credential stuffing attack from {attacker_ip}",
    "Unauthorized API key usage detected",
    "Port scanning detected from {attacker_ip}",
    "Privilege escalation attempt by {user}",
    "Malware signature detected in uploaded file",
    "Command injection attempt on {endpoint}",
    "Session hijacking attempt detected",
    "DNS tunneling activity detected from {attacker_ip}",
    "Suspicious outbound connection to {attacker_ip}",
]

ATTACKER_IPS = ["203.0.113.1", "198.51.100.2", "185.220.101.1", "45.33.32.156"]


def generate_log_entry(timestamp, attack_ratio=0.15):
    """Generate a single log entry — either normal or attack."""
    ip = random.choice(IP_ADDRESSES)
    user = random.choice(USERS)
    method = random.choice(HTTP_METHODS)
    endpoint = random.choice(ENDPOINTS)
    ts = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    is_attack = random.random() < attack_ratio

    if is_attack:
        template = random.choice(ATTACK_EVENTS)
        description = template.format(
            attacker_ip=random.choice(ATTACKER_IPS),
            endpoint=endpoint,
            user=user,
        )
        return f"- {ts} {ip} - {user} [{method} {endpoint}] {description}"
    else:
        response = random.choice(NORMAL_RESPONSES)
        agent = random.choice(USER_AGENTS)
        return f"- {ts} {ip} - {user} [{method} {endpoint}] {response} \"{agent}\""


def generate_log_file(
    output_path,
    count=500,
    start_date=None,
    days=1,
    attack_ratio=0.15,
    title="Server Logs",
):
    """Generate a complete log file with the given parameters."""
    if start_date is None:
        start_date = datetime.now() - timedelta(days=days)

    # Spread entries evenly across the time window
    total_seconds = days * 24 * 3600
    interval = total_seconds / max(count, 1)

    entries = []
    current_time = start_date

    for _ in range(count):
        # Add some jitter to make timestamps realistic
        jitter = random.uniform(0, interval * 0.8)
        entry_time = current_time + timedelta(seconds=jitter)
        entries.append(generate_log_entry(entry_time, attack_ratio))
        current_time += timedelta(seconds=interval)

    # Write to file
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# {title}\n\n")
        for entry in entries:
            f.write(entry + "\n")
        f.write("\n")

    return len(entries)


def main():
    parser = argparse.ArgumentParser(
        description="Security-Log-Analyser — Synthetic Log Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python logs/generate_logs.py
  python logs/generate_logs.py --count 1000 --output logs/large_test.md
  python logs/generate_logs.py --attack-ratio 0.4 --title "High-Threat Server Logs"
  python logs/generate_logs.py --start-date 2024-01-01 --days 30 --count 5000
        """,
    )
    parser.add_argument("--output", "-o", default=None,
                        help="Output file path (default: logs/generated_logs_<timestamp>.md)")
    parser.add_argument("--count", "-n", type=int, default=500,
                        help="Number of log entries to generate (default: 500)")
    parser.add_argument("--start-date", "-s", default=None,
                        help="Start date for logs in YYYY-MM-DD format (default: today)")
    parser.add_argument("--days", "-d", type=int, default=1,
                        help="Number of days to span (default: 1)")
    parser.add_argument("--attack-ratio", "-a", type=float, default=0.15,
                        help="Ratio of attack events 0.0-1.0 (default: 0.15)")
    parser.add_argument("--title", "-t", default="Server Logs",
                        help='Title header in the log file (default: "Server Logs")')

    args = parser.parse_args()

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        logs_dir = os.path.join(os.path.dirname(__file__))
        output_path = os.path.join(logs_dir, f"generated_logs_{ts}.md")

    # Parse start date
    start_date = None
    if args.start_date:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d")

    count = generate_log_file(
        output_path=output_path,
        count=args.count,
        start_date=start_date,
        days=args.days,
        attack_ratio=args.attack_ratio,
        title=args.title,
    )

    print(f"\n✅ Generated {count} log entries")
    print(f"📄 Output: {os.path.abspath(output_path)}")
    print(f"⚔️  Attack ratio: {args.attack_ratio:.0%}")
    print(f"📅 Spanning {args.days} day(s)\n")


if __name__ == "__main__":
    main()
