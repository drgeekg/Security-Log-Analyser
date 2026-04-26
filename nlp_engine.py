"""
Security-Log-Analyser — NLP Computation Engine
Pure-Python log analysis: parsing, attack detection, statistics, and threat scoring.
Zero LLM calls. All computation is deterministic and instant.

Pipeline:
  1. Parse raw log lines → structured records
  2. Detect attacks via regex/keyword patterns
  3. Compute statistics (counts, frequencies, timelines)
  4. Score threats (CVSS-like severity ranking)
  5. Build structured report context for optional LLM narrative
"""

import re
from datetime import datetime
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional


# ═══════════════════════════════════════════════════════════════════
#  1. LOG PARSER — Regex-based structured parsing
# ═══════════════════════════════════════════════════════════════════

# Pattern for normal log lines:
#   - 2024-08-12 14:45:48 198.51.100.2 - bob [PUT /login] "404 Not Found" "curl/7.68.0"
# Pattern for attack log lines:
#   - 2024-08-12 14:45:56 192.168.1.100 - user [CONNECT /index.html] Remote code execution attempt detected on /admin

LOG_LINE_PATTERN = re.compile(
    r'^-\s+'
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<method>\S+)\s+(?P<endpoint>\S+)\]\s+'
    r'(?P<payload>.+)$'
)

NORMAL_PAYLOAD_PATTERN = re.compile(
    r'^"(?P<status_code>\d{3})\s+(?P<status_text>[^"]+)"\s+"(?P<user_agent>[^"]+)"$'
)


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single log line into a structured record, with fallback for standard application logs."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # First attempt: Web/HTTP Security Log Pattern
    match = LOG_LINE_PATTERN.match(line)
    if match:
        record = {
            'timestamp': match.group('timestamp'),
            'ip': match.group('ip'),
            'user': match.group('user'),
            'method': match.group('method'),
            'endpoint': match.group('endpoint'),
            'raw': line,
        }

        # Try to parse as normal HTTP response
        payload = match.group('payload')
        normal_match = NORMAL_PAYLOAD_PATTERN.match(payload)

        if normal_match:
            record['status_code'] = int(normal_match.group('status_code'))
            record['status_text'] = normal_match.group('status_text')
            record['user_agent'] = normal_match.group('user_agent')
            record['is_attack'] = False
            record['attack_type'] = None
            record['attack_description'] = None
        else:
            # It's an attack event (does not match normal HTTP layout)
            record['status_code'] = None
            record['status_text'] = None
            record['user_agent'] = None
            record['is_attack'] = True
            record['attack_description'] = payload
            record['attack_type'] = classify_attack(payload)

    else:
        # Fallback: Generic Server / Application Log (e.g. Hadoop, Syslog)
        time_match = re.search(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})', line)
        if not time_match:
            return None  # Skip entirely if no timestamp can be found
            
        timestamp = time_match.group(1).replace('T', ' ')
        
        record = {
            'timestamp': timestamp,
            'ip': '0.0.0.0', # Default for internal app logs
            'user': 'system',
            'method': 'APP',
            'endpoint': 'ApplicationLog',
            'raw': line,
            'status_code': 200,
            'status_text': 'OK',
            'user_agent': 'Internal System'
        }
        
        # Determine if this generic log line contains an attack/exception natively
        atk_type = classify_attack(line)
        if atk_type != 'Unknown Attack':
            record['is_attack'] = True
            record['attack_type'] = atk_type
            record['attack_description'] = line
            record['status_code'] = None
        else:
            record['is_attack'] = False
            record['attack_type'] = None
            record['attack_description'] = None

    # Parse timestamp into a datetime object for aggregation
    try:
        record['datetime'] = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S')
    except ValueError:
        record['datetime'] = None

    return record


def parse_logs(log_text: str) -> List[Dict[str, Any]]:
    """Parse all lines from raw log text into structured records."""
    records = []
    for line in log_text.splitlines():
        record = parse_log_line(line)
        if record:
            records.append(record)
    return records


# ═══════════════════════════════════════════════════════════════════
#  2. ATTACK DETECTOR — Pattern-matching classification
# ═══════════════════════════════════════════════════════════════════

# Attack classification rules: (pattern, attack_type, severity, cvss_base)
ATTACK_PATTERNS = [
    (re.compile(r'Remote code execution', re.IGNORECASE), 'RCE', 'Critical', 9.8),
    (re.compile(r'SQL\s*Injection', re.IGNORECASE), 'SQL Injection', 'High', 8.6),
    (re.compile(r'Brute\s*force', re.IGNORECASE), 'Brute Force', 'High', 7.5),
    (re.compile(r'DDoS', re.IGNORECASE), 'DDoS', 'High', 7.5),
    (re.compile(r'Credential\s*stuffing', re.IGNORECASE), 'Credential Stuffing', 'High', 7.5),
    (re.compile(r'Command\s*injection', re.IGNORECASE), 'Command Injection', 'High', 8.0),
    (re.compile(r'Directory\s*traversal|\.\./\.\.', re.IGNORECASE), 'Directory Traversal', 'High', 8.6),
    (re.compile(r'IDOR|Insecure\s*direct\s*object', re.IGNORECASE), 'IDOR', 'High', 7.2),
    (re.compile(r'XSS|Cross.?Site\s*Scripting', re.IGNORECASE), 'XSS', 'Medium', 6.1),
    (re.compile(r'CSRF|Cross.?Site\s*Request', re.IGNORECASE), 'CSRF', 'Medium', 6.5),
    (re.compile(r'SSRF|Server\s*Side\s*Request', re.IGNORECASE), 'SSRF', 'High', 8.2),
    (re.compile(r'Suspicious\s*file\s*upload.*shell\.php', re.IGNORECASE), 'Malicious Upload (Web Shell)', 'Critical', 9.8),
    (re.compile(r'Suspicious\s*file\s*upload.*backdoor', re.IGNORECASE), 'Malicious Upload (Backdoor)', 'Critical', 9.8),
    (re.compile(r'Suspicious\s*file\s*upload', re.IGNORECASE), 'Suspicious File Upload', 'High', 7.0),
    (re.compile(r'Port\s*scanning', re.IGNORECASE), 'Port Scanning', 'Medium', 5.3),
    (re.compile(r'Privilege\s*escalation', re.IGNORECASE), 'Privilege Escalation', 'Critical', 8.8),
    (re.compile(r'DNS\s*tunneling', re.IGNORECASE), 'DNS Tunneling', 'High', 7.4),
    (re.compile(r'Session\s*hijacking', re.IGNORECASE), 'Session Hijacking', 'High', 7.5),
    (re.compile(r'Malware\s*signature', re.IGNORECASE), 'Malware Detected', 'Critical', 9.0),
    (re.compile(r'Unauthorized\s*API|API\s*abuse', re.IGNORECASE), 'API Abuse', 'Medium', 6.5),
    (re.compile(r'Suspicious\s*outbound', re.IGNORECASE), 'Suspicious Outbound Connection', 'High', 7.4),
    (re.compile(r'Cryptojacking|xmrig|coinbase', re.IGNORECASE), 'Cryptojacking', 'High', 7.8),
    (re.compile(r'Default\s*credentials|admin/admin|root/root', re.IGNORECASE), 'Default Credentials Usage', 'High', 8.0),
]

# CVSS lookup by attack type
ATTACK_SEVERITY = {p[1]: {'severity': p[2], 'cvss': p[3]} for p in ATTACK_PATTERNS}

# Known malicious user agents
MALICIOUS_USER_AGENTS = {
    'sqlmap': 'SQL Injection Tool',
    'nikto': 'Web Vulnerability Scanner',
    'nmap': 'Network Scanner',
    'dirbuster': 'Directory Brute-Forcer',
    'gobuster': 'Directory Brute-Forcer',
    'hydra': 'Password Cracker',
    'burpsuite': 'Web Security Testing Tool',
    'wpscan': 'WordPress Scanner',
    'masscan': 'Mass Port Scanner',
    'zmap': 'Network Scanner',
    'python-requests': 'Automated Request Script',
    'curl': 'Potential Automated Request',
}


def classify_attack(description: str) -> str:
    """Classify an attack description into an attack type."""
    for pattern, attack_type, _, _ in ATTACK_PATTERNS:
        if pattern.search(description):
            return attack_type
    return 'Unknown Attack'


def detect_malicious_agents(records: List[Dict]) -> List[Dict]:
    """Identify log entries with known malicious user agents."""
    flagged = []
    for rec in records:
        ua = (rec.get('user_agent') or '').lower()
        for agent_key, agent_name in MALICIOUS_USER_AGENTS.items():
            if agent_key in ua:
                flagged.append({
                    **rec,
                    'flagged_agent': agent_name,
                    'agent_key': agent_key,
                })
                break
    return flagged


# ═══════════════════════════════════════════════════════════════════
#  3. STATISTICAL AGGREGATOR — Compute all metrics
# ═══════════════════════════════════════════════════════════════════

def compute_statistics(records: List[Dict]) -> Dict[str, Any]:
    """Compute comprehensive statistics from parsed log records."""
    if not records:
        return _empty_stats()

    total = len(records)
    attacks = [r for r in records if r['is_attack']]
    normal = [r for r in records if not r['is_attack']]

    # ── Basic counts ─────────────────────────────────────────────
    attack_count = len(attacks)
    normal_count = len(normal)

    # ── Attack type breakdown ────────────────────────────────────
    attack_type_counts = Counter(r['attack_type'] for r in attacks)

    # ── Failed logins (401 Unauthorized) ─────────────────────────
    failed_logins = [r for r in normal if r.get('status_code') == 401]
    failed_login_details = []
    for r in failed_logins:
        failed_login_details.append({
            'timestamp': r['timestamp'],
            'ip': r['ip'],
            'user': r['user'],
            'method': r['method'],
            'endpoint': r['endpoint'],
        })

    # ── Status code distribution ─────────────────────────────────
    status_codes = Counter(
        r['status_code'] for r in normal if r.get('status_code')
    )

    # ── IP analysis ──────────────────────────────────────────────
    # Attack events by IP
    attacker_ips = Counter(r['ip'] for r in attacks)
    # All traffic by IP
    all_ips = Counter(r['ip'] for r in records)
    # Failed logins by IP
    failed_login_ips = Counter(r['ip'] for r in failed_logins)

    # IP behavior profiles
    ip_profiles = defaultdict(lambda: {
        'attack_types': Counter(),
        'total_events': 0,
        'attack_events': 0,
        'failed_logins': 0,
        'targeted_endpoints': Counter(),
        'targeted_users': set(),
        'methods': Counter(),
        'first_seen': None,
        'last_seen': None,
    })

    for r in records:
        ip = r['ip']
        profile = ip_profiles[ip]
        profile['total_events'] += 1
        profile['methods'][r['method']] += 1

        dt = r.get('datetime')
        if dt:
            if profile['first_seen'] is None or dt < profile['first_seen']:
                profile['first_seen'] = dt
            if profile['last_seen'] is None or dt > profile['last_seen']:
                profile['last_seen'] = dt

        if r['is_attack']:
            profile['attack_events'] += 1
            profile['attack_types'][r['attack_type']] += 1
            profile['targeted_endpoints'][r['endpoint']] += 1

        if not r['is_attack'] and r.get('status_code') == 401:
            profile['failed_logins'] += 1

        profile['targeted_users'].add(r['user'])

    # Convert sets to lists for serialization
    for ip in ip_profiles:
        ip_profiles[ip]['targeted_users'] = list(ip_profiles[ip]['targeted_users'])

    # ── Endpoint targeting ───────────────────────────────────────
    targeted_endpoints = Counter(r['endpoint'] for r in attacks)

    # ── User targeting ───────────────────────────────────────────
    targeted_users = Counter(r['user'] for r in attacks)

    # ── User-agent analysis ──────────────────────────────────────
    user_agents = Counter(
        r['user_agent'] for r in normal if r.get('user_agent')
    )
    malicious_agent_entries = detect_malicious_agents(normal)

    # ── Timeline analysis ────────────────────────────────────────
    # Bucket attacks by hour
    hourly_attacks = Counter()
    for r in attacks:
        dt = r.get('datetime')
        if dt:
            hourly_attacks[dt.strftime('%Y-%m-%d %H:00')] += 1

    # Bucket by date
    daily_attacks = Counter()
    for r in attacks:
        dt = r.get('datetime')
        if dt:
            daily_attacks[dt.strftime('%Y-%m-%d')] += 1

    # ── Time range ───────────────────────────────────────────────
    timestamps = [r['datetime'] for r in records if r.get('datetime')]
    time_range = {}
    if timestamps:
        time_range = {
            'start': min(timestamps).strftime('%Y-%m-%d %H:%M:%S'),
            'end': max(timestamps).strftime('%Y-%m-%d %H:%M:%S'),
            'duration_hours': round(
                (max(timestamps) - min(timestamps)).total_seconds() / 3600, 2
            ),
        }

    # ── HTTP method distribution ─────────────────────────────────
    methods_all = Counter(r['method'] for r in records)
    methods_attacks = Counter(r['method'] for r in attacks)

    return {
        'summary': {
            'total_log_entries': total,
            'total_attacks': attack_count,
            'total_normal': normal_count,
            'attack_ratio': round(attack_count / total * 100, 1) if total else 0,
            'total_failed_logins': len(failed_logins),
            'unique_ips': len(all_ips),
            'unique_attacker_ips': len(attacker_ips),
            'time_range': time_range,
        },
        'attack_breakdown': dict(attack_type_counts.most_common()),
        'failed_logins': {
            'count': len(failed_logins),
            'by_ip': dict(failed_login_ips.most_common()),
            'details': failed_login_details[:50],  # cap at 50 for display
        },
        'status_codes': dict(status_codes.most_common()),
        'top_attacker_ips': dict(attacker_ips.most_common(20)),
        'ip_profiles': {
            ip: {
                'total_events': p['total_events'],
                'attack_events': p['attack_events'],
                'failed_logins': p['failed_logins'],
                'attack_types': dict(p['attack_types']),
                'top_endpoints': dict(p['targeted_endpoints'].most_common(5)),
                'users_seen': p['targeted_users'],
                'methods': dict(p['methods']),
                'first_seen': p['first_seen'].strftime('%Y-%m-%d %H:%M:%S') if p['first_seen'] else None,
                'last_seen': p['last_seen'].strftime('%Y-%m-%d %H:%M:%S') if p['last_seen'] else None,
            }
            for ip, p in sorted(
                ip_profiles.items(),
                key=lambda x: x[1]['attack_events'],
                reverse=True,
            )[:20]  # top 20 IPs
        },
        'targeted_endpoints': dict(targeted_endpoints.most_common(15)),
        'targeted_users': dict(targeted_users.most_common(15)),
        'user_agents': {
            'distribution': dict(user_agents.most_common(15)),
            'malicious_count': len(malicious_agent_entries),
            'malicious_agents': [
                {
                    'timestamp': e['timestamp'],
                    'ip': e['ip'],
                    'user': e['user'],
                    'agent': e.get('user_agent', ''),
                    'tool': e['flagged_agent'],
                }
                for e in malicious_agent_entries[:30]
            ],
        },
        'timeline': {
            'hourly': dict(sorted(hourly_attacks.items())),
            'daily': dict(sorted(daily_attacks.items())),
        },
        'methods': {
            'all_traffic': dict(methods_all.most_common()),
            'attack_traffic': dict(methods_attacks.most_common()),
        },
    }


def _empty_stats():
    """Return empty stats structure."""
    return {
        'summary': {
            'total_log_entries': 0, 'total_attacks': 0, 'total_normal': 0,
            'attack_ratio': 0, 'total_failed_logins': 0,
            'unique_ips': 0, 'unique_attacker_ips': 0, 'time_range': {},
        },
        'attack_breakdown': {},
        'failed_logins': {'count': 0, 'by_ip': {}, 'details': []},
        'status_codes': {},
        'top_attacker_ips': {},
        'ip_profiles': {},
        'targeted_endpoints': {},
        'targeted_users': {},
        'user_agents': {'distribution': {}, 'malicious_count': 0, 'malicious_agents': []},
        'timeline': {'hourly': {}, 'daily': {}},
        'methods': {'all_traffic': {}, 'attack_traffic': {}},
    }


# ═══════════════════════════════════════════════════════════════════
#  4. THREAT SCORER — CVSS-like scoring
# ═══════════════════════════════════════════════════════════════════

def score_threats(records: List[Dict], stats: Dict) -> List[Dict]:
    """
    Score and rank threats by computed severity.
    Uses: base CVSS × log(frequency) × IP diversity factor
    """
    attack_breakdown = stats.get('attack_breakdown', {})
    if not attack_breakdown:
        return []

    attacks = [r for r in records if r['is_attack']]

    threats = []
    for attack_type, count in attack_breakdown.items():
        # Base CVSS score
        info = ATTACK_SEVERITY.get(attack_type, {'severity': 'Medium', 'cvss': 5.0})
        base_cvss = info['cvss']
        severity = info['severity']

        # IP diversity: how many unique IPs launched this attack
        ips_involved = set(r['ip'] for r in attacks if r['attack_type'] == attack_type)
        ip_count = len(ips_involved)

        # Targeted endpoints
        endpoints_targeted = set(r['endpoint'] for r in attacks if r['attack_type'] == attack_type)

        # Frequency factor: log-scale boost for repeated attacks
        import math
        freq_factor = 1 + math.log2(max(count, 1)) * 0.1

        # IP diversity factor: more IPs = more coordinated = worse
        ip_factor = 1 + (ip_count - 1) * 0.05

        # Adjusted score (cap at 10.0)
        adjusted_score = min(10.0, round(base_cvss * freq_factor * ip_factor, 1))

        threats.append({
            'attack_type': attack_type,
            'count': count,
            'base_cvss': base_cvss,
            'adjusted_score': adjusted_score,
            'severity': severity,
            'source_ips': sorted(ips_involved),
            'ip_count': ip_count,
            'endpoints_targeted': sorted(endpoints_targeted),
            'example_entries': [
                {
                    'timestamp': r['timestamp'],
                    'ip': r['ip'],
                    'user': r['user'],
                    'endpoint': r['endpoint'],
                    'description': r.get('attack_description', ''),
                }
                for r in attacks if r['attack_type'] == attack_type
            ][:5],  # up to 5 examples
        })

    # Sort by adjusted score descending
    threats.sort(key=lambda t: t['adjusted_score'], reverse=True)

    # Assign rank
    for i, t in enumerate(threats):
        t['rank'] = i + 1

    return threats


# ═══════════════════════════════════════════════════════════════════
#  5. REPORT CONTEXT BUILDER — Structured data for LLM
# ═══════════════════════════════════════════════════════════════════

def build_report_context(
    records: List[Dict],
    stats: Dict,
    threats: List[Dict],
    user_query: str = "",
) -> str:
    """
    Build a structured text context from the NLP-computed data.
    This is fed to the LLM in a single prompt for narrative generation.
    """
    lines = []
    summary = stats['summary']

    lines.append("=" * 60)
    lines.append("NLP-COMPUTED SECURITY LOG ANALYSIS DATA")
    lines.append("=" * 60)

    if user_query:
        lines.append(f"\nUser Query: {user_query}")

    # ── Summary ──────────────────────────────────────────────────
    lines.append("\n## LOG SUMMARY")
    lines.append(f"- Total log entries: {summary['total_log_entries']}")
    lines.append(f"- Attack events: {summary['total_attacks']} ({summary['attack_ratio']}%)")
    lines.append(f"- Normal events: {summary['total_normal']}")
    lines.append(f"- Failed logins (401): {summary['total_failed_logins']}")
    lines.append(f"- Unique IPs: {summary['unique_ips']}")
    lines.append(f"- Unique attacker IPs: {summary['unique_attacker_ips']}")
    tr = summary.get('time_range', {})
    if tr:
        lines.append(f"- Time range: {tr.get('start', '?')} to {tr.get('end', '?')} ({tr.get('duration_hours', '?')} hours)")

    # ── Attack Breakdown ─────────────────────────────────────────
    lines.append("\n## ATTACK TYPE BREAKDOWN")
    for atype, count in stats['attack_breakdown'].items():
        info = ATTACK_SEVERITY.get(atype, {'severity': '?', 'cvss': '?'})
        lines.append(f"- {atype}: {count} events (Severity: {info['severity']}, CVSS: {info['cvss']})")

    # ── Top Attacker IPs ─────────────────────────────────────────
    lines.append("\n## TOP ATTACKER IPs")
    for ip, count in stats['top_attacker_ips'].items():
        profile = stats['ip_profiles'].get(ip, {})
        attack_types = profile.get('attack_types', {})
        types_str = ', '.join(f"{t}({c})" for t, c in attack_types.items()) if attack_types else 'N/A'
        lines.append(f"- {ip}: {count} attacks [{types_str}]")

    # ── Failed Logins ────────────────────────────────────────────
    fl = stats['failed_logins']
    lines.append(f"\n## FAILED LOGINS: {fl['count']} total")
    if fl['by_ip']:
        lines.append("By IP:")
        for ip, count in fl['by_ip'].items():
            lines.append(f"  - {ip}: {count} failed logins")
    if fl['details']:
        lines.append("Sample entries:")
        for d in fl['details'][:15]:
            lines.append(f"  - [{d['timestamp']}] {d['ip']} → {d['user']} {d['method']} {d['endpoint']}")

    # ── Threat Rankings ──────────────────────────────────────────
    lines.append("\n## THREAT RANKINGS (by computed severity)")
    for t in threats:
        lines.append(
            f"  #{t['rank']} {t['attack_type']} — Score: {t['adjusted_score']}/10 "
            f"({t['severity']}) — {t['count']} events from {t['ip_count']} IPs"
        )
        lines.append(f"       Source IPs: {', '.join(t['source_ips'])}")
        lines.append(f"       Targets: {', '.join(t['endpoints_targeted'])}")

    # ── Malicious User Agents ────────────────────────────────────
    ua = stats['user_agents']
    if ua['malicious_count'] > 0:
        lines.append(f"\n## MALICIOUS USER AGENTS: {ua['malicious_count']} entries")
        for agent in ua['malicious_agents'][:10]:
            lines.append(f"  - [{agent['timestamp']}] {agent['ip']} using {agent['tool']} ({agent['agent']})")

    # ── Targeted Endpoints ───────────────────────────────────────
    lines.append("\n## MOST TARGETED ENDPOINTS")
    for ep, count in stats['targeted_endpoints'].items():
        lines.append(f"  - {ep}: {count} attacks")

    # ── Status Code Distribution ─────────────────────────────────
    lines.append("\n## HTTP STATUS CODE DISTRIBUTION")
    for code, count in stats['status_codes'].items():
        lines.append(f"  - {code}: {count}")

    # ── Timeline ─────────────────────────────────────────────────
    timeline = stats['timeline']
    if timeline.get('daily'):
        lines.append("\n## ATTACK TIMELINE (daily)")
        for day, count in timeline['daily'].items():
            lines.append(f"  - {day}: {count} attacks")

    # ── Raw Problematic Logs ─────────────────────────────────────
    lines.append("\n## RAW PROBLEMATIC LOGS (For deep behavioral & payload context - Max 500 lines)")
    
    # Get malicious timestamps to include scanner probes
    malicious_ua_timestamps = {a['timestamp'] for a in ua['malicious_agents']} if ua.get('malicious_agents') else set()
    
    problematic_lines = []
    for r in records:
        is_prob = r.get('is_attack') or r.get('status_code') == 401 or r.get('timestamp') in malicious_ua_timestamps
        if is_prob:
            problematic_lines.append(r.get('raw', ''))
            
    if len(problematic_lines) > 500:
        lines.append(f"*(Sampled 500 lines out of {len(problematic_lines)} total problematic events)*")
        # Uniform sampling to preserve timeline distribution
        step = len(problematic_lines) / 500.0
        sampled_lines = []
        for i in range(500):
            idx = int(i * step)
            if idx < len(problematic_lines):
                sampled_lines.append(problematic_lines[idx])
        problematic_lines = sampled_lines

    for raw_line in problematic_lines:
        lines.append(raw_line)

    lines.append("\n" + "=" * 60)

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
#  6. CONVENIENCE: Full analysis pipeline
# ═══════════════════════════════════════════════════════════════════

def full_analysis(log_text: str, user_query: str = "") -> Dict[str, Any]:
    """
    Run the complete NLP analysis pipeline.
    Returns structured data (stats, threats, context string).
    No LLM calls — pure computation.
    """
    records = parse_logs(log_text)
    stats = compute_statistics(records)
    threats = score_threats(records, stats)
    context = build_report_context(records, stats, threats, user_query)

    return {
        'records': records,
        'stats': stats,
        'threats': threats,
        'context': context,
        'record_count': len(records),
    }
