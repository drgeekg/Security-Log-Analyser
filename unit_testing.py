"""
Security-Log-Analyser — Unit Tests
Automated test suite for validating the NLP engine accuracy (deterministic, no LLM needed)
and optional LLM integration tests.
"""

import os
import sys
import time
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

load_dotenv()

from nlp_engine import (
    parse_log_line,
    parse_logs,
    classify_attack,
    detect_malicious_agents,
    compute_statistics,
    score_threats,
    full_analysis,
)
from main import load_log_file, LOG_DIRECTORY


# ═══════════════════════════════════════════════════════════════════
#  NLP ENGINE TESTS (deterministic — no LLM)
# ═══════════════════════════════════════════════════════════════════

def test_parse_normal_line():
    """Test parsing a normal HTTP log line."""
    line = '- 2024-08-12 14:45:48 198.51.100.2 - bob [PUT /login] "404 Not Found" "curl/7.68.0"'
    result = parse_log_line(line)

    assert result is not None, "Failed to parse normal line"
    assert result['ip'] == '198.51.100.2', f"IP mismatch: {result['ip']}"
    assert result['user'] == 'bob', f"User mismatch: {result['user']}"
    assert result['method'] == 'PUT', f"Method mismatch: {result['method']}"
    assert result['endpoint'] == '/login', f"Endpoint mismatch: {result['endpoint']}"
    assert result['status_code'] == 404, f"Status code mismatch: {result['status_code']}"
    assert result['user_agent'] == 'curl/7.68.0', f"User agent mismatch: {result['user_agent']}"
    assert result['is_attack'] is False, "Should not be an attack"
    return True


def test_parse_attack_line():
    """Test parsing an attack log line."""
    line = '- 2024-08-12 14:46:25 10.0.0.1 - guest [DELETE /index.html] Brute force attack detected from 203.0.113.1'
    result = parse_log_line(line)

    assert result is not None, "Failed to parse attack line"
    assert result['ip'] == '10.0.0.1', f"IP mismatch: {result['ip']}"
    assert result['user'] == 'guest', f"User mismatch: {result['user']}"
    assert result['is_attack'] is True, "Should be an attack"
    assert result['attack_type'] == 'Brute Force', f"Attack type mismatch: {result['attack_type']}"
    return True


def test_parse_rce_line():
    """Test parsing an RCE attack line."""
    line = '- 2024-08-12 14:45:56 192.168.1.100 - user [CONNECT /index.html] Remote code execution attempt detected on /admin'
    result = parse_log_line(line)

    assert result is not None, "Failed to parse RCE line"
    assert result['is_attack'] is True, "Should be an attack"
    assert result['attack_type'] == 'RCE', f"Attack type mismatch: {result['attack_type']}"
    return True


def test_parse_sqli_line():
    """Test parsing SQL injection attack line."""
    line = '- 2024-08-12 14:49:17 10.0.0.1 - john [POST /login] SQL Injection attempt on /login'
    result = parse_log_line(line)

    assert result is not None, "Failed to parse SQLi line"
    assert result['is_attack'] is True, "Should be an attack"
    assert result['attack_type'] == 'SQL Injection', f"Attack type mismatch: {result['attack_type']}"
    return True


def test_parse_xss_line():
    """Test parsing XSS attack line."""
    line = '- 2024-08-12 14:49:31 198.51.100.2 - user [OPTIONS /uploads/file1.jpg] XSS attack attempt on /index.html'
    result = parse_log_line(line)

    assert result is not None, "Failed to parse XSS line"
    assert result['is_attack'] is True
    assert result['attack_type'] == 'XSS', f"Attack type mismatch: {result['attack_type']}"
    return True


def test_parse_file_upload_line():
    """Test parsing suspicious file upload line."""
    line = '- 2024-08-12 14:46:50 10.0.0.150 - user [CONNECT /admin] Suspicious file upload detected: /uploads/shell.php'
    result = parse_log_line(line)

    assert result is not None, "Failed to parse file upload line"
    assert result['is_attack'] is True
    assert 'Malicious Upload' in result['attack_type'] or 'shell' in result['attack_type'].lower(), \
        f"Attack type mismatch: {result['attack_type']}"
    return True


def test_parse_ddos_line():
    """Test parsing DDoS attack line."""
    line = '- 2024-08-12 14:46:01 172.16.0.1 - user [OPTIONS /uploads/file1.jpg] DDoS attack pattern detected from 198.51.100.2'
    result = parse_log_line(line)

    assert result is not None, "Failed to parse DDoS line"
    assert result['is_attack'] is True
    assert result['attack_type'] == 'DDoS', f"Attack type mismatch: {result['attack_type']}"
    return True


def test_skip_header_lines():
    """Test that header/comment lines are skipped."""
    result1 = parse_log_line("# Server Logs")
    result2 = parse_log_line("")
    result3 = parse_log_line("   ")

    assert result1 is None, "Should skip comment lines"
    assert result2 is None, "Should skip empty lines"
    assert result3 is None, "Should skip whitespace lines"
    return True


def test_classify_attacks():
    """Test attack classification for various descriptions."""
    tests = [
        ("Brute force attack detected from 203.0.113.1", "Brute Force"),
        ("SQL Injection attempt on /login", "SQL Injection"),
        ("DDoS attack pattern detected from 198.51.100.2", "DDoS"),
        ("Remote code execution attempt detected on /admin", "RCE"),
        ("XSS attack attempt on /index.html", "XSS"),
        ("Suspicious file upload detected: /uploads/shell.php", "Malicious Upload (Web Shell)"),
        ("Directory traversal attempt: /../../etc/passwd", "Directory Traversal"),
        ("Credential stuffing attack from 203.0.113.1", "Credential Stuffing"),
        ("Port scanning detected from 45.33.32.156", "Port Scanning"),
        ("Privilege escalation attempt by root", "Privilege Escalation"),
        ("Command injection attempt on /api/data", "Command Injection"),
        ("DNS tunneling activity detected from 203.0.113.1", "DNS Tunneling"),
        ("Server Side Request Forgery attempt on webhook endpoint", "SSRF"),
        ("Insecure direct object reference on user_id=123", "IDOR"),
        ("API abuse detected: rate limit exceeded heavily", "API Abuse"),
        ("Cryptojacking script detected in payload", "Cryptojacking"),
    ]

    for description, expected_type in tests:
        result = classify_attack(description)
        assert result == expected_type, f"Classification mismatch for '{description}': got '{result}', expected '{expected_type}'"
    return True


def test_malicious_agent_detection():
    """Test malicious user agent detection."""
    records = [
        {'user_agent': 'sqlmap/1.6', 'timestamp': '2024-01-01', 'ip': '1.2.3.4', 'user': 'test', 'is_attack': False},
        {'user_agent': 'Mozilla/5.0', 'timestamp': '2024-01-01', 'ip': '1.2.3.5', 'user': 'test', 'is_attack': False},
        {'user_agent': 'Nikto/2.1.6', 'timestamp': '2024-01-01', 'ip': '1.2.3.6', 'user': 'test', 'is_attack': False},
        {'user_agent': 'Nmap Scripting Engine', 'timestamp': '2024-01-01', 'ip': '1.2.3.7', 'user': 'test', 'is_attack': False},
        {'user_agent': 'curl/7.68.0', 'timestamp': '2024-01-01', 'ip': '1.2.3.8', 'user': 'test', 'is_attack': False},
    ]

    flagged = detect_malicious_agents(records)
    assert len(flagged) == 3, f"Expected 3 malicious agents, got {len(flagged)}"
    return True


def test_statistics_computation():
    """Test that statistics are computed correctly from parsed logs."""
    log_text = """# Test Logs
- 2024-08-12 14:45:48 198.51.100.2 - bob [PUT /login] "401 Unauthorized" "curl/7.68.0"
- 2024-08-12 14:45:49 172.16.0.150 - guest [PUT /api/data] "200 OK" "Python-urllib/3.8"
- 2024-08-12 14:45:50 10.0.0.1 - john [GET /admin] Brute force attack detected from 203.0.113.1
- 2024-08-12 14:45:51 192.168.1.1 - alice [POST /login] SQL Injection attempt on /login
- 2024-08-12 14:45:52 10.0.0.150 - user [CONNECT /admin] Remote code execution attempt detected on /admin
- 2024-08-12 14:45:53 198.51.100.2 - bob [GET /index.html] "401 Unauthorized" "sqlmap/1.6"
"""

    records = parse_logs(log_text)
    stats = compute_statistics(records)

    assert stats['summary']['total_log_entries'] == 6, f"Expected 6 entries, got {stats['summary']['total_log_entries']}"
    assert stats['summary']['total_attacks'] == 3, f"Expected 3 attacks, got {stats['summary']['total_attacks']}"
    assert stats['summary']['total_normal'] == 3, f"Expected 3 normal, got {stats['summary']['total_normal']}"
    assert stats['summary']['total_failed_logins'] == 2, f"Expected 2 failed logins, got {stats['summary']['total_failed_logins']}"
    assert stats['attack_breakdown']['Brute Force'] == 1, "Expected 1 brute force"
    assert stats['attack_breakdown']['SQL Injection'] == 1, "Expected 1 SQL injection"
    assert stats['attack_breakdown']['RCE'] == 1, "Expected 1 RCE"
    assert stats['user_agents']['malicious_count'] == 1, f"Expected 1 malicious agent, got {stats['user_agents']['malicious_count']}"
    return True


def test_threat_scoring():
    """Test threat scoring produces ranked results."""
    log_text = """# Test Logs
- 2024-08-12 14:45:50 10.0.0.1 - john [GET /admin] Brute force attack detected from 203.0.113.1
- 2024-08-12 14:45:51 192.168.1.1 - alice [POST /login] SQL Injection attempt on /login
- 2024-08-12 14:45:52 10.0.0.150 - user [CONNECT /admin] Remote code execution attempt detected on /admin
- 2024-08-12 14:45:53 10.0.0.1 - bob [GET /login] Brute force attack detected from 203.0.113.1
"""

    records = parse_logs(log_text)
    stats = compute_statistics(records)
    threats = score_threats(records, stats)

    assert len(threats) == 3, f"Expected 3 threat types, got {len(threats)}"
    # RCE should be ranked highest (9.8 CVSS)
    assert threats[0]['attack_type'] == 'RCE', f"Expected RCE as top threat, got {threats[0]['attack_type']}"
    assert threats[0]['rank'] == 1, "RCE should be rank 1"
    # All threats should have a score
    for t in threats:
        assert t['adjusted_score'] > 0, f"Score should be > 0 for {t['attack_type']}"
    return True


def test_full_analysis_pipeline():
    """Test the full NLP analysis pipeline end-to-end."""
    log_text = """# Test Logs
- 2024-08-12 14:45:48 198.51.100.2 - bob [PUT /login] "401 Unauthorized" "curl/7.68.0"
- 2024-08-12 14:45:50 10.0.0.1 - john [GET /admin] Brute force attack detected from 203.0.113.1
- 2024-08-12 14:45:51 192.168.1.1 - alice [POST /login] SQL Injection attempt on /login
"""

    result = full_analysis(log_text, "What attacks were detected?")

    assert result['record_count'] == 3, f"Expected 3 records, got {result['record_count']}"
    assert 'stats' in result, "Missing stats"
    assert 'threats' in result, "Missing threats"
    assert 'context' in result, "Missing context"
    assert len(result['context']) > 100, "Context should be substantial"
    assert 'Brute Force' in result['context'], "Context should mention Brute Force"
    assert 'SQL Injection' in result['context'], "Context should mention SQL Injection"
    return True


# ═══════════════════════════════════════════════════════════════════
#  REAL LOG FILE TEST
# ═══════════════════════════════════════════════════════════════════

def test_real_log_file():
    """Test NLP analysis against a real log file (if available)."""
    log_dir = LOG_DIRECTORY
    log_files = [f for f in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, f))]

    if not log_files:
        print("  ⚠ No log files found — skipping real file test")
        return True

    log_file_path = os.path.join(log_dir, log_files[0])
    log_text = load_log_file(log_file_path)

    start = time.time()
    result = full_analysis(log_text, "Comprehensive security analysis")
    elapsed = time.time() - start

    stats = result['stats']
    print(f"\n  📄 File: {log_files[0]}")
    print(f"  ⏱  NLP analysis time: {elapsed:.3f}s")
    print(f"  📊 Total entries: {stats['summary']['total_log_entries']}")
    print(f"  🚨 Attacks: {stats['summary']['total_attacks']} ({stats['summary']['attack_ratio']}%)")
    print(f"  🔐 Failed logins: {stats['summary']['total_failed_logins']}")
    print(f"  🌐 Unique IPs: {stats['summary']['unique_ips']}")
    print(f"  🎯 Attack types: {len(stats['attack_breakdown'])}")
    for atype, count in stats['attack_breakdown'].items():
        print(f"      - {atype}: {count}")

    assert stats['summary']['total_log_entries'] > 0, "Should have parsed entries"
    assert elapsed < 10.0, f"NLP analysis should be under 10s, took {elapsed:.2f}s"
    return True


# ═══════════════════════════════════════════════════════════════════
#  TEST RUNNER
# ═══════════════════════════════════════════════════════════════════

def run_tests():
    """Run the full test suite."""
    print(f"\n{'='*60}")
    print(f"  Security-Log-Analyser — NLP Engine Test Suite")
    print(f"{'='*60}\n")

    tests = [
        ("Parse normal log line", test_parse_normal_line),
        ("Parse attack log line (Brute Force)", test_parse_attack_line),
        ("Parse attack log line (RCE)", test_parse_rce_line),
        ("Parse attack log line (SQL Injection)", test_parse_sqli_line),
        ("Parse attack log line (XSS)", test_parse_xss_line),
        ("Parse attack log line (File Upload)", test_parse_file_upload_line),
        ("Parse attack log line (DDoS)", test_parse_ddos_line),
        ("Skip header/comment lines", test_skip_header_lines),
        ("Classify attack descriptions", test_classify_attacks),
        ("Malicious user agent detection", test_malicious_agent_detection),
        ("Statistics computation", test_statistics_computation),
        ("Threat scoring", test_threat_scoring),
        ("Full analysis pipeline", test_full_analysis_pipeline),
        ("Real log file analysis", test_real_log_file),
    ]

    passed = 0
    failed = 0

    for name, test_fn in tests:
        print(f"  Test: {name}")
        try:
            result = test_fn()
            if result:
                passed += 1
                print(f"  \033[92m  ✓ PASSED\033[0m")
            else:
                failed += 1
                print(f"  \033[91m  ✗ FAILED\033[0m")
        except Exception as e:
            failed += 1
            print(f"  \033[91m  ✗ ERROR — {str(e)}\033[0m")

    print(f"\n{'='*60}")
    print(f"\033[94m  Tests Passed: {passed}\033[0m")
    print(f"\033[94m  Tests Failed: {failed}\033[0m")
    print(f"\033[94m  Total:        {passed + failed}\033[0m")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    run_tests()
