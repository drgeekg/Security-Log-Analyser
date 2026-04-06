"""
Security-Log-Analyser — Unit Tests
Automated test suite for validating the multi-LLM analysis pipeline accuracy.
"""

import os
import sys
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

load_dotenv()

from langchain_ollama import ChatOllama
from main import (
    load_log_file,
    query_logs,
    OLLAMA_BASE_URL,
    SYNTHESIS_MODEL,
    LOG_DIRECTORY,
)

# Evaluation prompt for comparing actual vs expected results
EVAL_PROMPT = """
Expected Answer: {expected_response}
Actual Answer: {actual_response}
---
(Answer with 'true' or 'false') Does the actual answer match the expected answer?
"""


def query_and_validate(log_text, question: str, expected_response: str):
    """Query using the multi-LLM pipeline and validate the result against the expected answer."""
    response_text = query_logs(log_text, question)

    prompt = EVAL_PROMPT.format(
        expected_response=expected_response,
        actual_response=response_text,
    )

    model = ChatOllama(
        model=SYNTHESIS_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,
    )
    evaluation_result = model.invoke(prompt)

    # Handle both string and AIMessage responses
    if hasattr(evaluation_result, "content"):
        result_str = evaluation_result.content.strip().lower()
    else:
        result_str = str(evaluation_result).strip().lower()

    if "true" in result_str:
        return True, response_text
    elif "false" in result_str:
        return False, response_text
    else:
        raise ValueError(
            f"Invalid evaluation result. Could not determine 'true' or 'false'. Got: {result_str}"
        )


def run_tests(log_file_path):
    """Run the full test suite against a log file."""
    print(f"\n{'='*60}")
    print(f"  Security-Log-Analyser — Test Suite")
    print(f"  Log file: {log_file_path}")
    print(f"{'='*60}\n")

    print("Loading log file...")
    log_text = load_log_file(log_file_path)
    print(f"Loaded {len(log_text.splitlines())} lines.\n")

    tests = [
        ("How many failed login attempts are there?", "9"),
        ("How many brute force attacks were detected?", "8"),
        ("How many SQL injection attempts were detected?", "5"),
        ("How many DDoS attacks were detected?", "5"),
        ("How many suspicious file upload attempts were detected?", "6"),
        ("Which IP attempted remote code execution?", "192.168.1.100"),
        ("Which IP performed the most attack attempts?", "203.0.113.1"),
    ]

    passed = 0
    failed = 0

    for question, expected in tests:
        print(f"\nTest: {question}")
        try:
            result, actual = query_and_validate(log_text, question, expected)
            if result:
                passed += 1
                print("\033[92m  ✓ PASSED\033[0m")
            else:
                failed += 1
                print(f"\033[91m  ✗ FAILED — Expected: {expected}, Got: {actual}\033[0m")
        except Exception as e:
            failed += 1
            print(f"\033[91m  ✗ ERROR — {str(e)}\033[0m")

    print(f"\n{'='*60}")
    print(f"\033[94m  Tests Passed: {passed}\033[0m")
    print(f"\033[94m  Tests Failed: {failed}\033[0m")
    print(f"\033[94m  Total:        {passed + failed}\033[0m")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    log_dir = LOG_DIRECTORY
    log_files = [f for f in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, f))]

    if not log_files:
        print("No log files found in the logs directory.")
    else:
        log_file_path = os.path.join(log_dir, log_files[0])
        print(f"Using log file: {log_file_path}")
        run_tests(log_file_path)
