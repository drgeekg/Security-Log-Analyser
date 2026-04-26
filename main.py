"""
Security-Log-Analyser — Core Analysis Engine (NLP-First Architecture)
Hybrid NLP-computation + LLM pipeline for fast, accurate log analysis.

Pipeline:
  1. NLP Engine: Parse → Detect → Aggregate → Score  (instant, ~1-3 seconds)
  2. LLM Synthesis: Generate narrative report            (1 call, ~30-90 seconds)

This replaces the previous multi-LLM pipeline (17+ calls, ~45 minutes)
with a single LLM call. All counting, detection, and statistics are
computed deterministically by the NLP engine.
"""

import os
import json
from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

import nlp_engine

# Load environment variables
load_dotenv()

# ── Configuration from .env ─────────────────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
REPORT_MODEL = os.getenv("REPORT_MODEL", "gpt-oss:120b-cloud")
LOG_DIRECTORY = os.getenv("LOG_DIRECTORY", "./logs")
NLP_STATS_ONLY = os.getenv("NLP_STATS_ONLY", "false").lower() == "true"


# ═══════════════════════════════════════════════════════════════════
#  REPORT GENERATION PROMPT — Single LLM call
# ═══════════════════════════════════════════════════════════════════

REPORT_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "You are a Senior Security Operations Center (SOC) Analyst.\n"
     "Your task is NOT just to classify logs, but to perform full threat intelligence analysis.\n"
     "You will be given structured or unstructured application/server logs along with computed NLP stats.\n\n"
     "---\n\n"
     "## STEP 1: PARSE & STRUCTURE\n"
     "From each log entry, extract:\n"
     "* timestamp\n"
     "* source IP\n"
     "* user/account\n"
     "* HTTP method\n"
     "* endpoint/path\n"
     "* status code (if present)\n"
     "* user-agent/tool (if present)\n"
     "* detected attack phrase (if any)\n\n"
     "---\n\n"
     "## STEP 2: DETECT EVENTS\n"
     "Classify each log into ONE OR MORE of the following categories:\n"
     "* SQL Injection\n"
     "* Remote Code Execution (RCE)\n"
     "* Cross-Site Scripting (XSS)\n"
     "* Command Injection\n"
     "* Directory Traversal\n"
     "* Privilege Escalation\n"
     "* Credential Stuffing\n"
     "* Brute Force\n"
     "* Session Hijacking\n"
     "* API Abuse\n"
     "* DDoS Pattern\n"
     "* DNS Tunneling\n"
     "* Malicious Upload (Web Shell / Backdoor)\n"
     "* Port Scanning\n"
     "* Suspicious Outbound Connection\n\n"
     "IMPORTANT:\n"
     "* “User-agent tools” (curl, sqlmap, Nmap, etc.) are NOT attacks.\n"
     "* Treat them as indicators, not categories.\n\n"
     "---\n\n"
     "## STEP 3: BUILD ATTACKER PROFILES (CRITICAL)\n"
     "Group logs by source IP.\n"
     "For each IP:\n"
     "* total requests\n"
     "* total attacks\n"
     "* attack types involved\n"
     "* endpoints targeted\n"
     "* tools used (user-agents)\n"
     "* failed login count\n\n"
     "Then identify:\n"
     "* top attacker IPs\n"
     "* percentage of total attacks per IP\n\n"
     "---\n\n"
     "## STEP 4: DETECT CAMPAIGNS (VERY IMPORTANT)\n"
     "Identify whether attacks are:\n"
     "* isolated\n"
     "* or part of a coordinated campaign\n\n"
     "Look for:\n"
     "* same IP performing multiple attack types\n"
     "* repeated targeting of /api/* or auth endpoints\n"
     "* repeated HTTP verbs (POST, PATCH, OPTIONS)\n"
     "* combination of:\n"
     "  * failed logins + token access\n"
     "  * scanning + exploitation\n"
     "  * upload + privilege escalation\n\n"
     "Output:\n"
     "* “multi-stage attack chain” if present\n\n"
     "---\n\n"
     "## STEP 5: BEHAVIORAL ANALYSIS\n"
     "Detect:\n"
     "* rate-limit bypass patterns\n"
     "* aggressive scraping behavior\n"
     "* automated tooling (based on user-agent)\n"
     "* burst traffic from same IP\n\n"
     "---\n\n"
     "## STEP 6: SEVERITY PRIORITIZATION\n"
     "Assign severity:\n"
     "Critical: RCE, Privilege Escalation, Malicious Upload\n"
     "High: SQL Injection, Credential Stuffing, Brute Force\n"
     "Medium: API Abuse, XSS, Command Injection\n"
     "Low: Port Scanning, Recon activity\n\n"
     "---\n\n"
     "## STEP 7: OUTPUT FORMAT (STRICT)\n"
     "Return output in THIS STRUCTURE:\n\n"
     "### 1. Executive Summary\n"
     "- Total logs\n"
     "- Total attacks (%)\n"
     "- Unique attacker IPs\n"
     "- Key observation (1–2 lines)\n\n"
     "### 2. Attack Distribution\n"
     "(list counts per attack type)\n\n"
     "### 3. Attacker Analysis\n"
     "- Top attacker IPs\n"
     "- % contribution\n"
     "- behavior summary per IP\n\n"
     "### 4. Campaign Analysis\n"
     "State clearly:\n"
     "- Is this a coordinated attack? (YES/NO)\n"
     "- Evidence\n\n"
     "### 5. Behavioral Insights\n"
     "- automation indicators\n"
     "- scraping patterns\n"
     "- rate-limit bypass signs\n\n"
     "### 6. Threat Prioritization\n"
     "Rank top threats with reasoning\n\n"
     "### 7. Key Risks\n"
     "Explain what attackers are trying to achieve\n\n"
     "### 8. Recommendations\n"
     "Give immediate actions and medium-term fixes\n\n"
     "---\n\n"
     "## CRITICAL RULES\n"
     "* Do NOT just list numbers\n"
     "* Always explain WHY something is happening\n"
     "* Correlate events across logs\n"
     "* Think like an attacker AND defender\n"
     "* Prefer insights over raw counts\n\n"
     "Your output should read like a professional SOC report. Answer the User Question contextually if one is provided."
     ),
    ("human",
     "User Question: {question}\n\n"
     "Provided Log Data & NLP Pre-computation Context:\n"
     "{analysis_data}\n\n"
     "Execute the SOC Analyst task using the strict output format required above:"),
])


# ── Helper: LLM factory ────────────────────────────────────────────
def get_report_llm(streaming=False):
    """Create a ChatOllama instance for report generation."""
    return ChatOllama(
        model=REPORT_MODEL,
        base_url=OLLAMA_BASE_URL,
        streaming=streaming,
        temperature=0.2,
    )


# ── Log loading & file listing ──────────────────────────────────────
def load_log_file(file_path):
    """Read the raw text content of a log file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def list_log_files(directory=None):
    """Return a list of log filenames in the log directory."""
    log_dir = directory or LOG_DIRECTORY
    if not os.path.isdir(log_dir):
        return []
    return [
        f for f in os.listdir(log_dir)
        if os.path.isfile(os.path.join(log_dir, f))
    ]


# ═══════════════════════════════════════════════════════════════════
#  ANALYSIS PIPELINE — NLP + Single LLM Call
# ═══════════════════════════════════════════════════════════════════

def analyze_logs(log_text: str, query: str) -> dict:
    """
    Run the full NLP analysis pipeline.
    Returns the NLP-computed stats, threats, and context.
    """
    return nlp_engine.full_analysis(log_text, query)


def query_logs(log_text: str, query: str) -> str:
    """
    Run NLP analysis + LLM report generation (non-streaming).
    Returns the complete report string.
    """
    # Step 1: NLP computation (instant)
    analysis = analyze_logs(log_text, query)

    if NLP_STATS_ONLY:
        return analysis['context']

    # Step 2: Single LLM call for narrative report
    llm = get_report_llm(streaming=False)
    chain = REPORT_PROMPT | llm | StrOutputParser()
    report = chain.invoke({
        "question": query,
        "analysis_data": analysis['context'],
    })

    return report


def query_logs_stream(log_text: str, query: str):
    """
    Run NLP analysis + stream the LLM report token-by-token.
    Yields tokens as they are generated.
    """
    # Step 1: NLP computation (instant)
    analysis = analyze_logs(log_text, query)

    if NLP_STATS_ONLY:
        yield analysis['context']
        return

    # Step 2: Stream the LLM report (single call)
    llm = get_report_llm(streaming=True)
    chain = REPORT_PROMPT | llm | StrOutputParser()

    for token in chain.stream({
        "question": query,
        "analysis_data": analysis['context'],
    }):
        if token:
            yield token


def get_quick_stats(log_text: str) -> dict:
    """
    Run NLP analysis only (no LLM). Returns structured stats instantly.
    Used for the quick-stats API endpoint.
    """
    analysis = nlp_engine.full_analysis(log_text)
    return analysis['stats']


# ── CLI Mode (for quick testing) ────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.panel import Panel
    from rich.text import Text
    import time

    console = Console()
    console.print(Panel(
        "[bold cyan]Security-Log-Analyser[/bold cyan]\n"
        "[dim]NLP-First Analysis Engine (Computation + Single LLM Report)[/dim]",
        expand=False,
    ))

    while True:
        files = list_log_files()
        if not files:
            console.print("[bold red]No log files found in the logs directory.[/bold red]")
            break

        console.print("\n[bold cyan]Available log files:[/bold cyan]")
        for i, f in enumerate(files, 1):
            console.print(f"  [green]{i}[/green]. {f}")

        idx = Prompt.ask(
            "[green]Select a file number[/green]",
            choices=[str(i) for i in range(1, len(files) + 1)],
        )
        file_path = os.path.join(LOG_DIRECTORY, files[int(idx) - 1])

        console.print("[cyan]Loading log file...[/cyan]")
        log_text = load_log_file(file_path)
        console.print(f"[dim]Loaded {len(log_text.splitlines())} lines[/dim]")

        # Run NLP analysis first (instant)
        console.print("[cyan]Running NLP analysis...[/cyan]")
        start = time.time()
        analysis = analyze_logs(log_text, "")
        nlp_time = time.time() - start

        stats = analysis['stats']
        console.print(Panel(
            f"[bold green]NLP Analysis Complete[/bold green] in {nlp_time:.2f}s\n\n"
            f"  📊 Total entries: {stats['summary']['total_log_entries']}\n"
            f"  🚨 Attacks: {stats['summary']['total_attacks']} ({stats['summary']['attack_ratio']}%)\n"
            f"  🔐 Failed logins: {stats['summary']['total_failed_logins']}\n"
            f"  🌐 Unique IPs: {stats['summary']['unique_ips']}\n"
            f"  🎯 Attack types: {len(stats['attack_breakdown'])}",
            title="[bold cyan]Instant NLP Stats[/bold cyan]",
        ))

        query = Prompt.ask("[green]Enter your query (or 'exit' to quit)[/green]")
        if query.lower() == "exit":
            console.print("[red]Exiting...[/red]")
            break
        if not query.strip():
            console.print("[yellow]Empty query, try again.[/yellow]")
            continue

        console.print("[cyan]Generating report (single LLM call)...[/cyan]")
        start = time.time()
        response = query_logs(log_text, query)
        total_time = time.time() - start

        console.print(Panel(
            Text(response, style="bold white"),
            title=f"[bold cyan]Analysis Result ({total_time:.1f}s)[/bold cyan]",
        ))
        console.print()
