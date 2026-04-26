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
     "You are a Senior SOC (Security Operations Center) Analyst writing a comprehensive "
     "security report. You will receive pre-computed NLP analysis data containing exact "
     "counts, IP addresses, attack classifications, threat scores, and statistical findings "
     "from security logs.\n\n"
     "Your job is to:\n"
     "1. Write a professional, well-structured security report based on the data provided.\n"
     "2. DO NOT re-count or re-analyze — the numbers given are exact (computed, not estimated).\n"
     "3. Use the threat rankings to prioritize your findings.\n"
     "4. Highlight the most critical threats and provide actionable recommendations.\n"
     "5. If the user asked a specific question, answer it directly using the data.\n"
     "6. Use markdown formatting for headers, tables, and lists.\n"
     "7. Include an Executive Summary, Detailed Findings, Threat Prioritization, and Recommendations.\n"
     "8. Be authoritative, precise, and actionable."),
    ("human",
     "User Question: {question}\n\n"
     "{analysis_data}\n\n"
     "Write a comprehensive security report based on the above NLP-computed analysis data:"),
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
