"""
Security-Log-Analyser — Core Multi-LLM Analysis Engine
Backend using LangGraph with query splitting + direct log injection.

Pipeline:
  1. Split user query into focused sub-queries  (fast model)
  2. Analyze each log chunk per sub-query         (fast model)
  3. Synthesize all analyses into final answer     (powerful model)
"""

import os
import json
import re
from typing import List
from typing_extensions import TypedDict
from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langgraph.graph import StateGraph, START, END

# Load environment variables
load_dotenv()

# ── Configuration from .env ─────────────────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
ANALYSIS_MODEL = os.getenv(
    "ANALYSIS_MODEL",
    "radenadri/Qwen3.5-0.8B-Claude-4.6-Opus-Reasoning-Distilled-GGUF",
)
SYNTHESIS_MODEL = os.getenv("SYNTHESIS_MODEL", "gpt-oss:120b-cloud")
LOG_CHUNK_LINES = int(os.getenv("LOG_CHUNK_LINES", "100"))
LOG_DIRECTORY = os.getenv("LOG_DIRECTORY", "./logs")


# ── LangGraph State Schema ─────────────────────────────────────────
class AnalysisState(TypedDict):
    question: str
    log_text: str
    log_chunks: List[str]
    sub_queries: List[str]
    chunk_analyses: List[str]
    answer: str


# ═══════════════════════════════════════════════════════════════════
#  SYSTEM PROMPTS — one for each LLM call type
# ═══════════════════════════════════════════════════════════════════

# ── 1. Query Splitter (fast model) ─────────────────────────────────
QUERY_SPLITTER_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "You are a query decomposition assistant for a Security Operations Center. "
     "Your ONLY job is to break a user's security question into 2-4 focused, "
     "independent sub-queries that together fully cover the original question.\n\n"
     "Rules:\n"
     "- Each sub-query must be self-contained and specific.\n"
     "- Output ONLY a valid JSON array of strings — no commentary, no markdown.\n"
     "- If the question is already simple/atomic, return it as a single-item array.\n\n"
     "Example:\n"
     "  Input:  \"What brute force and SQL injection attacks happened, and which IPs are involved?\"\n"
     "  Output: [\"How many brute force attacks were detected and from which IPs?\", "
     "\"How many SQL injection attempts were detected and from which IPs?\"]"),
    ("human", "{question}"),
])

# ── 2. Chunk Analyst (fast model) ──────────────────────────────────
CHUNK_ANALYST_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "You are a Level 1 SOC (Security Operations Center) Analyst performing "
     "targeted log analysis. You will receive a chunk of raw security logs and "
     "a specific analysis question.\n\n"
     "Instructions:\n"
     "- Carefully scan every log line in the chunk for evidence relevant to the question.\n"
     "- Extract exact IPs, timestamps, usernames, attack types, status codes, and counts.\n"
     "- If no relevant evidence is found in this chunk, say \"No relevant findings in this chunk.\"\n"
     "- Be precise and factual — do NOT make up information.\n"
     "- Keep your response concise: bullet points with hard evidence only."),
    ("human",
     "=== LOG CHUNK ===\n{log_chunk}\n=== END CHUNK ===\n\n"
     "Analysis Question: {sub_query}\n\n"
     "Findings:"),
])

# ── 3. Synthesis (powerful model) ──────────────────────────────────
SYNTHESIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "You are a Senior SOC Analyst synthesizing findings from multiple log analysis passes. "
     "You will receive the original user question and a collection of sub-analyses that "
     "were performed across different log chunks and sub-queries.\n\n"
     "Instructions:\n"
     "- Merge, deduplicate, and reconcile all findings into one coherent security report.\n"
     "- Provide accurate counts, specific IPs, timestamps, and attack classifications.\n"
     "- Highlight the most critical threats and recommend immediate actions.\n"
     "- If evidence is contradictory, note the discrepancy.\n"
     "- Structure your response clearly with sections if appropriate.\n"
     "- Be authoritative, precise, and actionable."),
    ("human",
     "Original Question: {question}\n\n"
     "=== COLLECTED ANALYSES ===\n{analyses}\n=== END ANALYSES ===\n\n"
     "Comprehensive Security Analysis:"),
])


# ── Helper factories ───────────────────────────────────────────────
def get_analysis_llm(streaming=False):
    """Create a ChatOllama instance for the fast analysis model (Qwen)."""
    return ChatOllama(
        model=ANALYSIS_MODEL,
        base_url=OLLAMA_BASE_URL,
        streaming=streaming,
        temperature=0.1,
    )


def get_synthesis_llm(streaming=False):
    """Create a ChatOllama instance for the powerful synthesis model."""
    return ChatOllama(
        model=SYNTHESIS_MODEL,
        base_url=OLLAMA_BASE_URL,
        streaming=streaming,
        temperature=0.2,
    )


# ── Log loading & chunking ────────────────────────────────────────
def load_log_file(file_path):
    """Read the raw text content of a log file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def chunk_log_text(log_text, max_lines=None):
    """Split raw log text into chunks of `max_lines` lines each."""
    if max_lines is None:
        max_lines = LOG_CHUNK_LINES
    lines = log_text.splitlines()
    chunks = []
    for i in range(0, len(lines), max_lines):
        chunk = "\n".join(lines[i : i + max_lines])
        if chunk.strip():
            chunks.append(chunk)
    return chunks


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
#  LangGraph Pipeline — Split → Analyze → Synthesize
# ═══════════════════════════════════════════════════════════════════

def _build_analysis_graph(streaming=False):
    """
    Build a compiled LangGraph StateGraph for multi-LLM analysis.

    Nodes:  chunk_logs  →  split_query  →  analyze_chunks  →  synthesize
    """
    analysis_llm = get_analysis_llm(streaming=False)   # always non-streaming for intermediate steps
    synthesis_llm = get_synthesis_llm(streaming=streaming)

    splitter_chain = QUERY_SPLITTER_PROMPT | analysis_llm | StrOutputParser()
    analyst_chain = CHUNK_ANALYST_PROMPT | analysis_llm | StrOutputParser()
    synthesis_chain = SYNTHESIS_PROMPT | synthesis_llm | StrOutputParser()

    # ── Node: chunk_logs ─────────────────────────────────────────
    def chunk_logs(state: AnalysisState) -> dict:
        chunks = chunk_log_text(state["log_text"])
        return {"log_chunks": chunks}

    # ── Node: split_query ────────────────────────────────────────
    def split_query(state: AnalysisState) -> dict:
        raw = splitter_chain.invoke({"question": state["question"]})
        # Parse JSON array from LLM response
        try:
            # Try to extract JSON array from response (may have extra text)
            match = re.search(r'\[.*\]', raw, re.DOTALL)
            if match:
                sub_queries = json.loads(match.group())
            else:
                sub_queries = [state["question"]]
        except (json.JSONDecodeError, TypeError):
            # Fallback: use original question as-is
            sub_queries = [state["question"]]
        return {"sub_queries": sub_queries}

    # ── Node: analyze_chunks ─────────────────────────────────────
    def analyze_chunks(state: AnalysisState) -> dict:
        analyses = []
        for sq in state["sub_queries"]:
            for i, chunk in enumerate(state["log_chunks"]):
                result = analyst_chain.invoke({
                    "log_chunk": chunk,
                    "sub_query": sq,
                })
                analyses.append(
                    f"--- Sub-query: {sq} | Chunk {i+1}/{len(state['log_chunks'])} ---\n{result}"
                )
        return {"chunk_analyses": analyses}

    # ── Node: synthesize ─────────────────────────────────────────
    def synthesize(state: AnalysisState) -> dict:
        combined = "\n\n".join(state["chunk_analyses"])
        answer = synthesis_chain.invoke({
            "question": state["question"],
            "analyses": combined,
        })
        return {"answer": answer}

    # ── Assemble graph ───────────────────────────────────────────
    graph = StateGraph(AnalysisState)
    graph.add_node("chunk_logs", chunk_logs)
    graph.add_node("split_query", split_query)
    graph.add_node("analyze_chunks", analyze_chunks)
    graph.add_node("synthesize", synthesize)

    graph.add_edge(START, "chunk_logs")
    graph.add_edge("chunk_logs", "split_query")
    graph.add_edge("split_query", "analyze_chunks")
    graph.add_edge("analyze_chunks", "synthesize")
    graph.add_edge("synthesize", END)

    return graph.compile()


# ── Public query functions (API-compatible) ────────────────────────
def query_logs(log_text, query):
    """Run the full multi-LLM analysis pipeline and return the result string."""
    compiled = _build_analysis_graph(streaming=False)
    result = compiled.invoke({
        "question": query,
        "log_text": log_text,
        "log_chunks": [],
        "sub_queries": [],
        "chunk_analyses": [],
        "answer": "",
    })
    return result.get("answer", "No result found.")


def query_logs_stream(log_text, query):
    """
    Run the multi-LLM pipeline and yield final synthesis tokens as they stream.
    Intermediate steps (splitting, chunk analysis) run to completion first,
    then the synthesis step streams token-by-token.
    """
    # Step 1-3: Run splitting & chunk analysis (non-streaming)
    analysis_llm = get_analysis_llm(streaming=False)
    splitter_chain = QUERY_SPLITTER_PROMPT | analysis_llm | StrOutputParser()
    analyst_chain = CHUNK_ANALYST_PROMPT | analysis_llm | StrOutputParser()

    # Chunk the logs
    log_chunks = chunk_log_text(log_text)

    # Split the query
    raw = splitter_chain.invoke({"question": query})
    try:
        match = re.search(r'\[.*\]', raw, re.DOTALL)
        if match:
            sub_queries = json.loads(match.group())
        else:
            sub_queries = [query]
    except (json.JSONDecodeError, TypeError):
        sub_queries = [query]

    # Analyze each chunk for each sub-query
    analyses = []
    for sq in sub_queries:
        for i, chunk in enumerate(log_chunks):
            result = analyst_chain.invoke({
                "log_chunk": chunk,
                "sub_query": sq,
            })
            analyses.append(
                f"--- Sub-query: {sq} | Chunk {i+1}/{len(log_chunks)} ---\n{result}"
            )

    # Step 4: Stream the synthesis
    synthesis_llm = get_synthesis_llm(streaming=True)
    synthesis_chain = SYNTHESIS_PROMPT | synthesis_llm | StrOutputParser()
    combined = "\n\n".join(analyses)

    for token in synthesis_chain.stream({
        "question": query,
        "analyses": combined,
    }):
        if token:
            yield token


# ── CLI Mode (optional, for quick testing) ──────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.panel import Panel
    from rich.text import Text

    console = Console()
    console.print(Panel(
        "[bold cyan]Security-Log-Analyser[/bold cyan]\n"
        "[dim]Multi-LLM Analysis Engine (Query Splitting + Direct Log Injection)[/dim]",
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

        query = Prompt.ask("[green]Enter your query (or 'exit' to quit)[/green]")
        if query.lower() == "exit":
            console.print("[red]Exiting...[/red]")
            break
        if not query.strip():
            console.print("[yellow]Empty query, try again.[/yellow]")
            continue

        console.print("[cyan]Analysing (split → chunk-analyse → synthesize)...[/cyan]")
        response = query_logs(log_text, query)
        console.print(Panel(
            Text(response, style="bold white"),
            title="[bold cyan]Analysis Result[/bold cyan]",
        ))
        console.print()
