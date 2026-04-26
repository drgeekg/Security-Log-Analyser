# 🛡️ Security-Log-Analyser

> **High-performance security log analysis using hybrid NLP computation and Ollama LLM**

An intelligent security log analysis tool that leverages a deterministic NLP engine for instant parsing and statistics, followed by a local LLM to act as a Level 1 SOC (Security Operations Center) Analyst. Upload your security logs, get instant attack metrics, and receive a comprehensive, real-time streaming report — all running locally on your machine.

---

## ✨ Features

- ⚡ **Hybrid Architecture** — Instant pure-Python NLP computation for parsing and statistics, dropping analysis time from 45 minutes to < 2 minutes.
- 📊 **Instant Metrics Panel** — Instantly view total logs, attack ratio, failed logins, unique IPs, and attack breakdowns as soon as a file is selected.
- 🤖 **Local LLM via Ollama** — A single LLM call synthesizes the final report. Runs entirely on your machine; no data leaves your system.
- 🌊 **Real-Time Streaming** — Token-by-token response streaming for the final narrative report.
- 🎨 **Modern Web UI** — Premium dark-themed Flask interface with glassmorphism design.
- 📤 **Drag & Drop Upload** — Easily upload new log files for analysis.
- 🎯 **Quick Actions** — One-click common security queries (suspicious activities, failed logins, DDoS, etc.).
- 🔧 **Fully Configurable** — Settings in a `.env` file (model, port, stats-only mode, etc.).

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **LLM** | Ollama (gpt-oss:120b-cloud or llama-based models) |
| **NLP Engine** | Pure Python (Regex, collections, computation) |
| **LLM Integration** | LangChain |
| **Web Framework** | Flask |
| **Frontend** | HTML, CSS, JavaScript (vanilla) |
| **Language** | Python 3.8+ |

---

## 📂 Project Structure

```
Security-Log-Analyser/
├── nlp_engine.py            # Core NLP computation (parsing, stats, scoring)
├── main.py                  # Pipeline manager (NLP + single LLM call)
├── unit_testing.py          # Deterministic test suite for the NLP engine
├── requirements.txt         # Python dependencies
├── .env                     # Environment configuration
├── logs/                    # Log files for analysis
│   ├── logs1.md             # Sample log data
│   ├── logs2.md             # Sample log data
│   └── generate_logs.py     # Batch log generator script
└── frontend/                # Flask web application
    ├── app.py               # Flask server with SSE streaming & /api/quick-stats
    ├── templates/
    │   └── index.html       # Main dashboard
    └── static/
        ├── css/
        │   └── style.css    # Premium dark theme
        └── js/
            └── app.js       # Client-side streaming & stats logic
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **Ollama** installed and running locally ([Install Ollama](https://ollama.ai))

### 1. Pull Required Models

```bash
# Example model for the report generation
ollama pull llama3.1
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure (Optional)

Edit the `.env` file to change models or modes:

```env
OLLAMA_BASE_URL=http://localhost:11434
REPORT_MODEL=llama3.1
NLP_STATS_ONLY=false
FLASK_PORT=5000
```

### 5. Run the Application

```bash
python frontend/app.py
```

Open your browser and navigate to **http://localhost:5000**

---

## 💡 Usage

1. **Select a log file** from the sidebar (log files from the `logs/` directory are automatically listed).
2. **Review Instant Stats** — Watch the sidebar instantly populate with NLP-computed metrics like total entries, attack counts, and IP behavior.
3. **Type a query** or click a **Quick Action** button.
4. **Watch the streaming response** appear token-by-token as the AI writes the final narrative report based on the NLP data.
5. **Upload new logs** via drag & drop or the file browser.

### Example Queries

- *"Provide a comprehensive security analysis of all logs"*
- *"List all failed login attempts with IP addresses"*
- *"Detect any brute force or DDoS attacks"*
- *"What IPs performed the most attack attempts?"*
- *"Identify SQL injection attempts"*

---

## ⚙️ How It Works

```
Log File → NLP Parsing → Attack Detection & Stats Computation → Single LLM Synthesis O(1) → Streaming Report
```

1. **Log Ingestion** — Security logs are loaded as raw text.
2. **NLP Engine** — Pure Python logic deterministicly parses lines, detects severe attacks using complex RegExp/keywords (SQLi, RCE, XSS, DDoS), and aggregates statistical metrics (frequency, IPs).
3. **Threat Scoring** — The NLP engine ranks threats using a CVSS-based computation formula considering severity, IP distribution, and frequency.
4. **LLM Synthesis** — A single, structured prompt containing the precise computed data is fed into the local LLM.
5. **Streaming Output** — The LLM acts as a Senior SOC analyst, formatting the data into an authoritative, narrative markdown report that streams to the frontend.

---

## 🔧 Log Generation Tools

### Batch Log Generator

Generate synthetic security logs for testing:

```bash
python logs/generate_logs.py                              # 500 entries, defaults
python logs/generate_logs.py --count 1000 -o logs/big.md  # Custom count & output
python logs/generate_logs.py --attack-ratio 0.4           # 40% attack events
python logs/generate_logs.py --start-date 2024-01-01 --days 30 --count 5000
```

---

## 🧪 Testing

Run the automated test suite to validate the pure-computation NLP engine:

```bash
python unit_testing.py
```

Tests deterministically validate the NLP pipeline's parsing accuracy, malicious agent detection, statistic aggregation, and threat scoring without ever calling an LLM.

---

## 📜 License

This project is licensed under the GNU General Public License v2.0 (GPL-2.0). See the [LICENSE](LICENSE) file for more details.

---

**👤 Author:** [Ganesh](https://github.com/drgeekg)

---
