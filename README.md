# 🛡️ Security-Log-Analyser

> **AI-powered security log analysis using RAG (Retrieval-Augmented Generation) and Ollama LLM**

An intelligent security log analysis tool that leverages a local LLM to act as a Level 1 SOC (Security Operations Center) Analyst. Upload your security logs, ask natural language questions, and get real-time streaming analysis — all running locally on your machine.

---

## ✨ Features

- 🔍 **RAG-Powered Analysis** — Retrieval-Augmented Generation for context-aware log analysis
- 🤖 **Local LLM via Ollama** — Runs entirely on your machine, no data leaves your system
- ⚡ **Real-Time Streaming** — Token-by-token response streaming for instant feedback
- 🎨 **Modern Web UI** — Premium dark-themed Flask interface with glassmorphism design
- 📤 **Drag & Drop Upload** — Easily upload new log files for analysis
- 🎯 **Quick Actions** — One-click common security queries (suspicious activities, failed logins, DDoS, etc.)
- 🔧 **Fully Configurable** — All settings in a `.env` file (model, chunk size, port, etc.)

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **LLM** | Ollama (llama3.1) |
| **Embeddings** | Ollama (nomic-embed-text) |
| **RAG Framework** | LangChain |
| **Vector Store** | FAISS |
| **Web Framework** | Flask |
| **Frontend** | HTML, CSS, JavaScript (vanilla) |
| **Language** | Python |

---

## 📂 Project Structure

```
Security-Log-Analyser/
├── main.py                  # Core RAG engine (streaming + non-streaming)
├── unit_testing.py          # Automated test suite
├── requirements.txt         # Python dependencies
├── .env                     # Environment configuration
├── notes.txt                # Project notes & TODOs
├── logs/                    # Log files for analysis
│   ├── logs1.md             # Sample log data
│   ├── logs2.md             # Sample log data
│   ├── generate_logs.py     # Batch log generator script
│   └── live_logs.py         # Live log streaming server
└── frontend/                # Flask web application
    ├── app.py               # Flask server with SSE streaming
    ├── templates/
    │   └── index.html       # Main dashboard
    └── static/
        ├── css/
        │   └── style.css    # Premium dark theme
        └── js/
            └── app.js       # Client-side streaming logic
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **Ollama** installed and running locally ([Install Ollama](https://ollama.ai))

### 1. Pull Required Models

```bash
ollama pull llama3.1
ollama pull nomic-embed-text
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

Edit the `.env` file to change models, port, or RAG settings:

```env
OLLAMA_MODEL=llama3.1
OLLAMA_EMBED_MODEL=nomic-embed-text
FLASK_PORT=5000
CHUNK_SIZE=500
```

### 5. Run the Application

```bash
python frontend/app.py
```

Open your browser and navigate to **http://localhost:5000**

---

## 💡 Usage

1. **Select a log file** from the sidebar (log files from the `logs/` directory are automatically listed)
2. **Type a query** or click a **Quick Action** button
3. **Watch the streaming response** appear token-by-token as the AI analyses your logs
4. **Upload new logs** via drag & drop or the file browser

### Example Queries

- *"Summarize all suspicious activities in the logs"*
- *"List all failed login attempts with IP addresses"*
- *"Detect any brute force or DDoS attacks"*
- *"What IPs performed the most attack attempts?"*
- *"Identify SQL injection attempts"*

---

## 📸 Screenshots

| Dashboard | Analysis Streaming |
|-----------|--------------------|
| ![Screenshot 1](Static/Screenshot%202026-04-07%20015439.png) | ![Screenshot 2](Static/Screenshot%202026-04-07%20015502.png) |

| Quick Actions | Rendered Markdown Report |
|---------------|--------------------------|
| ![Screenshot 3](Static/Screenshot%202026-04-07%20015548.png) | ![Screenshot 4](Static/Screenshot%202026-04-07%20015600.png) |

---

## ⚙️ How It Works

```
Log File → Chunking → Query Splitting (Qwen) → Parallel Chunk Analysis (Qwen) → Synthesis (120b) → Streaming
```

1. **Log Ingestion** — Security logs are loaded as raw text and split into manageable ~100-line chunks.
2. **Query Splitting** — A fast LLM breaks the user's natural language question into specific, focused sub-queries.
3. **Parallel Analysis** — The fast LLM acts as a Level 1 SOC Analyst, scanning log chunks for evidence related to each sub-query.
4. **Synthesis** — A powerful, logic-heavy LLM merges all sub-analyses into a comprehensive security report.
5. **Streaming Output** — The final markdown report stream is rendered in real-time in the browser.

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

### Live Log Streaming Server

Run a live log generator with a REST API for real-time analysis:

```bash
python logs/live_logs.py                    # Starts on port 5001, 1 log/sec
python logs/live_logs.py --rate 5 --port 5001
```

**API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/stream` | GET | SSE stream of real-time logs |
| `/api/recent?n=50` | GET | Get recent log entries |
| `/api/status` | GET | Server status info |
| `/api/start` | POST | Start log generation |
| `/api/stop` | POST | Stop log generation |
| `/api/config` | POST | Update rate/attack ratio |

The live server also writes to `logs/live_feed.md` which can be analysed in the main UI.

---

## 🧪 Testing

Run the automated test suite:

```bash
python unit_testing.py
```

Tests validate the RAG pipeline's accuracy against known security events in the logs.

---

## 📜 License

This project is licensed under the MIT License.

---

**👤 Author:** [Ganesh](https://github.com/drgeekg)

---
