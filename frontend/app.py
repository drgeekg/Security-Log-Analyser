"""
Security-Log-Analyser — Flask Web Application
Serves the modern UI and provides API endpoints for log analysis with streaming.
Now includes /api/quick-stats for instant NLP-computed metrics (no LLM).
"""

import os
import sys
import json
import time

# Add parent directory to path so we can import main.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from main import load_log_file, list_log_files, query_logs_stream, get_quick_stats, LOG_DIRECTORY

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit

# Resolve log directory relative to project root
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", LOG_DIRECTORY))

# Cache for raw log text (so we don't re-read the same file repeatedly)
_log_text_cache = {}


def _get_log_text(filename):
    """Get or cache the raw text content of a log file."""
    file_path = os.path.join(LOG_DIR, filename)
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Log file not found: {filename}")
    if filename not in _log_text_cache:
        _log_text_cache[filename] = load_log_file(file_path)
    return _log_text_cache[filename]


@app.route("/")
def index():
    """Serve the main dashboard."""
    return render_template("index.html")


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Return the list of available log files."""
    files = list_log_files(LOG_DIR)
    file_info = []
    for f in files:
        path = os.path.join(LOG_DIR, f)
        size = os.path.getsize(path)
        file_info.append({"name": f, "size": size})
    return jsonify({"files": file_info})


@app.route("/api/upload", methods=["POST"])
def upload_log():
    """Upload a new log file."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    os.makedirs(LOG_DIR, exist_ok=True)
    file.save(os.path.join(LOG_DIR, filename))

    # Clear cache for this file if it existed before
    _log_text_cache.pop(filename, None)

    return jsonify({"message": f"File '{filename}' uploaded successfully", "filename": filename})


@app.route("/api/generate", methods=["POST"])
def generate_logs():
    """Generate artificial tracking logs."""
    try:
        data = request.get_json(silent=True) or {}
        count = int(data.get("count", 800))
        attack_ratio = float(data.get("attack_ratio", 0.20))

        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from logs.generate_logs import generate_log_file
        
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"generated_logs_{ts}.md"
        output_path = os.path.join(LOG_DIR, filename)
        
        generate_log_file(
            output_path=output_path,
            count=count,
            days=7,
            attack_ratio=attack_ratio,
            title=f"Synthetic Logs - {ts}"
        )
        return jsonify({"message": "Logs generated", "filename": filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/quick-stats", methods=["POST"])
def quick_stats():
    """
    Run NLP analysis only (no LLM call) and return computed stats instantly.
    This gives the user immediate insight while the full report streams.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    filename = data.get("filename")
    if not filename:
        return jsonify({"error": "No log file specified"}), 400

    try:
        log_text = _get_log_text(filename)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Error loading file: {str(e)}"}), 500

    start = time.time()
    stats = get_quick_stats(log_text)
    elapsed = round(time.time() - start, 3)

    return jsonify({
        "stats": stats,
        "computation_time_seconds": elapsed,
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze a log file with a query.
    Returns a streaming SSE response for real-time token display.
    Pipeline: NLP computation (instant) → Single LLM report (streaming).
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    filename = data.get("filename")
    query = data.get("query", "").strip()

    if not filename:
        return jsonify({"error": "No log file specified"}), 400
    if not query:
        return jsonify({"error": "Empty query"}), 400

    try:
        log_text = _get_log_text(filename)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Error loading file: {str(e)}"}), 500

    def generate():
        try:
            for token in query_logs_stream(log_text, query):
                # Send as Server-Sent Event
                yield f"data: {json.dumps({'token': token})}\n\n"
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "True").lower() == "true"
    print(f"\n🔍 Security-Log-Analyser is running at http://{host}:{port}\n")
    app.run(host=host, port=port, debug=debug)
