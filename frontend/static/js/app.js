/**
 * Security-Log-Analyser — Frontend Application
 * Handles file selection, upload, query submission, SSE streaming,
 * and instant NLP stats display.
 */

(function () {
    "use strict";

    // ── Configure marked.js ──────────────────
    marked.setOptions({
        breaks: true,
        gfm: true,
        highlight: function (code, lang) {
            if (lang && hljs.getLanguage(lang)) {
                return hljs.highlight(code, { language: lang }).value;
            }
            return hljs.highlightAuto(code).value;
        },
    });

    // ── DOM Elements ─────────────────────────
    const fileList = document.getElementById("fileList");
    const fileInput = document.getElementById("fileInput");
    const uploadArea = document.getElementById("uploadArea");
    const queryInput = document.getElementById("queryInput");
    const querySubmit = document.getElementById("querySubmit");
    const responseContent = document.getElementById("responseContent");
    const statusBar = document.getElementById("statusBar");
    const statusText = document.getElementById("statusText");
    const quickActions = document.getElementById("quickActions");
    const toastContainer = document.getElementById("toastContainer");
    const statsPanel = document.getElementById("statsPanel");
    const statsGrid = document.getElementById("statsGrid");
    const statsTime = document.getElementById("statsTime");

    let selectedFile = null;
    let isAnalysing = false;

    // ── Initialize ───────────────────────────
    loadFiles();

    // ── Auto-resize textarea ─────────────────
    queryInput.addEventListener("input", () => {
        queryInput.style.height = "auto";
        queryInput.style.height = Math.min(queryInput.scrollHeight, 150) + "px";
    });

    // ── Submit on Enter (Shift+Enter for newline) ──
    queryInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            submitQuery();
        }
    });

    querySubmit.addEventListener("click", submitQuery);

    // ── Quick Action Buttons ─────────────────
    quickActions.addEventListener("click", (e) => {
        const btn = e.target.closest(".quick-action-btn");
        if (btn) {
            queryInput.value = btn.dataset.query;
            queryInput.style.height = "auto";
            queryInput.style.height = queryInput.scrollHeight + "px";
            submitQuery();
        }
    });

    // ── Drag & Drop Upload ───────────────────
    uploadArea.addEventListener("dragover", (e) => {
        e.preventDefault();
        uploadArea.classList.add("dragover");
    });

    uploadArea.addEventListener("dragleave", () => {
        uploadArea.classList.remove("dragover");
    });

    uploadArea.addEventListener("drop", (e) => {
        e.preventDefault();
        uploadArea.classList.remove("dragover");
        const files = e.dataTransfer.files;
        if (files.length > 0) uploadFile(files[0]);
    });

    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            uploadFile(fileInput.files[0]);
            fileInput.value = "";
        }
    });

    // ── Load Log Files ───────────────────────
    async function loadFiles() {
        try {
            const res = await fetch("/api/logs");
            const data = await res.json();

            if (data.files.length === 0) {
                fileList.innerHTML = `
                    <li class="file-item" style="justify-content:center; color:var(--text-muted); font-size:0.85rem;">
                        No log files found
                    </li>`;
                return;
            }

            fileList.innerHTML = "";
            data.files.forEach((file) => {
                const li = document.createElement("li");
                li.className = "file-item fade-in";
                li.innerHTML = `
                    <span class="file-item__icon">📄</span>
                    <div class="file-item__info">
                        <div class="file-item__name">${escapeHtml(file.name)}</div>
                        <div class="file-item__size">${formatSize(file.size)}</div>
                    </div>`;
                li.addEventListener("click", () => selectFile(file.name, li));
                fileList.appendChild(li);
            });
        } catch (err) {
            fileList.innerHTML = `
                <li class="file-item" style="justify-content:center; color:var(--danger); font-size:0.85rem;">
                    Failed to load files
                </li>`;
        }
    }

    // ── Select File ──────────────────────────
    function selectFile(filename, element) {
        selectedFile = filename;

        document.querySelectorAll(".file-item").forEach((el) => el.classList.remove("active"));
        element.classList.add("active");

        queryInput.disabled = false;
        querySubmit.disabled = false;

        setStatus("ready", `Ready — ${filename} selected`);

        // Fetch instant NLP stats
        fetchQuickStats(filename);
    }

    // ── Fetch Quick NLP Stats ────────────────
    async function fetchQuickStats(filename) {
        statsPanel.style.display = "block";
        statsGrid.innerHTML = `
            <div class="stats-loading">
                <div class="loading-dots"><span></span><span></span><span></span></div>
                <span>Computing NLP stats...</span>
            </div>`;
        statsTime.textContent = "";

        try {
            const res = await fetch("/api/quick-stats", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ filename }),
            });

            if (!res.ok) {
                throw new Error("Failed to fetch stats");
            }

            const data = await res.json();
            const s = data.stats.summary;

            statsTime.textContent = `${data.computation_time_seconds}s`;

            statsGrid.innerHTML = `
                <div class="stat-card">
                    <div class="stat-value">${s.total_log_entries.toLocaleString()}</div>
                    <div class="stat-label">Total Entries</div>
                </div>
                <div class="stat-card stat-card--danger">
                    <div class="stat-value">${s.total_attacks.toLocaleString()}</div>
                    <div class="stat-label">Attacks (${s.attack_ratio}%)</div>
                </div>
                <div class="stat-card stat-card--warning">
                    <div class="stat-value">${s.total_failed_logins.toLocaleString()}</div>
                    <div class="stat-label">Failed Logins</div>
                </div>
                <div class="stat-card stat-card--info">
                    <div class="stat-value">${s.unique_ips}</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
                <div class="stat-card stat-card--info">
                    <div class="stat-value">${s.unique_attacker_ips}</div>
                    <div class="stat-label">Attacker IPs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${Object.keys(data.stats.attack_breakdown).length}</div>
                    <div class="stat-label">Attack Types</div>
                </div>
            `;

            // Show attack breakdown below stats
            const breakdown = data.stats.attack_breakdown;
            if (Object.keys(breakdown).length > 0) {
                const breakdownHtml = Object.entries(breakdown)
                    .map(([type, count]) => `
                        <div class="attack-row">
                            <span class="attack-type">${escapeHtml(type)}</span>
                            <span class="attack-count">${count}</span>
                        </div>`)
                    .join("");

                statsGrid.innerHTML += `
                    <div class="stat-divider"></div>
                    <div class="attack-breakdown">
                        <div class="attack-breakdown-title">Attack Breakdown</div>
                        ${breakdownHtml}
                    </div>`;
            }

            // Show malicious agents count if any
            const malCount = data.stats.user_agents.malicious_count;
            if (malCount > 0) {
                statsGrid.innerHTML += `
                    <div class="stat-card stat-card--danger" style="grid-column: 1 / -1;">
                        <div class="stat-value">⚠️ ${malCount}</div>
                        <div class="stat-label">Malicious User Agent Entries (sqlmap, Nikto, Nmap...)</div>
                    </div>`;
            }

        } catch (err) {
            statsGrid.innerHTML = `
                <div style="color: var(--danger); font-size: 0.85rem; text-align: center; padding: 8px;">
                    Could not compute stats
                </div>`;
        }
    }

    // ── Upload File ──────────────────────────
    async function uploadFile(file) {
        const formData = new FormData();
        formData.append("file", file);

        setStatus("loading", `Uploading ${file.name}...`);

        try {
            const res = await fetch("/api/upload", { method: "POST", body: formData });
            const data = await res.json();

            if (res.ok) {
                showToast(data.message, "success");
                loadFiles();
                setStatus("success", "File uploaded successfully");
            } else {
                showToast(data.error || "Upload failed", "error");
                setStatus("error", "Upload failed");
            }
        } catch (err) {
            showToast("Network error during upload", "error");
            setStatus("error", "Upload failed");
        }
    }

    // ── Submit Query ─────────────────────────
    async function submitQuery() {
        const query = queryInput.value.trim();
        if (!query || !selectedFile || isAnalysing) return;

        isAnalysing = true;
        querySubmit.disabled = true;
        queryInput.disabled = true;

        setStatus("loading", "NLP analysis (instant) → generating LLM report...");

        // Show loading animation
        responseContent.innerHTML = `
            <div class="loading-dots">
                <span></span><span></span><span></span>
            </div>
            <span style="color: var(--text-muted); font-size: 0.85rem; margin-left: 12px;">
                NLP computation complete → streaming LLM report...
            </span>`;

        try {
            const res = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ filename: selectedFile, query }),
            });

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.error || "Analysis failed");
            }

            // Read the SSE stream
            responseContent.innerHTML = `<div class="markdown-body" id="streamOutput"></div>`;
            const streamOutput = document.getElementById("streamOutput");
            let fullResponse = "";

            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";

            setStatus("loading", "Streaming LLM report...");

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split("\n");
                buffer = lines.pop(); // keep incomplete line in buffer

                for (const line of lines) {
                    if (line.startsWith("data: ")) {
                        try {
                            const payload = JSON.parse(line.slice(6));

                            if (payload.error) {
                                throw new Error(payload.error);
                            }

                            if (payload.token) {
                                fullResponse += payload.token;
                                // Render markdown in real-time
                                streamOutput.innerHTML = marked.parse(fullResponse) +
                                    '<span class="streaming-cursor"></span>';
                                // Auto-scroll to bottom
                                streamOutput.scrollTop = streamOutput.scrollHeight;
                            }

                            if (payload.done) {
                                // Final render: parse markdown + highlight code blocks
                                streamOutput.innerHTML = marked.parse(fullResponse);
                                streamOutput.querySelectorAll('pre code').forEach((el) => {
                                    hljs.highlightElement(el);
                                });
                            }
                        } catch (parseErr) {
                            if (parseErr.message !== "Analysis failed") {
                                console.warn("Parse error:", parseErr);
                            } else {
                                throw parseErr;
                            }
                        }
                    }
                }
            }

            setStatus("success", "Analysis complete");
        } catch (err) {
            responseContent.innerHTML = `
                <div class="response-placeholder">
                    <span class="response-placeholder__icon" style="font-size: 2rem;">⚠️</span>
                    <span class="response-placeholder__text" style="color: var(--danger);">${escapeHtml(err.message)}</span>
                </div>`;
            setStatus("error", "Analysis failed");
            showToast(err.message, "error");
        } finally {
            isAnalysing = false;
            querySubmit.disabled = false;
            queryInput.disabled = false;
            queryInput.focus();
        }
    }

    // ── Status Bar ───────────────────────────
    function setStatus(type, message) {
        statusBar.className = "status-bar";
        switch (type) {
            case "loading":
                statusBar.classList.add("status-bar--loading");
                break;
            case "success":
                statusBar.classList.add("status-bar--success");
                break;
            case "error":
                statusBar.classList.add("status-bar--error");
                break;
            default:
                statusBar.classList.add("status-bar--idle");
        }
        statusText.textContent = message;
    }

    // ── Toast ────────────────────────────────
    function showToast(message, type = "success") {
        const toast = document.createElement("div");
        toast.className = `toast toast--${type}`;
        toast.textContent = message;
        toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateX(100%)";
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // ── Utilities ────────────────────────────
    function formatSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / 1048576).toFixed(1) + " MB";
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }
})();
