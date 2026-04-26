/**
 * Security-Log-Analyser — Frontend Application
 * Handles chat interface, file selection, instant NLP stats as system messages,
 * and SSE streaming for LLM responses.
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
    const chatFeed = document.getElementById("chatFeed");
    const welcomeView = document.getElementById("welcomeView");
    const quickActionsGrid = document.getElementById("quickActionsGrid");
    const statusBar = document.getElementById("statusBar");
    const statusText = document.getElementById("statusText");
    const toastContainer = document.getElementById("toastContainer");
    const newChatBtn = document.getElementById("newChatBtn");

    let selectedFile = null;
    let isAnalysing = false;
    let hasStartedChat = false;

    // ── Initialize ───────────────────────────
    loadFiles();

    // ── New Chat / Reset ──────────────────────
    newChatBtn.addEventListener("click", () => {
        // Clear selection
        selectedFile = null;
        hasStartedChat = false;
        document.querySelectorAll(".file-item").forEach((el) => el.classList.remove("active"));
        
        // Reset UI
        queryInput.disabled = true;
        querySubmit.disabled = true;
        queryInput.value = "";
        queryInput.placeholder = "Select a log file first to start analysis...";
        queryInput.style.height = "56px";
        
        // Clear chat feed except welcome view
        Array.from(chatFeed.children).forEach(child => {
            if (child.id !== "welcomeView") {
                child.remove();
            }
        });
        welcomeView.style.display = "flex";
        
        setStatus("idle", "System Ready");
    });

    // ── Auto-resize textarea ─────────────────
    queryInput.addEventListener("input", () => {
        queryInput.style.height = "auto";
        queryInput.style.height = Math.min(queryInput.scrollHeight, 200) + "px";
        querySubmit.disabled = queryInput.value.trim().length === 0;
    });

    // ── Submit on Enter (Shift+Enter for newline) ──
    queryInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            if (!querySubmit.disabled) submitQuery();
        }
    });

    querySubmit.addEventListener("click", () => {
        if (!querySubmit.disabled) submitQuery();
    });

    // ── Quick Action Buttons ─────────────────
    quickActionsGrid.addEventListener("click", (e) => {
        const card = e.target.closest(".quick-action-card");
        if (card && selectedFile) {
            queryInput.value = card.dataset.query;
            submitQuery();
        } else if (card && !selectedFile) {
            showToast("Please select a log file from the sidebar first.", "error");
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

    // ── Generate Logs Panel Toggle ───────────
    const toggleGenConfigBtn = document.getElementById("toggleGenConfigBtn");
    const genConfigPanel = document.getElementById("genConfigPanel");
    const generateLogsSubmitBtn = document.getElementById("generateLogsSubmitBtn");

    if (toggleGenConfigBtn && genConfigPanel && generateLogsSubmitBtn) {
        toggleGenConfigBtn.addEventListener("click", () => {
            const isHidden = genConfigPanel.style.display === "none";
            genConfigPanel.style.display = isHidden ? "block" : "none";
            toggleGenConfigBtn.style.background = isHidden ? "rgba(139, 92, 246, 0.25)" : "rgba(139, 92, 246, 0.1)";
        });

        generateLogsSubmitBtn.addEventListener("click", async () => {
            const count = document.getElementById("genCount").value || 500;
            const ratio = document.getElementById("genAttackRatio").value || 0.15;
            
            const originalText = generateLogsSubmitBtn.innerHTML;
            generateLogsSubmitBtn.innerHTML = `<span class="icon">⏳</span> Generating...`;
            generateLogsSubmitBtn.disabled = true;
            
            setStatus("loading", `Generating ${count} logs...`);

            try {
                const res = await fetch("/api/generate", { 
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ count: parseInt(count), attack_ratio: parseFloat(ratio) }) 
                });
                const data = await res.json();

                if (res.ok) {
                    showToast(`Generated: ${data.filename}`, "success");
                    loadFiles();
                    setStatus("success", "Logs generated successfully");
                    genConfigPanel.style.display = "none";
                    toggleGenConfigBtn.style.background = "rgba(139, 92, 246, 0.1)";
                } else {
                    showToast(data.error || "Generation failed", "error");
                    setStatus("error", "Generation failed");
                }
            } catch (err) {
                showToast("Network error during generation", "error");
                setStatus("error", "Generation failed");
            } finally {
                generateLogsSubmitBtn.innerHTML = originalText;
                generateLogsSubmitBtn.disabled = false;
            }
        });
    }

    // ── Load Log Files ───────────────────────
    async function loadFiles() {
        try {
            const res = await fetch("/api/logs");
            const data = await res.json();

            if (data.files.length === 0) {
                fileList.innerHTML = `<li class="file-item empty-state">No log files found</li>`;
                return;
            }

            fileList.innerHTML = "";
            // Reverse so newest are at top
            data.files.slice().reverse().forEach((file) => {
                const li = document.createElement("li");
                li.className = "file-item fade-in";
                if (file.name === selectedFile) li.classList.add("active");
                li.innerHTML = `
                    <span class="icon">📄</span>
                    <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
                    <span style="font-size:0.7rem; color:var(--text-muted);">${formatSize(file.size)}</span>
                `;
                li.addEventListener("click", () => selectFile(file.name, li));
                fileList.appendChild(li);
            });
        } catch (err) {
            fileList.innerHTML = `<li class="file-item empty-state" style="color:var(--danger)">Failed to load files</li>`;
        }
    }

    // ── Select File ──────────────────────────
    function selectFile(filename, element) {
        if (selectedFile === filename) return; 
        
        selectedFile = filename;

        document.querySelectorAll(".file-item").forEach((el) => el.classList.remove("active"));
        element.classList.add("active");

        queryInput.disabled = false;
        queryInput.placeholder = "Ask me anything about these logs...";
        
        setStatus("success", `File linked: ${filename}`);

        // Fetch instant NLP stats and show them as a message (but don't hide welcomeView yet)
        if (!hasStartedChat) {
            fetchQuickStatsAndAppend(filename);
        } else {
            // If they change files midway through a chat, drop another context card
            fetchQuickStatsAndAppend(filename);
        }
    }

    // ── UI Chat Append Helpers ───────────────
    function appendUserMessage(text) {
        const tpl = document.getElementById("tpl-message-user").content.cloneNode(true);
        tpl.querySelector(".message__content").textContent = text;
        chatFeed.appendChild(tpl);
        scrollToBottom();
    }

    function appendLoadingMessage() {
        const tpl = document.getElementById("tpl-message-llm").content.cloneNode(true);
        const contentDiv = tpl.querySelector(".message__content");
        contentDiv.innerHTML = `
            <div class="loading-dots" id="loadingIndicator">
                <span></span><span></span><span></span>
            </div>`;
        
        // Return the actual DOM element that was appended so we can modify it later
        const wrapper = document.createElement("div");
        wrapper.appendChild(tpl);
        const node = wrapper.firstElementChild;
        chatFeed.appendChild(node);
        scrollToBottom();
        return node;
    }

    function removeLoadingMessage() {
        const loading = document.getElementById("loadingIndicator");
        if (loading) {
            // Remove the whole message bubble if it only contains the loading dots
            const bubble = loading.closest(".message");
            if (bubble) bubble.remove();
        }
    }

    function scrollToBottom() {
        chatFeed.scrollTo({
            top: chatFeed.scrollHeight,
            behavior: "smooth"
        });
    }

    // ── Fetch NLP Stats (System Message) ──────
    async function fetchQuickStatsAndAppend(filename) {
        const tpl = document.getElementById("tpl-message-nlp").content.cloneNode(true);
        const wrapper = document.createElement("div");
        wrapper.appendChild(tpl);
        const node = wrapper.firstElementChild;
        
        const grid = node.querySelector(".nlp-stats-grid");
        const headerText = node.querySelector(".nlp-card__header span:first-child");
        
        headerText.textContent = `Computing NLP statistics for ${filename}...`;
        grid.innerHTML = `<div class="loading-dots"><span></span><span></span><span></span></div>`;
        
        chatFeed.appendChild(node);
        scrollToBottom();

        try {
            const res = await fetch("/api/quick-stats", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ filename }),
            });

            if (!res.ok) throw new Error("Failed to compute stats");

            const data = await res.json();
            const s = data.stats.summary;

            node.querySelector(".nlp-time").textContent = `${data.computation_time_seconds}s`;
            headerText.textContent = `NLP Context Built: ${filename}`;

            grid.innerHTML = `
                <div class="stat-card-mini">
                    <div class="val">${s.total_log_entries.toLocaleString()}</div>
                    <div class="lbl">Total Logs</div>
                </div>
                <div class="stat-card-mini ${s.total_attacks > 0 ? 'danger' : ''}">
                    <div class="val">${s.total_attacks.toLocaleString()}</div>
                    <div class="lbl">Attacks (${s.attack_ratio}%)</div>
                </div>
                <div class="stat-card-mini ${s.total_failed_logins > 0 ? 'warning' : ''}">
                    <div class="val">${s.total_failed_logins.toLocaleString()}</div>
                    <div class="lbl">Failed Logins</div>
                </div>
            `;

            // Setup breakdown
            const breakdownContainer = node.querySelector(".nlp-attack-breakdown");
            const breakdown = data.stats.attack_breakdown;
            if (Object.keys(breakdown).length > 0) {
                const rowsHtml = Object.entries(breakdown)
                    .map(([type, count]) => `
                        <div class="attack-row-mini">
                            <span class="type">${escapeHtml(type)}</span>
                            <span class="count">${count}</span>
                        </div>`)
                    .join("");
                breakdownContainer.innerHTML = rowsHtml;
            } else {
                breakdownContainer.style.display = "none";
            }

            // Agents
            const malCount = data.stats.user_agents?.malicious_count || 0;
            if (malCount > 0) {
                if(breakdownContainer.style.display === "none") breakdownContainer.style.display = "block";
                breakdownContainer.innerHTML += `
                    <div class="attack-row-mini" style="margin-top:8px;">
                        <span class="type" style="color:var(--warning)">⚠️ Malicious Scanners/Agents</span>
                        <span class="count">${malCount}</span>
                    </div>`;
            }

            scrollToBottom();
        } catch (err) {
            headerText.textContent = `Error computing NLP stats`;
            headerText.style.color = "var(--danger)";
            grid.innerHTML = `<span style="font-size:0.85rem;color:var(--text-muted)">Please try uploading the file again.</span>`;
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
        
        appendUserMessage(query);
        queryInput.value = "";
        queryInput.style.height = "56px"; // Reset height

        if (welcomeView.style.display !== "none") {
            welcomeView.style.display = "none";
            hasStartedChat = true;
        }

        const llmNode = appendLoadingMessage();
        const contentDiv = llmNode.querySelector(".message__content");
        
        setStatus("loading", "Gathering NLP context and generating analysis...");

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

            // Remove loading dots
            contentDiv.innerHTML = "";
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
                                const err = new Error(payload.error);
                                err.isBackendError = true;
                                throw err;
                            }

                            if (payload.token) {
                                fullResponse += payload.token;
                                // Render markdown in real-time
                                contentDiv.innerHTML = marked.parse(fullResponse) + '<span class="streaming-cursor"></span>';
                                scrollToBottom();
                            }

                            if (payload.done) {
                                // Final render: parse markdown + highlight code blocks
                                contentDiv.innerHTML = marked.parse(fullResponse);
                                contentDiv.querySelectorAll('pre code').forEach((el) => {
                                    hljs.highlightElement(el);
                                });
                                scrollToBottom();
                            }
                        } catch (parseErr) {
                            if (parseErr.isBackendError) {
                                throw parseErr;
                            } else {
                                console.warn("Parse error:", parseErr);
                            }
                        }
                    }
                }
            }

            setStatus("success", "Analysis stream complete");
        } catch (err) {
            contentDiv.innerHTML = `<div class="error-text">${escapeHtml(err.message)}</div>`;
            setStatus("error", "Analysis failed");
            scrollToBottom();
        } finally {
            isAnalysing = false;
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
