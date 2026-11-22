// State Management
let sessionScans = [];
const sessionCountEl = document.getElementById('sessionScanCount');

// DOM Elements
const urlForm = document.getElementById('urlForm');
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const scanSpinner = document.getElementById('scanSpinner');
const statusText = document.getElementById('statusText');
const resultContent = document.getElementById('resultContent');
const pasteBtn = document.getElementById('pasteBtn');
const clearBtn = document.getElementById('clearBtn');
const darkModeToggle = document.getElementById('darkModeToggle');

// Tab Switching
const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');

tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        tabButtons.forEach(b => b.classList.remove('active'));
        tabPanes.forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const activePane = document.getElementById(targetTab);
        if (activePane) activePane.classList.add('active');
    });
});

// Theme Management
const savedTheme = localStorage.getItem('phishguard-theme') || 'light';
if (savedTheme === 'dark') {
    document.body.classList.add('dark-mode');
    updateThemeToggleText(true);
}

if (darkModeToggle) {
    darkModeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        const isDark = document.body.classList.contains('dark-mode');
        localStorage.setItem('phishguard-theme', isDark ? 'dark' : 'light');
        updateThemeToggleText(isDark);
    });
}

function updateThemeToggleText(isDark) {
    if (!darkModeToggle) return;
    darkModeToggle.querySelector('.theme-icon').textContent = isDark ? '☀️' : '🌙';
    darkModeToggle.querySelector('.theme-label').textContent = isDark ? 'Light' : 'Dark';
}

// Quick Test Presets
document.querySelectorAll('.preset-pill').forEach(pill => {
    pill.addEventListener('click', () => {
        const targetUrl = pill.getAttribute('data-url');
        urlInput.value = targetUrl;
        // Ensure scanner tab is active
        document.querySelector('[data-tab="tab-scanner"]').click();
        predictUrl(targetUrl);
    });
});

// Clipboard & Clear
if (pasteBtn) {
    pasteBtn.addEventListener('click', async () => {
        try {
            const text = await navigator.clipboard.readText();
            if (text) {
                urlInput.value = text.trim();
                urlInput.focus();
            }
        } catch {
            statusText.textContent = 'Clipboard access not allowed.';
        }
    });
}

if (clearBtn) {
    clearBtn.addEventListener('click', () => {
        urlInput.value = '';
        urlInput.focus();
    });
}

// Scan Loader Helper
function setLoading(isLoading, text = 'Deep scanning URL heuristics & AI model...') {
    if (scanSpinner) scanSpinner.style.display = isLoading ? 'inline-block' : 'none';
    if (scanBtn) scanBtn.disabled = isLoading;
    if (statusText) statusText.textContent = isLoading ? text : '';
}

// Render Single Prediction
function renderResult(payload) {
    let tagClass = 'safe';
    let statusIcon = '🛡️';

    if (payload.prediction === 'Phishing') {
        tagClass = 'phishing';
        statusIcon = '🚨';
    } else if (payload.prediction === 'Suspicious') {
        tagClass = 'suspicious';
        statusIcon = '⚠️';
    }

    const threatBanner = (payload.threat_intel && payload.threat_intel.is_malicious) ? `
        <div class="threat-intel-banner">
            <span>🌐 Threat Intelligence Match:</span>
            <span>${payload.threat_intel.source} &bull; ${payload.threat_intel.threat_type || 'Malicious URL'}</span>
        </div>
    ` : '';

    const reasonsHtml = (payload.reasons || []).map(r => {
        let cls = tagClass;
        let icon = tagClass === 'phishing' ? '🛑' : (tagClass === 'suspicious' ? '⚠️' : '✅');
        if (typeof r === 'object') {
            cls = r.severity || tagClass;
            icon = cls === 'high' ? '🛑' : (cls === 'warning' ? '⚠️' : '✅');
            r = r.reason;
        }
        return `
            <div class="reason-card ${cls}">
                <span class="reason-icon">${icon}</span>
                <span class="reason-text">${r}</span>
            </div>
        `;
    }).join('');

    const featuresHtml = payload.features ? Object.entries(payload.features).map(([k, v]) => `
        <tr>
            <td><strong>${k}</strong></td>
            <td>${v}</td>
        </tr>
    `).join('') : '';

    resultContent.innerHTML = `
        <div class="verdict-card-content">
            <div class="verdict-header">
                <span class="verdict-badge ${tagClass}">
                    ${statusIcon} ${payload.prediction}
                </span>
                <span class="risk-level-tag">${payload.risk_level || 'Evaluated'}</span>
            </div>

            <div class="target-url-display">
                <strong>Target:</strong> ${escapeHtml(payload.url || urlInput.value)}
            </div>

            ${threatBanner}

            <div class="metrics-grid">
                <div class="metric-box">
                    <span class="metric-num" style="color: var(--color-${tagClass});">${payload.confidence}%</span>
                    <span class="metric-title">Confidence</span>
                </div>
                <div class="metric-box">
                    <span class="metric-num">${payload.phishing_prob || 0}%</span>
                    <span class="metric-title">Phishing Prob</span>
                </div>
                <div class="metric-box">
                    <span class="metric-num">${(payload.flags || []).length}</span>
                    <span class="metric-title">Flags Raised</span>
                </div>
            </div>

            <div class="reasons-box">
                <div class="reasons-header">Detected Security Signals & Reasons:</div>
                <div class="reasons-items">
                    ${reasonsHtml || '<div class="reason-card safe">✅ Passed all heuristic and model tests.</div>'}
                </div>
            </div>

            ${payload.features ? `
                <div class="features-accordion">
                    <button type="button" class="accordion-toggle" onclick="toggleFeatures()">
                        <span>🔍 Inspect All 30 Extracted Feature Signals</span>
                        <span id="accordionArrow">▼</span>
                    </button>
                    <div class="features-table-wrapper" id="featuresWrapper">
                        <table class="features-table">
                            <thead>
                                <tr><th>Feature Name</th><th>Extracted Value</th></tr>
                            </thead>
                            <tbody>
                                ${featuresHtml}
                            </tbody>
                        </table>
                    </div>
                </div>
            ` : ''}
        </div>
    `;

    // Record Scan in Session History
    recordSessionScan({
        time: new Date().toLocaleTimeString(),
        url: payload.url || urlInput.value,
        prediction: payload.prediction,
        confidence: payload.confidence
    });
}

function renderError(message) {
    resultContent.innerHTML = `
        <div class="empty-state">
            <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">⚠️</div>
            <h3 style="color: var(--color-phishing);">Scan Failed</h3>
            <p>${message}</p>
        </div>
    `;
}

// Single URL Predict API Call
async function predictUrl(url) {
    const cleanUrl = (url || '').trim();
    if (!cleanUrl) {
        renderError('Please enter a target URL.');
        return;
    }

    setLoading(true);
    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: cleanUrl }),
        });

        const data = await response.json();
        if (!response.ok) {
            renderError(data.error || 'Server error occurred during scan.');
        } else {
            renderResult(data);
        }
    } catch (error) {
        renderError(error.message || 'Network connection failed.');
    } finally {
        setLoading(false);
    }
}

// Form Submission
if (urlForm) {
    urlForm.addEventListener('submit', (e) => {
        e.preventDefault();
        predictUrl(urlInput.value);
    });
}

// Feature Accordion Toggle
window.toggleFeatures = function() {
    const wrapper = document.getElementById('featuresWrapper');
    const arrow = document.getElementById('accordionArrow');
    if (wrapper) {
        wrapper.classList.toggle('open');
        if (arrow) arrow.textContent = wrapper.classList.contains('open') ? '▲' : '▼';
    }
};

// Batch Scanner Logic
const batchInput = document.getElementById('batchInput');
const batchScanBtn = document.getElementById('batchScanBtn');
const batchSampleBtn = document.getElementById('batchSampleBtn');
const batchClearBtn = document.getElementById('batchClearBtn');
const batchExportBtn = document.getElementById('batchExportBtn');
const batchSummary = document.getElementById('batchSummary');
const batchTableWrapper = document.getElementById('batchTableWrapper');
const batchTableBody = document.getElementById('batchTableBody');
let currentBatchResults = [];

if (batchSampleBtn) {
    batchSampleBtn.addEventListener('click', () => {
        batchInput.value = [
            'https://www.google.com',
            'http://192.0.2',
            'http://paypal-security-login.xyz/verify',
            'http://xn--pypal-4ve.com/signin',
            'http://example.com/browse/news',
            'https://github.com/microsoft',
            'http://bit.ly/secure-paypal-login'
        ].join('\n');
    });
}

if (batchClearBtn) {
    batchClearBtn.addEventListener('click', () => {
        batchInput.value = '';
        batchSummary.style.display = 'none';
        batchTableWrapper.style.display = 'none';
        if (batchExportBtn) batchExportBtn.disabled = true;
    });
}

if (batchScanBtn) {
    batchScanBtn.addEventListener('click', async () => {
        const raw = (batchInput.value || '').trim();
        if (!raw) {
            alert('Please enter at least one URL to batch scan.');
            return;
        }

        const urls = raw.split('\n').map(u => u.trim()).filter(Boolean);
        batchScanBtn.disabled = true;
        batchScanBtn.textContent = 'Scanning Batch...';

        try {
            const res = await fetch('/batch_predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls }),
            });
            const data = await res.json();
            if (data.results) {
                currentBatchResults = data.results;
                renderBatchResults(data.results);
            }
        } catch (err) {
            alert('Batch scan error: ' + err.message);
        } finally {
            batchScanBtn.disabled = false;
            batchScanBtn.textContent = 'Scan All URLs';
        }
    });
}

function renderBatchResults(results) {
    let phishing = 0, suspicious = 0, safe = 0;
    batchTableBody.innerHTML = '';

    results.forEach((item, idx) => {
        if (item.prediction === 'Phishing') phishing++;
        else if (item.prediction === 'Suspicious') suspicious++;
        else safe++;

        let badgeClass = item.prediction === 'Phishing' ? 'phishing' : (item.prediction === 'Suspicious' ? 'suspicious' : 'safe');
        const topReason = (item.reasons && item.reasons[0]) ? item.reasons[0] : 'Clean';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${idx + 1}</td>
            <td style="font-family: var(--font-mono); font-size: 0.84rem;">${escapeHtml(item.url)}</td>
            <td><span class="table-badge ${badgeClass}">${item.prediction}</span></td>
            <td><strong>${item.confidence}%</strong></td>
            <td style="font-size: 0.84rem;">${escapeHtml(topReason)}</td>
        `;
        batchTableBody.appendChild(tr);

        // Also add to session history
        recordSessionScan({
            time: new Date().toLocaleTimeString(),
            url: item.url,
            prediction: item.prediction,
            confidence: item.confidence
        });
    });

    document.getElementById('batchCountPhishing').textContent = phishing;
    document.getElementById('batchCountSuspicious').textContent = suspicious;
    document.getElementById('batchCountSafe').textContent = safe;

    batchSummary.style.display = 'grid';
    batchTableWrapper.style.display = 'block';
    if (batchExportBtn) batchExportBtn.disabled = false;
}

if (batchExportBtn) {
    batchExportBtn.addEventListener('click', () => {
        if (!currentBatchResults.length) return;
        let csv = 'Index,URL,Prediction,Risk_Level,Confidence,Primary_Reason\n';
        currentBatchResults.forEach((r, i) => {
            const reason = (r.reasons && r.reasons[0]) ? `"${r.reasons[0].replace(/"/g, '""')}"` : 'None';
            csv += `${i + 1},"${r.url}",${r.prediction},${r.risk_level},${r.confidence}%,${reason}\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard_batch_scan_${Date.now()}.csv`;
        a.click();
    });
}

// Session History Management
function recordSessionScan(scan) {
    sessionScans.unshift(scan);
    if (sessionScans.length > 50) sessionScans.pop();
    if (sessionCountEl) sessionCountEl.textContent = sessionScans.length;
    renderHistoryTable();
}

function renderHistoryTable(filterText = '') {
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;

    const filtered = sessionScans.filter(s => {
        if (!filterText) return true;
        const q = filterText.toLowerCase();
        return s.url.toLowerCase().includes(q) || s.prediction.toLowerCase().includes(q);
    });

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted" style="padding: 1.5rem; text-align: center;">No matching scan records found.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(s => {
        const badgeClass = s.prediction === 'Phishing' ? 'phishing' : (s.prediction === 'Suspicious' ? 'suspicious' : 'safe');
        return `
            <tr>
                <td style="font-size: 0.82rem; color: var(--text-muted);">${s.time}</td>
                <td style="font-family: var(--font-mono); font-size: 0.84rem;">${escapeHtml(s.url)}</td>
                <td><span class="table-badge ${badgeClass}">${s.prediction}</span></td>
                <td><strong>${s.confidence}%</strong></td>
                <td>
                    <button class="btn btn-outline" style="padding: 0.25rem 0.65rem; font-size: 0.8rem;" onclick="recheckUrl('${escapeHtml(s.url)}')">
                        Re-scan
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

window.recheckUrl = function(url) {
    urlInput.value = url;
    document.querySelector('[data-tab="tab-scanner"]').click();
    predictUrl(url);
};

const historySearch = document.getElementById('historySearch');
if (historySearch) {
    historySearch.addEventListener('input', (e) => {
        renderHistoryTable(e.target.value.trim());
    });
}

const clearHistoryBtn = document.getElementById('clearHistoryBtn');
if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
        sessionScans = [];
        if (sessionCountEl) sessionCountEl.textContent = '0';
        renderHistoryTable();
    });
}

// Lightbox Chart Zoom
window.openLightbox = function(src) {
    const modal = document.getElementById('chartModal');
    const modalImg = document.getElementById('modalImg');
    if (modal && modalImg) {
        modal.style.display = 'block';
        modalImg.src = src;
    }
};

window.closeLightbox = function() {
    const modal = document.getElementById('chartModal');
    if (modal) modal.style.display = 'none';
};

// Security Helper
function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
