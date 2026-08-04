// ============================================================
// BACKEND CONNECTION
// Change this if your FastAPI server runs somewhere other than
// localhost:8000 (e.g. a teammate's machine's IP address).
// ============================================================
const BACKEND_URL = "http://localhost:8000";

// --- 1. INITIALIZE EMPTY STATE ---
// These 6 classes match your model's actual le_encoder.pkl classes,
// confirmed via find_attack.py: BENIGN, Bot, DDoS, Infiltration, PortScan, Web Attack
let networkDataset = []; // Starts empty!
let activeFilters = { minConfidence: 50, classes: ["BENIGN", "Bot", "DDoS", "Infiltration", "PortScan", "Web Attack"] };
let selectedLogId = null;
const uniqueClasses = ["BENIGN", "Bot", "DDoS", "Infiltration", "PortScan", "Web Attack"];

// --- DOM ELEMENTS ---
const alertFeedContainer = document.getElementById('alert-feed');
const tokenFiltersContainer = document.getElementById('token-filters');
const confSlider = document.getElementById('conf-slider');
const confValLabel = document.getElementById('conf-val');
const totalMetricEl = document.getElementById('metric-total');
const threatsMetricEl = document.getElementById('metric-threats');

const nodeClass = document.getElementById('node-class');
const nodeConf = document.getElementById('node-conf');
const nodeTopFeat = document.getElementById('node-top-feature');
const shapBarsContainer = document.getElementById('shap-bars-container');
const forcePlotAxis = document.getElementById('force-plot-axis');
const threatBanner = document.getElementById('threat-banner');
const observationMatrix = document.getElementById('observation-matrix');
const llmNarrativeText = document.getElementById('llm-narrative-text');
const playbookContainer = document.getElementById('playbook-container');
const themeToggleBtn = document.getElementById('theme-toggle');
const statusText = document.querySelector('.system-status span');

// --- 2. STARTUP LOGIC ---
function initApp() {
    renderFilterTokens();
    bindEventListeners();
    resetDashboardToEmpty(); // Ensure everything shows 0 or blank initially
}

function resetDashboardToEmpty() {
    totalMetricEl.textContent = "0";
    threatsMetricEl.textContent = "0";
    alertFeedContainer.innerHTML = `<div style="font-size: 0.95rem; color: var(--text-muted); text-align: center; padding: 2rem;">Awaiting CSV Upload...</div>`;

    nodeClass.querySelector('.val').textContent = "—";
    nodeClass.className = "stat-node";
    nodeConf.querySelector('.val').textContent = "—";
    nodeTopFeat.querySelector('.val').textContent = "—";

    shapBarsContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.9rem;">No data loaded</div>`;
    forcePlotAxis.innerHTML = '';

    threatBanner.className = "banner-alert";
    threatBanner.textContent = "NO LOG SELECTED";

    observationMatrix.innerHTML = '';
    llmNarrativeText.textContent = "Upload a CSV file to process telemetry and invoke Layer 3 generation verification certificates.";
    playbookContainer.innerHTML = '';
}

// --- 3. CSV UPLOAD & REAL BACKEND PREDICTION ---
const csvUploadInput = document.getElementById('csv-upload');

csvUploadInput.addEventListener('change', function (event) {
    const file = event.target.files[0];

    if (file) {
        if (file.type !== "text/csv" && !file.name.endsWith('.csv')) {
            alert("Please upload a valid CSV file.");
            return;
        }

        statusText.textContent = `System Hook: Processing ${file.name}...`;

        const reader = new FileReader();

        reader.onload = async function (e) {
            const rawCSVText = e.target.result;

            let results;
            try {
                results = await parseCSVToDashboardData(rawCSVText);
            } catch (err) {
                console.error("Backend connection failed:", err);
                alert(`Could not reach the backend at ${BACKEND_URL}. Make sure the FastAPI server is running (uvicorn api.main:app --reload --port 8000).`);
                statusText.textContent = `System Hook: Ready`;
                return;
            }

            networkDataset = results;

            if (networkDataset.length > 0) {
                selectedLogId = networkDataset[0].id; // Select first row automatically
                applyPipelineProcessing();
                syncDetailedAnalysis(selectedLogId);
                statusText.textContent = `System Hook: Processed ${networkDataset.length} rows successfully`;
            } else {
                alert("CSV appears to be empty, improperly formatted, or every row was rejected by the backend.");
                statusText.textContent = `System Hook: Ready`;
            }
        };

        reader.onerror = function () {
            alert("Error reading the file. Please try again.");
            statusText.textContent = `System Hook: Ready`;
        };

        reader.readAsText(file);
    }

    event.target.value = ''; // Reset input
});

// Turns one CSV row into a {featureName: number} object for /predict.
function rowToFeatures(headers, values) {
    const features = {};
    headers.forEach((header, idx) => {
        const num = parseFloat(values[idx]);
        features[header] = isNaN(num) ? 0.0 : num;
    });
    return features;
}

// Calls your real FastAPI backend for one row of features.
async function predictRow(features) {
    const response = await fetch(`${BACKEND_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ features })
    });
    if (!response.ok) {
        const errText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errText}`);
    }
    return response.json();
}

// Converts a /predict response into the shape this dashboard renders.
function transformPrediction(prediction, rowId) {
    return {
        id: rowId,
        attack_type: prediction.attack_type,
        confidence: prediction.confidence,
        is_attack: prediction.is_attack,
        timestamp: new Date().toLocaleTimeString(),
        summary: [prediction.summary],
        llm_narrative: prediction.context ? `${prediction.summary} ${prediction.context}` : prediction.summary,
        shap_values: (prediction.top_shap_values || []).map(s => ({
            feature: s.feature,
            value: s.shap_value,
            impact: s.impact
        })),
        playbook: prediction.is_attack
            ? [
                "Escalate this flow to your security analyst for review.",
                "Cross-reference the source host with recent activity logs."
              ]
            : ["No containment directives required. Traffic is within normal parameters."]
    };
}

// Sends each CSV row to the real backend (one at a time) and builds
// dashboard-ready data from the actual model + SHAP predictions.
async function parseCSVToDashboardData(csvText) {
    const lines = csvText.split('\n').filter(line => line.trim() !== '');
    if (lines.length < 2) return []; // Needs at least headers and one row

    const headers = lines[0].split(',').map(h => h.trim());
    const parsedData = [];

    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',').map(v => v.trim());
        if (values.length !== headers.length) continue; // skip malformed rows

        statusText.textContent = `System Hook: Predicting row ${i} of ${lines.length - 1}...`;

        const features = rowToFeatures(headers, values);
        const prediction = await predictRow(features); // throws on network/backend failure
        parsedData.push(transformPrediction(prediction, `CSV-ROW-${i}`));
    }
    return parsedData;
}

// --- 4. CORE DASHBOARD LOGIC ---
function renderFilterTokens() {
    tokenFiltersContainer.innerHTML = uniqueClasses.map(cls => `
        <div>
            <input type="checkbox" id="token-${cls}" class="token-checkbox" value="${cls}" checked>
            <label for="token-${cls}" class="token-label">${cls}</label>
        </div>
    `).join('');
}

function bindEventListeners() {
    confSlider.addEventListener('input', (e) => {
        activeFilters.minConfidence = parseInt(e.target.value);
        confValLabel.textContent = `${activeFilters.minConfidence}%`;
        applyPipelineProcessing();
    });

    tokenFiltersContainer.addEventListener('change', () => {
        const checkedBoxes = tokenFiltersContainer.querySelectorAll('.token-checkbox:checked');
        activeFilters.classes = Array.from(checkedBoxes).map(cb => cb.value);
        applyPipelineProcessing();
    });

    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);

        const darkIcon = themeToggleBtn.querySelector('.mode-icon-dark');
        const lightIcon = themeToggleBtn.querySelector('.mode-icon-light');

        if (nextTheme === 'dark') {
            darkIcon.style.display = 'inline';
            lightIcon.style.display = 'none';
        } else {
            darkIcon.style.display = 'none';
            lightIcon.style.display = 'inline';
        }
    });
}

function applyPipelineProcessing() {
    const filteredLogs = networkDataset.filter(log => {
        return log.confidence >= activeFilters.minConfidence && activeFilters.classes.includes(log.attack_type);
    });

    totalMetricEl.textContent = filteredLogs.length;
    threatsMetricEl.textContent = filteredLogs.filter(l => l.is_attack).length;

    renderActivityFeed(filteredLogs);
}

function renderActivityFeed(logs) {
    if (logs.length === 0) {
        alertFeedContainer.innerHTML = `<div style="font-size: 0.95rem; color: var(--text-muted); text-align: center; padding: 2rem;">No matching session logs.</div>`;
        return;
    }

    alertFeedContainer.innerHTML = logs.map(log => {
        const riskClass = log.is_attack ? 'malicious' : 'safe';
        const isActive = log.id === selectedLogId ? 'active' : '';
        return `
            <div class="log-card ${riskClass} ${isActive}" onclick="handleLogSelection('${log.id}')">
                <div class="log-card-header">
                    <span class="log-tag">${log.attack_type}</span>
                    <span class="log-conf">${log.confidence.toFixed(1)}%</span>
                </div>
                <div class="log-time">${log.timestamp}</div>
            </div>
        `;
    }).join('');
}

window.handleLogSelection = function (id) {
    selectedLogId = id;
    applyPipelineProcessing();
    syncDetailedAnalysis(id);
};

function syncDetailedAnalysis(id) {
    const targetData = networkDataset.find(log => log.id === id);
    if (!targetData) return;

    nodeClass.querySelector('.val').textContent = targetData.attack_type;
    nodeClass.querySelector('.val').style.color = targetData.is_attack ? 'var(--color-malicious)' : 'var(--color-safe)';
    nodeClass.className = `stat-node ${targetData.is_attack ? 'danger' : 'secure'}`;
    nodeConf.querySelector('.val').textContent = `${targetData.confidence.toFixed(1)}%`;

    const topFeatureNode = targetData.shap_values.reduce((prev, current) => (Math.abs(current.value) > Math.abs(prev.value)) ? current : prev);
    nodeTopFeat.querySelector('.val').textContent = topFeatureNode.feature;

    shapBarsContainer.innerHTML = targetData.shap_values.map(shap => {
        const percentageWidth = Math.min(Math.abs(shap.value) * 100, 100);
        return `
            <div class="shap-row">
                <div class="shap-label-meta">
                    <span class="shap-feat-name">${shap.feature}</span>
                    <span class="shap-feat-val">${shap.value > 0 ? '+' : ''}${shap.value.toFixed(4)}</span>
                </div>
                <div class="bar-track">
                    <div class="bar-fill ${shap.impact === 'positive' ? 'pos' : 'neg'}" style="width: ${percentageWidth}%"></div>
                </div>
            </div>
        `;
    }).join('');

    renderForcePlot(targetData);

    if (targetData.is_attack) {
        threatBanner.className = "banner-alert malicious";
        threatBanner.textContent = `🚨 EXPLOIT ISOLATED: ${targetData.attack_type.toUpperCase()}`;
        playbookContainer.className = "playbook-steps";
    } else {
        threatBanner.className = "banner-alert safe";
        threatBanner.textContent = "✅ FLOW VERIFIED SAFE";
        playbookContainer.className = "playbook-steps safe-playbook";
    }

    observationMatrix.innerHTML = targetData.summary.map(sentence => `<li class="matrix-item">${sentence}</li>`).join('');
    llmNarrativeText.textContent = targetData.llm_narrative;
    playbookContainer.innerHTML = targetData.playbook.map((step, idx) => `
        <div class="step-node">
            <span class="step-num">0${idx + 1}.</span>
            <span>${step}</span>
        </div>
    `).join('');
}

function renderForcePlot(data) {
    forcePlotAxis.innerHTML = '';
    let expectedValuePointer = 0.5;

    data.shap_values.forEach(shap => {
        const segmentWidth = Math.abs(shap.value) * 40;
        const segmentEl = document.createElement('div');
        segmentEl.className = `force-segment ${shap.impact === 'positive' ? 'push-pos' : 'push-neg'}`;
        segmentEl.style.width = `${segmentWidth}%`;
        forcePlotAxis.appendChild(segmentEl);
        expectedValuePointer += (shap.impact === 'positive' ? 1 : -1) * (Math.abs(shap.value) * 0.4);
    });

    const markerEl = document.createElement('div');
    markerEl.className = 'force-marker';
    markerEl.style.left = `${Math.max(Math.min(expectedValuePointer * 100, 95), 5)}%`;
    forcePlotAxis.appendChild(markerEl);
}

// Start application
window.addEventListener('DOMContentLoaded', initApp);


function startSOCClock() {
    const clockElement = document.getElementById('soc-clock');
    if (!clockElement) return;

    function updateTime() {
        const now = new Date();

        // This strictly forces the time to Indian Standard Time (IST)
        const timeString = now.toLocaleTimeString('en-US', {
            timeZone: 'Asia/Kolkata',
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        clockElement.textContent = `SYS.TIME: ${timeString} IST`;
    }

    updateTime(); // Run immediately
    setInterval(updateTime, 1000); // Update every second
}

document.addEventListener('DOMContentLoaded', startSOCClock);
