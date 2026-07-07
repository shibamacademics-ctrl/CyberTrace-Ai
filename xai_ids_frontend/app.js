const mockNetworkDataset = [
    {
        "id": "A1",
        "attack_type": "DDoS",
        "confidence": 94.20,
        "is_attack": true,
        "timestamp": "2026-07-07 21:03:35",
        "summary": [
            "Packet transmission rates surged over 3.5x past static configuration base metrics.",
            "Network stream inter-arrival times collapsed toward immediate zero parameters."
        ],
        "llm_narrative": "This flow is flagged as an active DDoS attempt because packet transmission rates surged over 3x baseline limits while packet sizes shrunk drastically—both characteristics of malicious automated resource flooding.",
        "shap_values": [
            { "feature": "Flow Packets/s", "value": 0.48, "impact": "positive" },
            { "feature": "Flow IAT Mean", "value": 0.35, "impact": "positive" },
            { "feature": "SYN Flag Count", "value": 0.12, "impact": "positive" },
            { "feature": "Average Packet Size", "value": -0.22, "impact": "negative" }
        ],
        "playbook": [
            "Enable immediate threshold rate-limiting on destination edge ports.",
            "Inject real-time dropping flags for anomalous upstream origin paths."
        ]
    },
    {
        "id": "A2",
        "attack_type": "PortScan",
        "confidence": 88.50,
        "is_attack": true,
        "timestamp": "2026-07-07 21:04:12",
        "summary": [
            "Sequential port traversal flagged tracking across 150+ discrete destinations.",
            "SYN flags set high outside established session sequence structures."
        ],
        "llm_narrative": "The interface maps highly methodical, rapid sequential connection attempts across broad sets of structural ports, typical of systematic reconnaissance profiling prior to an infiltration push.",
        "shap_values": [
            { "feature": "SYN Flag Count", "value": 0.55, "impact": "positive" },
            { "feature": "Flow IAT Mean", "value": -0.15, "impact": "negative" },
            { "feature": "Average Packet Size", "value": -0.10, "impact": "negative" }
        ],
        "playbook": [
            "Isolate offending host address into local sandbox VLAN routing rules.",
            "Drop outbound visibility confirmations globally on unassigned network ports."
        ]
    },
    {
        "id": "A3",
        "attack_type": "BENIGN",
        "confidence": 99.10,
        "is_attack": false,
        "timestamp": "2026-07-07 21:05:01",
        "summary": [
            "Packet flow configurations adhere completely to nominal pipeline profiles.",
            "Structural byte delivery metrics show highly balanced asymmetrical tracking."
        ],
        "llm_narrative": "Telemetry matches a clean TLS session routing context. High internal data payload weight profiles combined with expected standard transmission pacing show zero mechanical automation signatures.",
        "shap_values": [
            { "feature": "Average Packet Size", "value": -0.45, "impact": "negative" },
            { "feature": "Flow IAT Mean", "value": -0.35, "impact": "negative" },
            { "feature": "Flow Packets/s", "value": 0.05, "impact": "positive" }
        ],
        "playbook": [
            "No containment directives required. Pass telemetry to active state processing matrix layers."
        ]
    },
    {
        "id": "A4",
        "attack_type": "Botnet",
        "confidence": 76.40,
        "is_attack": true,
        "timestamp": "2026-07-07 21:05:49",
        "summary": [
            "Persistent heartbeat signals match configured Command & Control infrastructure.",
            "Asymmetric payloads broadcast at recurring predictable mathematical loops."
        ],
        "llm_narrative": "Low-volume telemetry shows a cyclical, highly deterministic heartbeat routine communicating with external addresses linked directly to known peer-to-peer adversarial frameworks.",
        "shap_values": [
            { "feature": "Flow IAT Mean", "value": 0.42, "impact": "positive" },
            { "feature": "Flow Packets/s", "value": -0.20, "impact": "negative" },
            { "feature": "SYN Flag Count", "value": 0.15, "impact": "positive" }
        ],
        "playbook": [
            "Terminate established session handshakes immediately across security proxies.",
            "Cross-reference destination host records with integrated threat intelligence groups."
        ]
    },
    {
        "id": "A5",
        "attack_type": "Brute Force",
        "confidence": 91.80,
        "is_attack": true,
        "timestamp": "2026-07-07 21:06:22",
        "summary": [
            "Repeated authentication protocol exceptions captured over telemetry channels.",
            "Payload structures indicate uniform structural content loops."
        ],
        "llm_narrative": "The structural processing stack notes high-frequency authorization payload failures targeted at infrastructure gateways, denoting systematic dictionary enumeration exploits.",
        "shap_values": [
            { "feature": "Flow Packets/s", "value": 0.39, "impact": "positive" },
            { "feature": "Average Packet Size", "value": 0.28, "impact": "positive" },
            { "feature": "Flow IAT Mean", "value": -0.12, "impact": "negative" }
        ],
        "playbook": [
            "Apply geometric cooling-off penalties to originating telemetry paths.",
            "Require dual-factor out-of-band operational verification sweeps."
        ]
    }
];

let activeFilters = { minConfidence: 50, classes: ["DDoS", "PortScan", "Botnet", "Brute Force", "BENIGN"] };
let selectedLogId = mockNetworkDataset[0].id;
const uniqueClasses = ["DDoS", "PortScan", "Botnet", "Brute Force", "BENIGN"];

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

function initApp() {
    renderFilterTokens();
    bindEventListeners();
    applyPipelineProcessing();
    syncDetailedAnalysis(selectedLogId);
}

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

    // Theme Engine Router Event
    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);
        
        const darkIcon = themeToggleBtn.querySelector('.mode-icon-dark');
        const lightIcon = themeToggleBtn.querySelector('.mode-icon-light');
        
        if(nextTheme === 'dark') {
            darkIcon.style.display = 'inline';
            lightIcon.style.display = 'none';
        } else {
            darkIcon.style.display = 'none';
            lightIcon.style.display = 'inline';
        }
    });
}

function applyPipelineProcessing() {
    const filteredLogs = mockNetworkDataset.filter(log => {
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

window.handleLogSelection = function(id) {
    selectedLogId = id;
    applyPipelineProcessing(); 
    syncDetailedAnalysis(id);
};

function syncDetailedAnalysis(id) {
    const targetData = mockNetworkDataset.find(log => log.id === id);
    if (!targetData) return;

    nodeClass.querySelector('.val').textContent = targetData.attack_type;
    nodeClass.querySelector('.val').style.color = targetData.is_attack ? 'var(--color-malicious)' : 'var(--color-safe)';
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

window.addEventListener('DOMContentLoaded', initApp);