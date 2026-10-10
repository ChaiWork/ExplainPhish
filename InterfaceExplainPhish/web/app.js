/**
 * ExplainPhish Web SOC Workstation Client
 * Reactive client-side orchestrator managing file uploads, live URL fetching,
 * LangGraph pipeline execution, and interactive evidence visualization.
 */

(function () {
    'use strict';

    // State
    let currentMode = 'file'; // 'file' | 'url'
    let selectedFile = null;
    let activeInvestigationData = null;

    // DOM Elements
    const tabModeFile = document.getElementById('tabModeFile');
    const tabModeUrl = document.getElementById('tabModeUrl');
    const fileUploadContainer = document.getElementById('fileUploadContainer');
    const urlInputContainer = document.getElementById('urlInputContainer');
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const btnBrowseFile = document.getElementById('btnBrowseFile');
    const selectedFileInfo = document.getElementById('selectedFileInfo');
    const selectedFileName = document.getElementById('selectedFileName');
    const selectedFileSize = document.getElementById('selectedFileSize');
    const btnClearFile = document.getElementById('btnClearFile');
    const urlInput = document.getElementById('urlInput');
    const btnRunInvestigation = document.getElementById('btnRunInvestigation');
    const btnRunText = document.getElementById('btnRunText');
    const sampleSelect = document.getElementById('sampleSelect');
    const btnRefreshSamples = document.getElementById('btnRefreshSamples');

    // Stepper Elements
    const stepperStatusText = document.getElementById('stepperStatusText');
    const stepperRows = {
        intake_safety: document.getElementById('step-intake_safety'),
        feature_extraction: document.getElementById('step-feature_extraction'),
        ml_ensemble: document.getElementById('step-ml_ensemble'),
        explainability: document.getElementById('step-explainability'),
        deep_threat_analysis: document.getElementById('step-deep_threat_analysis'),
        mitre_mapping: document.getElementById('step-mitre_mapping'),
        soc_report: document.getElementById('step-soc_report'),
    };

    // Metadata Card
    const metadataCard = document.getElementById('metadataCard');
    const metaFormat = document.getElementById('metaFormat');
    const metaSize = document.getElementById('metaSize');
    const metaSha256 = document.getElementById('metaSha256');
    const metaMd5 = document.getElementById('metaMd5');

    // Verdict Banner
    const verdictBanner = document.getElementById('verdictBanner');
    const verdictBadge = document.getElementById('verdictBadge');
    const threatSeverityBadge = document.getElementById('threatSeverityBadge');
    const confPercentage = document.getElementById('confPercentage');
    const confProgressFill = document.getElementById('confProgressFill');
    const actionText = document.getElementById('actionText');

    // Tabs
    const navTabs = document.querySelectorAll('.nav-tab');
    const tabPanes = document.querySelectorAll('.tab-pane');

    // Report Actions
    const btnCopyReport = document.getElementById('btnCopyReport');
    const btnDownloadReport = document.getElementById('btnDownloadReport');
    const reportViewer = document.getElementById('reportViewer');

    // Toast
    const toastNotification = document.getElementById('toastNotification');
    const toastMessage = document.getElementById('toastMessage');
    const toastIcon = document.getElementById('toastIcon');

    // ─────────────────────────────────────────────────────────────────────────
    // Initialization
    // ─────────────────────────────────────────────────────────────────────────

    function init() {
        setupEventListeners();
        loadSampleCatalog();
    }

    function setupEventListeners() {
        // Mode switching
        tabModeFile.addEventListener('click', () => setMode('file'));
        tabModeUrl.addEventListener('click', () => setMode('url'));

        // File drop zone
        dropZone.addEventListener('click', () => fileInput.click());
        btnBrowseFile.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });
        fileInput.addEventListener('change', handleFileSelect);

        // Drag and drop
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('dragover');
            });
        });
        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('dragover');
            });
        });
        dropZone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleFileChosen(e.dataTransfer.files[0]);
            }
        });

        // Clear file
        btnClearFile.addEventListener('click', clearSelectedFile);

        // URL input listeners
        urlInput.addEventListener('input', validateRunState);
        urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                runInvestigation();
            }
        });

        // Sample Select
        sampleSelect.addEventListener('change', handleSampleChosen);
        btnRefreshSamples.addEventListener('click', loadSampleCatalog);

        // Primary Run Button
        btnRunInvestigation.addEventListener('click', runInvestigation);

        // Tab Navigation
        navTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.getAttribute('data-tab');
                switchTab(targetTab);
            });
        });

        // Copy / Download Report
        btnCopyReport.addEventListener('click', copyReportToClipboard);
        btnDownloadReport.addEventListener('click', downloadReportMarkdown);

        // Copyable Hash metadata
        [metaSha256, metaMd5].forEach(el => {
            el.addEventListener('click', () => {
                if (el.textContent && el.textContent !== '-') {
                    navigator.clipboard.writeText(el.textContent);
                    showToast('Hash copied to clipboard', '📋');
                }
            });
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Mode & Ingestion Management
    // ─────────────────────────────────────────────────────────────────────────

    function setMode(mode) {
        currentMode = mode;
        if (mode === 'file') {
            tabModeFile.classList.add('active');
            tabModeUrl.classList.remove('active');
            fileUploadContainer.classList.remove('hidden');
            urlInputContainer.classList.add('hidden');
        } else {
            tabModeUrl.classList.add('active');
            tabModeFile.classList.remove('active');
            urlInputContainer.classList.remove('hidden');
            fileUploadContainer.classList.add('hidden');
        }
        validateRunState();
    }

    function handleFileSelect(e) {
        if (e.target.files && e.target.files.length > 0) {
            handleFileChosen(e.target.files[0]);
        }
    }

    function handleFileChosen(file) {
        selectedFile = file;
        selectedFileName.textContent = file.name;
        selectedFileSize.textContent = formatBytes(file.size);
        dropZone.classList.add('hidden');
        selectedFileInfo.classList.remove('hidden');
        sampleSelect.value = '';
        validateRunState();
    }

    function clearSelectedFile() {
        selectedFile = null;
        fileInput.value = '';
        dropZone.classList.remove('hidden');
        selectedFileInfo.classList.add('hidden');
        validateRunState();
    }

    function validateRunState() {
        if (currentMode === 'file') {
            btnRunInvestigation.disabled = !selectedFile;
        } else {
            const val = urlInput.value.trim();
            btnRunInvestigation.disabled = val.length === 0;
        }
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sample Catalog
    // ─────────────────────────────────────────────────────────────────────────

    async function loadSampleCatalog() {
        try {
            const resp = await fetch('/api/samples');
            const data = await resp.json();
            sampleSelect.innerHTML = '<option value="">Select Sample Document...</option>';
            if (data.samples && data.samples.length > 0) {
                data.samples.forEach(s => {
                    const opt = document.createElement('option');
                    opt.value = s.id;
                    opt.textContent = `[${s.category}] ${s.name} (${s.format})`;
                    sampleSelect.appendChild(opt);
                });
            }
        } catch (err) {
            console.error('Failed to load sample catalog:', err);
        }
    }

    function handleSampleChosen() {
        const path = sampleSelect.value;
        if (!path) return;
        // Trigger sample analyze directly
        runSampleAnalysis(path);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Investigation Pipeline Execution
    // ─────────────────────────────────────────────────────────────────────────

    async function runInvestigation() {
        if (btnRunInvestigation.disabled) return;

        setAnalyzingUI();

        try {
            let resp;
            if (currentMode === 'file') {
                const formData = new FormData();
                formData.append('file', selectedFile);
                resp = await fetch('/api/analyze/file', {
                    method: 'POST',
                    body: formData,
                });
            } else {
                let targetUrl = urlInput.value.trim();
                if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                    targetUrl = 'https://' + targetUrl;
                    urlInput.value = targetUrl;
                }
                resp = await fetch('/api/analyze/url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: targetUrl }),
                });
            }

            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({ detail: 'Unknown server error' }));
                throw new Error(errData.detail || 'Analysis request failed');
            }

            const data = await resp.json();
            handleInvestigationSuccess(data);
        } catch (err) {
            handleInvestigationError(err.message);
        }
    }

    async function runSampleAnalysis(samplePath) {
        setAnalyzingUI();
        try {
            const resp = await fetch('/api/analyze/sample', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sample_path: samplePath }),
            });

            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({ detail: 'Unknown error' }));
                throw new Error(errData.detail || 'Sample analysis failed');
            }

            const data = await resp.json();
            handleInvestigationSuccess(data);
        } catch (err) {
            handleInvestigationError(err.message);
        }
    }

    function setAnalyzingUI() {
        btnRunInvestigation.disabled = true;
        btnRunText.textContent = 'Investigating...';
        stepperStatusText.textContent = 'Active: LangGraph Orchestrator Running';

        // Reset Stepper rows to running animation
        Object.keys(stepperRows).forEach(key => {
            const row = stepperRows[key];
            row.className = 'stepper-row running';
            row.querySelector('.step-glyph').textContent = '[>]';
        });

        // Banner
        verdictBanner.className = 'verdict-banner banner-neutral';
        verdictBadge.textContent = 'ANALYZING...';
        threatSeverityBadge.textContent = 'IN PROGRESS';
        confPercentage.textContent = '50.0%';
        confProgressFill.style.width = '50%';
        actionText.textContent = 'Executing 7-stage autonomous LangGraph SOC workflow...';
    }

    function handleInvestigationSuccess(data) {
        activeInvestigationData = data;
        btnRunInvestigation.disabled = false;
        btnRunText.textContent = 'Run Investigation';
        stepperStatusText.textContent = 'Investigation Complete';

        // 1. Update Stepper with actual stage outcomes and rules
        updateStepperOutcomes(data);

        // 2. Update Metadata Card
        updateMetadataCard(data);

        // 3. Update Verdict Hero Banner
        updateVerdictBanner(data);

        // 4. Update Tab Contents
        renderOverviewTab(data);
        renderModelsTab(data);
        renderXaiTab(data);
        renderForensicsTab(data);
        renderMitreTab(data);
        renderReportTab(data);

        showToast('Autonomous SOC triage completed', '✅');
    }

    function handleInvestigationError(msg) {
        btnRunInvestigation.disabled = false;
        btnRunText.textContent = 'Run Investigation';
        stepperStatusText.textContent = 'Investigation Failed';

        verdictBanner.className = 'verdict-banner banner-malicious';
        verdictBadge.textContent = 'ANALYSIS ERROR';
        threatSeverityBadge.textContent = 'FAILED';
        actionText.textContent = msg;

        showToast(msg, '❌');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stepper UI Renderer
    // ─────────────────────────────────────────────────────────────────────────

    function updateStepperOutcomes(data) {
        const rules = data.applied_rules || {};
        const isBorderline = data.is_borderline;
        const deepAdj = (data.deep_analysis && data.deep_analysis.verdict_adjustment) || 'NONE';

        // Stage 1: Intake
        setStepRow('intake_safety', 'completed', '[v]',
            `Verified ${data.format_display || 'Document'} • Rule: Sandbox Limits Passed`,
            rules.intake_safety || 'Rule 1: Format signature, magic bytes & container limits verified.');

        // Stage 2: Telemetry
        const nFeats = Object.keys(data.raw_features || {}).length;
        setStepRow('feature_extraction', 'completed', '[v]',
            `Extracted ${nFeats} vectors • Rule: Static Telemetry`,
            rules.feature_extraction || `Rule 2: Computed ${nFeats} static structural telemetry vectors.`);

        // Stage 3: ML Consensus
        const v = data.ensemble_verdict || 'UNKNOWN';
        const c = data.confidence_score || 0;
        if (isBorderline) {
            setStepRow('ml_ensemble', 'borderline', '[!]',
                `${v} (${(c * 100).toFixed(1)}%) • Rule: Borderline Escalated`,
                rules.ml_ensemble || 'Rule 3: Borderline criteria triggered -> Escalate to Deep Forensics.');
        } else {
            setStepRow('ml_ensemble', 'completed', '[v]',
                `${v} (${(c * 100).toFixed(1)}%) • Rule: Unanimous Consensus`,
                rules.ml_ensemble || `Rule 3: Unanimous multi-model agreement (${(c * 100).toFixed(1)}% confidence).`);
        }

        // Stage 4: XAI
        const nDrivers = (data.top_risk_drivers || []).length;
        setStepRow('explainability', 'completed', '[v]',
            `Ranked ${nDrivers} drivers • Rule: XAI Attribution`,
            rules.explainability || `Rule 4: Ranked top ${nDrivers} feature drivers.`);

        // Stage 5: Deep Forensics
        if (data.deep_analysis && data.deep_analysis.forensic_inspection_conducted) {
            if (deepAdj === 'DOWNGRADE_TO_BENIGN') {
                setStepRow('deep_threat_analysis', 'borderline', '[!]',
                    `Calibrated • Rule: False-Positive Screened`,
                    rules.deep_threat_analysis || 'Rule 5A: Zero macros, zero OLE, zero DDE verified safe.');
            } else if (deepAdj === 'UPGRADE_TO_MALICIOUS') {
                setStepRow('deep_threat_analysis', 'malicious', '[!]',
                    `Overridden • Rule: Forensic Payload Detected`,
                    rules.deep_threat_analysis || 'Rule 5B: Active execution vectors detected.');
            } else if (deepAdj === 'ESCALATE_TO_SUSPICIOUS') {
                setStepRow('deep_threat_analysis', 'borderline', '[!]',
                    `Policy Violation • Rule: AUP Enforcement`,
                    rules.deep_threat_analysis || 'Rule 5D: High-risk gambling/casino operations detected.');
            } else {
                const nInd = (data.deep_analysis.indicators || []).length;
                setStepRow('deep_threat_analysis', 'completed', '[v]',
                    `${nInd} findings • Rule: Deep Static Verification`,
                    rules.deep_threat_analysis || `Rule 5C: Verified ${nInd} telemetry indicators.`);
            }
        } else {
            setStepRow('deep_threat_analysis', 'bypassed', '[o]',
                `Bypassed • Rule: Fast-Track (Clear Consensus)`,
                'Rule: High confidence unanimous consensus achieved; deep forensics bypassed.');
        }

        // Stage 6: MITRE
        const nMitre = (data.mitre_tactics || []).length;
        setStepRow('mitre_mapping', 'completed', '[v]',
            `${nMitre} techniques • Rule: ATT&CK & SOAR`,
            rules.mitre_mapping || `Rule 6: Mapped ${nMitre} MITRE techniques and SOAR playbooks.`);

        // Stage 7: Report
        setStepRow('soc_report', 'completed', '[v]',
            `Generated dossier • Rule: IR Synthesis`,
            rules.soc_report || 'Rule 7: Synthesized executive incident report with timeline and playbooks.');
    }

    function setStepRow(nodeKey, stateClass, glyph, subText, tooltipText) {
        const row = stepperRows[nodeKey];
        if (!row) return;
        row.className = `stepper-row ${stateClass}`;
        row.querySelector('.step-glyph').textContent = glyph;
        const sub = row.querySelector('.step-sub');
        sub.textContent = subText;
        row.setAttribute('title', tooltipText || subText);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Metadata Card
    // ─────────────────────────────────────────────────────────────────────────

    function updateMetadataCard(data) {
        metadataCard.classList.remove('hidden');
        metaFormat.textContent = data.format_display || data.file_format || '-';
        metaSize.textContent = `${(data.file_size_bytes || 0).toLocaleString()} bytes`;
        metaSha256.textContent = data.file_hash_sha256 || '-';
        metaMd5.textContent = data.file_hash_md5 || '-';
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verdict Hero Banner
    // ─────────────────────────────────────────────────────────────────────────

    function updateVerdictBanner(data) {
        const verdict = data.final_verdict || data.ensemble_verdict || 'UNKNOWN';
        const threat = data.threat_level || 'UNKNOWN';
        const conf = data.confidence_score || 0;
        const pct = (conf * 100).toFixed(1) + '%';

        verdictBadge.textContent = verdict.toUpperCase();
        threatSeverityBadge.textContent = threat.toUpperCase();
        confPercentage.textContent = pct;
        confProgressFill.style.width = pct;

        // Action Recommendation
        if (data.soc_playbook_actions && data.soc_playbook_actions.length > 0) {
            actionText.textContent = `${data.soc_playbook_actions[0].tier}: ${data.soc_playbook_actions[0].action}`;
        } else {
            actionText.textContent = 'No immediate SOC escalation required.';
        }

        // Banner Color Coding
        if (verdict.includes('MALICIOUS')) {
            verdictBanner.className = 'verdict-banner banner-malicious';
        } else if (verdict.includes('SUSPICIOUS') || verdict.includes('INACCESSIBLE')) {
            verdictBanner.className = 'verdict-banner banner-suspicious';
        } else if (verdict.includes('Screened') || threat === 'LOW') {
            verdictBanner.className = 'verdict-banner banner-calibrated';
        } else if (verdict.includes('BENIGN')) {
            verdictBanner.className = 'verdict-banner banner-benign';
        } else {
            verdictBanner.className = 'verdict-banner banner-neutral';
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tab Renderers
    // ─────────────────────────────────────────────────────────────────────────

    function renderOverviewTab(data) {
        document.getElementById('overviewSummaryText').textContent =
            data.executive_summary || `File classified as ${data.final_verdict} (${data.threat_level}) with ${(data.confidence_score * 100).toFixed(1)}% confidence.`;

        const tbody = document.getElementById('tbodyAppliedRules');
        const rules = data.applied_rules || {};
        const keys = ['intake_safety', 'feature_extraction', 'ml_ensemble', 'explainability', 'deep_threat_analysis', 'mitre_mapping', 'soc_report'];

        const rows = keys.filter(k => rules[k]).map(k => {
            const title = k.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
            return `<tr>
                <td><strong>${title}</strong></td>
                <td>${escapeHtml(rules[k])}</td>
            </tr>`;
        });

        tbody.innerHTML = rows.length > 0 ? rows.join('') : '<tr><td colspan="2" class="empty-state">No rules evaluated.</td></tr>';
    }

    function renderModelsTab(data) {
        const preds = data.model_predictions || [];
        const votes = data.vote_counts || { malicious: 0, benign: 0 };
        document.getElementById('voteCountsDisplay').textContent =
            `${votes.malicious} Malicious vs ${votes.benign} Benign (Consensus: ${data.ensemble_verdict || 'N/A'})`;

        const consensusTag = document.getElementById('consensusTag');
        if (data.unanimous) {
            consensusTag.textContent = 'Unanimous 100% Agreement';
            consensusTag.style.color = '#10B981';
        } else {
            consensusTag.textContent = 'Split Decision Resolved via Forensics';
            consensusTag.style.color = '#F59E0B';
        }

        const tbody = document.getElementById('tbodyModels');
        if (preds.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No models evaluated.</td></tr>';
            return;
        }

        tbody.innerHTML = preds.map(p => {
            const isMal = p.prediction === 1;
            const predBadge = isMal ? '<span style="color: #EF4444; font-weight: 700;">MALICIOUS</span>' : '<span style="color: #10B981; font-weight: 700;">BENIGN</span>';
            const icon = isMal ? '⚠️' : '✅';
            const prob = ((p.probability || p.probability_malicious || 0) * 100).toFixed(1) + '%';
            return `<tr>
                <td><strong>${escapeHtml(p.model)}</strong></td>
                <td>${predBadge}</td>
                <td><code>${prob}</code></td>
                <td>${icon}</td>
            </tr>`;
        }).join('');
    }

    function renderXaiTab(data) {
        const drivers = data.top_risk_drivers || [];
        const tbody = document.getElementById('tbodyXai');
        if (drivers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No risk drivers calculated.</td></tr>';
            return;
        }

        tbody.innerHTML = drivers.map(d => {
            const isRisk = d.direction === '↑';
            const dirIcon = isRisk ? '<span style="color: #EF4444;">🔺 Increases Risk</span>' : '<span style="color: #10B981;">🔻 Reduces Risk</span>';
            const impactSign = d.impact >= 0 ? `+${d.impact.toFixed(4)}` : d.impact.toFixed(4);
            const zSign = d.std_value >= 0 ? `+${d.std_value.toFixed(2)}` : d.std_value.toFixed(2);
            return `<tr>
                <td><code>${escapeHtml(d.feature)}</code></td>
                <td>${escapeHtml(d.description || '-')}</td>
                <td><code>${d.raw_value}</code></td>
                <td><code>${zSign}</code></td>
                <td><strong>${d.direction}</strong></td>
                <td>${dirIcon} (<code>${impactSign}</code>)</td>
            </tr>`;
        }).join('');
    }

    function renderForensicsTab(data) {
        const deep = data.deep_analysis || {};
        const rationaleBox = document.getElementById('forensicRationaleBox');
        if (deep.rationale) {
            rationaleBox.classList.remove('hidden');
            document.getElementById('forensicRationaleText').textContent = deep.rationale;
        } else {
            rationaleBox.classList.add('hidden');
        }

        const findingsList = document.getElementById('findingsList');
        const indicators = deep.indicators || [];
        if (indicators.length > 0) {
            findingsList.innerHTML = indicators.map(ind => `<li>• ${escapeHtml(ind)}</li>`).join('');
        } else {
            findingsList.innerHTML = '<li class="empty-state">Verified: 0 active execution vectors detected.</li>';
        }

        const tbody = document.getElementById('tbodyIocs');
        const iocs = data.indicators_of_compromise || [];
        if (iocs.length > 0) {
            tbody.innerHTML = iocs.map(ioc => `<tr>
                <td><strong>${escapeHtml(ioc.type)}</strong></td>
                <td><code>${escapeHtml(ioc.value)}</code></td>
            </tr>`).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="2" class="empty-state">No Indicators of Compromise (IOCs) detected.</td></tr>';
        }
    }

    function renderMitreTab(data) {
        const mitre = data.mitre_tactics || [];
        const grid = document.getElementById('mitreCardsGrid');
        if (mitre.length > 0) {
            grid.innerHTML = mitre.map(m => `<div class="mitre-card">
                <div class="mitre-id">${escapeHtml(m.id)}</div>
                <div class="mitre-technique">${escapeHtml(m.technique)}</div>
                <span class="mitre-tactic">${escapeHtml(m.tactic)}</span>
                <p class="mitre-desc">${escapeHtml(m.description)}</p>
            </div>`).join('');
        } else {
            grid.innerHTML = '<div class="empty-state-card">No malicious MITRE techniques identified.</div>';
        }

        const tbody = document.getElementById('tbodySoar');
        const actions = data.soc_playbook_actions || [];
        if (actions.length > 0) {
            tbody.innerHTML = actions.map(a => `<tr>
                <td><strong>${escapeHtml(a.stage)}</strong></td>
                <td><span style="color: #38BDF8; font-weight: 600;">${escapeHtml(a.tier)}</span></td>
                <td>${escapeHtml(a.action)}</td>
            </tr>`).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No playbooks generated.</td></tr>';
        }
    }

    function renderReportTab(data) {
        const md = data.soc_report_markdown || 'Report synthesis pending.';
        reportViewer.textContent = md;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tab Switching & Utilities
    // ─────────────────────────────────────────────────────────────────────────

    function switchTab(targetTab) {
        navTabs.forEach(t => {
            const isMatch = t.getAttribute('data-tab') === targetTab;
            t.classList.toggle('active', isMatch);
            t.setAttribute('aria-selected', isMatch ? 'true' : 'false');
        });
        tabPanes.forEach(pane => {
            pane.classList.toggle('active', pane.id === `pane${targetTab.charAt(0).toUpperCase() + targetTab.slice(1)}`);
        });
    }

    function copyReportToClipboard() {
        if (!activeInvestigationData || !activeInvestigationData.soc_report_markdown) {
            showToast('No report available to copy', '⚠️');
            return;
        }
        navigator.clipboard.writeText(activeInvestigationData.soc_report_markdown);
        showToast('Report copied to clipboard', '📋');
    }

    function downloadReportMarkdown() {
        if (!activeInvestigationData || !activeInvestigationData.soc_report_markdown) {
            showToast('No report available to download', '⚠️');
            return;
        }
        const blob = new Blob([activeInvestigationData.soc_report_markdown], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const hash = (activeInvestigationData.file_hash_sha256 || 'report').substring(0, 10);
        a.href = url;
        a.download = `SOC_Report_${hash}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Report downloaded', '💾');
    }

    function showToast(message, icon = 'ℹ️') {
        toastMessage.textContent = message;
        toastIcon.textContent = icon;
        toastNotification.classList.remove('hidden');
        setTimeout(() => {
            toastNotification.classList.add('hidden');
        }, 3500);
    }

    function escapeHtml(text) {
        if (!text) return '';
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Run Initialization
    document.addEventListener('DOMContentLoaded', init);
})();
