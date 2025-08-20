(() => {
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    const urlText = document.getElementById('url-text');
    const riskNum = document.getElementById('risk-num');
    const gaugeNum = document.getElementById('gauge-num');
    const reasonsEl = document.getElementById('reasons');
    const statusPill = document.getElementById('status-pill');
    const refreshButton = document.getElementById('refresh-button');

    function getActiveTabUrl() {
        return new Promise((resolve) => {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                resolve((tabs && tabs[0] && tabs[0].url) || '');
            });
        });
    }

    function getConfig() {
        return new Promise((resolve) => {
            chrome.storage.sync.get({ apiBase: '', mode: 'balanced', fastOnSlow: true }, (cfg) => resolve(cfg));
        });
    }

    async function callBackend(url) {
        const cfg = await getConfig();
        const base = cfg.apiBase && cfg.apiBase.trim() ? cfg.apiBase.trim() : (window.API_BASE || 'http://127.0.0.1:5000');
        const API = base.replace(/\/$/, '');
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 7000);
        try {
            const res = await fetch(`${API}/process`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, mode: cfg.mode, fast: false }),
                signal: controller.signal,
            });
            clearTimeout(timer);
            return await res.json();
        } catch (e) {
            clearTimeout(timer);
            throw e;
        }
    }

    async function callBackendFast(url) {
        const cfg = await getConfig();
        const base = cfg.apiBase && cfg.apiBase.trim() ? cfg.apiBase.trim() : (window.API_BASE || 'http://127.0.0.1:5000');
        const API = base.replace(/\/$/, '');
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        try {
            const res = await fetch(`${API}/process`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, mode: cfg.mode, fast: true }),
                signal: controller.signal,
            });
            clearTimeout(timer);
            return await res.json();
        } catch (e) {
            clearTimeout(timer);
            throw e;
        }
    }

    function renderResult(res, cfg) {
        loading.classList.add('hidden');
        result.classList.remove('hidden');

        const pred = typeof res.prediction === 'number' ? res.prediction : null;
        let risk = Math.max(0, Math.min(100, Number(res.risk) || 0));
        if (cfg.mode === 'strict') risk = Math.min(100, Math.round(risk * 1.1));
        if (cfg.mode === 'relaxed') risk = Math.max(0, Math.round(risk * 0.9));

        riskNum.textContent = `${risk}%`;
        gaugeNum.textContent = `${risk}%`;
        result.style.setProperty('--p', risk);

        result.classList.remove('phishing', 'safe');
        statusPill.className = 'pill';
        if (pred === -1) {
            statusPill.classList.add('phishing');
            statusPill.textContent = 'Phishing';
            result.classList.add('phishing');
        } else if (pred === 1) {
            statusPill.classList.add('safe');
            statusPill.textContent = 'Safe';
            result.classList.add('safe');
        } else {
            statusPill.classList.add('unknown');
            statusPill.textContent = 'Unknown';
        }

        const reasons = Array.isArray(res.reasons) ? res.reasons : [];
        const exp = res.explanation || {};
        const top = Array.isArray(exp.top) ? exp.top : [];
        const explainItems = top.map(t => {
            const arrow = t.contrib > 0 ? '↑' : (t.contrib < 0 ? '↓' : '•');
            const amt = Math.abs(Number(t.contrib || 0)).toFixed(3);
            return `<li><strong>${t.name}</strong> ${arrow} <span class="muted">${amt}</span></li>`;
        });
        const reasonItems = reasons.map(r => `<li>${r}</li>`);
        const items = explainItems.concat(reasonItems);
        reasonsEl.innerHTML = items.length ? items.join('') : '<li class="muted">No explanation available</li>';

        try { chrome.runtime.sendMessage({ type: 'SET_BADGE', risk, pred }, () => {}); } catch (e) {}
    }

    async function startPhishingCheck() {
        // Reset to loading state
        loading.classList.remove('hidden');
        loading.classList.add('shown');
        result.classList.add('hidden');
        result.classList.remove('phishing', 'safe');
        statusPill.className = 'pill';
        statusPill.textContent = 'Checking…';
        reasonsEl.innerHTML = '';
        riskNum.textContent = '0%';
        gaugeNum.textContent = '0%';
        result.style.setProperty('--p', 0);

        const url = await getActiveTabUrl();
        urlText.textContent = url;
        const cfg = await getConfig();

        // 1) Try cache first
        try {
            chrome.runtime.sendMessage({ type: 'GET_CACHE', url, mode: cfg.mode }, (res) => {
                if (res && res.hit && res.data) {
                    renderResult(res.data, cfg);
                }
            });
        } catch (e) { /* ignore */ }

        // 2) Start full request and optionally a fast fallback if slow
        try {
            const fullPromise = callBackend(url);
            let replacedByFull = false;

            if (cfg.fastOnSlow) {
                setTimeout(async () => {
                    if (!replacedByFull) {
                        try {
                            const fastRes = await callBackendFast(url);
                            if (!replacedByFull) {
                                renderResult(fastRes, cfg);
                                chrome.runtime.sendMessage({ type: 'SET_CACHE', url, mode: cfg.mode, data: fastRes }, () => {});
                            }
                        } catch { /* ignore */ }
                    }
                }, 900);
            }

            const res = await fullPromise;
            replacedByFull = true;
            renderResult(res, cfg);
            chrome.runtime.sendMessage({ type: 'SET_CACHE', url, mode: cfg.mode, data: res }, () => {});
        } catch (err) {
            loading.classList.add('hidden');
            result.classList.remove('hidden');
            statusPill.classList.add('unknown');
            statusPill.textContent = 'Offline';
            riskNum.textContent = '—';
            gaugeNum.textContent = '—';
            result.style.setProperty('--p', 0);
            reasonsEl.innerHTML = '<li class="muted">Cannot reach backend. Start server on http://127.0.0.1:5000</li>';
            try { chrome.action.setBadgeText({ text: '' }); } catch (e) {}
        }
    }

    async function getPageLinksOrAnalyze(pageUrl) {
        return new Promise((resolve) => {
            chrome.runtime.sendMessage({ type: 'GET_PAGE_ANALYSIS', page: pageUrl }, async (res) => {
                if (res && res.hit && res.data) return resolve(res.data);
                // cache miss: ask background to analyze now
                chrome.runtime.sendMessage({ type: 'ANALYZE_PAGE', page: pageUrl }, (r2) => {
                    if (r2 && r2.ok && r2.data) return resolve(r2.data);
                    resolve(null);
                });
            });
        });
    }

    function renderPageScan(scan) {
        const box = document.getElementById('page-scan');
        const summary = document.getElementById('scan-summary');
        const itemsEl = document.getElementById('scan-items');
        const viewDetails = document.getElementById('view-details');
        if (!scan || typeof scan !== 'object') {
            box.style.display = 'none';
            if (viewDetails) viewDetails.style.display = 'none';
            return;
        }
        const total = scan.total_links || 0;
        const ext = scan.external_links || 0;
        const flagged = scan.flagged || 0;
        const bannerFlagged = scan.banner_flagged || 0;
        summary.textContent = `Terdeteksi ${total} link (eksternal ${ext}). Mencurigakan: ${flagged}, banner berbahaya: ${bannerFlagged}.`;
        const items = (scan.items || []).filter(x => x.prediction === -1).slice(0, 5);
        itemsEl.innerHTML = items.map(x => {
            const tag = x.banner ? '[Banner] ' : '';
            const risk = x.risk ?? 0;
            const host = (()=>{ try { return new URL(x.url).host; } catch { return x.url; } })();
            const llm = x.llm_reason ? `<div class="muted" style="margin-left:8px;">${x.llm_reason}</div>` : '';
            return `<li>${tag}<strong>${host}</strong> — ${risk}% <span class="muted">(${x.url})</span>${llm}</li>`;
        }).join('');
    const show = flagged > 0;
    box.style.display = show ? 'block' : 'none';
    if (viewDetails) viewDetails.style.display = show ? 'inline' : 'none';
    }

    // Hook into existing startPhishingCheck to also pull page analysis
    const _origStart = startPhishingCheck;
    startPhishingCheck = async function() {
        await _origStart();
        const page = await getActiveTabUrl();
        const scan = await getPageLinksOrAnalyze(page);
        renderPageScan(scan);
    };

    refreshButton.addEventListener('click', () => { startPhishingCheck(); });
    const openOpts = document.getElementById('open-options');
    if (openOpts) {
        openOpts.addEventListener('click', (e) => { e.preventDefault(); try { chrome.runtime.openOptionsPage(); } catch {} });
    }
    const vd = document.getElementById('view-details');
    if (vd) {
        vd.addEventListener('click', async (e) => {
            // Trigger a fresh analyze then let link open
            try {
                const page = await getActiveTabUrl();
                chrome.runtime.sendMessage({ type: 'ANALYZE_PAGE', page }, () => {});
            } catch {}
        });
    }
    startPhishingCheck();
})();
