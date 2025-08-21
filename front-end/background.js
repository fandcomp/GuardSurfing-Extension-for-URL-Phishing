// Background service worker (MV3)
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const cache = new Map(); // key -> { ts, data }
const pageScanCache = new Map(); // page_url -> { ts, data } or { ts, links }
const analyzeTimers = new Map(); // page_url -> timer id

async function loadCache() {
  try {
    chrome.storage?.session?.get({ cache: {} }, (res) => {
      const obj = res && res.cache ? res.cache : {};
      for (const [k, v] of Object.entries(obj)) {
        cache.set(k, v);
      }
    });
  } catch {}
}

async function saveCache() {
  try {
    const obj = Object.fromEntries(cache);
    chrome.storage?.session?.set({ cache: obj }, () => {});
  } catch {}
}

function makeKey(url, mode) {
  return `${mode || 'balanced'}|${url || ''}`;
}

function getCache(url, mode) {
  const key = makeKey(url, mode);
  const entry = cache.get(key);
  if (!entry) return { hit: false };
  const age = Date.now() - entry.ts;
  if (age > CACHE_TTL_MS) {
    cache.delete(key);
    return { hit: false };
  }
  return { hit: true, data: entry.data };
}

function setCache(url, mode, data) {
  const key = makeKey(url, mode);
  cache.set(key, { ts: Date.now(), data });
  saveCache();
}
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.active && tab.url) {
    // Nothing to do here for now; popup will query active tab directly.
  }
});

// Optional: respond to ping from popup to fetch current tab
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === 'GET_ACTIVE_TAB_URL') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const t = tabs && tabs[0];
      sendResponse({ url: t?.url || '' });
    });
    return true; // async
  }
  if (msg?.type === 'GET_CACHE') {
    const { url, mode } = msg;
    const res = getCache(url, mode);
    sendResponse(res);
    return true;
  }
  if (msg?.type === 'SET_CACHE') {
    const { url, mode, data } = msg;
    setCache(url, mode, data);
    sendResponse({ ok: true });
    return true;
  }
  if (msg?.type === 'SET_BADGE' && typeof msg.risk === 'number' && typeof msg.pred === 'number') {
    const text = `${Math.round(msg.risk)}`;
    const color = msg.pred === -1 ? '#dc2626' : '#0284c7';
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
    sendResponse({ ok: true });
    return true;
  }
  if (msg?.type === 'GET_PAGE_ANALYSIS') {
    const page = msg.page;
    const entry = pageScanCache.get(page);
    if (entry && entry.data && Date.now() - entry.ts < CACHE_TTL_MS) {
      sendResponse({ hit: true, data: entry.data });
      return true;
    }
    sendResponse({ hit: false });
    return true;
  }
  if (msg?.type === 'ANALYZE_PAGE') {
    (async () => {
      const page = msg.page;
      const entry = pageScanCache.get(page);
      let links = msg.links || (entry && entry.links) || [];
      if (!links || links.length === 0) {
        // Ask content script to provide links immediately
        try {
          const tabs = await new Promise((resolve) => chrome.tabs.query({}, resolve));
          const t = (tabs || []).find(tt => tt && tt.url === page);
          if (t && t.id) {
            await new Promise((resolve) => {
              chrome.tabs.sendMessage(t.id, { type: 'GET_LINKS' }, () => setTimeout(resolve, 400));
            });
            const after = pageScanCache.get(page);
            links = (after && after.links) || [];
          }
        } catch {}
      }
      const data = await analyzePageNow(page, links);
      sendResponse({ ok: !!data, data });
    })();
    return true;
  }
  if (msg?.type === 'PAGE_LINKS') {
    // content script sent links; aggregate by topPage when available (frames)
    const topPage = msg.topPage || msg.page;
    const entry = pageScanCache.get(topPage) || { ts: 0, links: [] };
    const merged = [...(entry.links || []), ...(msg.links || [])];
    // de-duplicate by URL
    const seen = new Set();
    const uniq = [];
    for (const it of merged) { if (it && it.url && !seen.has(it.url)) { seen.add(it.url); uniq.push(it); } }
    pageScanCache.set(topPage, { ts: Date.now(), links: uniq });
    const old = analyzeTimers.get(topPage);
    if (old) clearTimeout(old);
    const t = setTimeout(() => {
      analyzePageNow(topPage, uniq);
      analyzeTimers.delete(topPage);
    }, 1200);
    analyzeTimers.set(topPage, t);
    sendResponse({ ok: true });
    return true;
  }
});

// Initialize persisted cache
loadCache();

async function getOptions() {
  return new Promise((resolve) => chrome.storage.sync.get({ apiBase: '', mode: 'balanced', fastOnSlow: true, allowlist: [], llmEnabled: false, llmModel: 'llama3.1:8b', llmOnlyExternal: false, llmMax: 10, kidsMode: false }, resolve));
}

async function analyzePageNow(page, links) {
  const cfg = await getOptions();
  // Allowlist check
  try {
    const host = new URL(page).host;
    const allow = (cfg.allowlist || []).some(d => host === d || host.endsWith('.' + d));
    if (allow) {
      const data = { page, total_links: links?.length || 0, external_links: 0, analyzed: 0, flagged: 0, banner_flagged: 0, items: [] };
      pageScanCache.set(page, { ts: Date.now(), data });
      return data;
    }
  } catch {}
  const base = cfg.apiBase && cfg.apiBase.trim() ? cfg.apiBase.trim() : (self.API_BASE || 'http://127.0.0.1:5000');
  const API = base.replace(/\/$/, '');
  try {
    const res = await fetch(`${API}/analyze_page`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ page_url: page, links, mode: cfg.mode, fast: true, top_k_full: 3, llm: !!cfg.llmEnabled, llm_max: cfg.llmMax || 10, llm_only_external: !!cfg.llmOnlyExternal, kids_mode: !!cfg.kidsMode })
    });
    const data = await res.json();
    pageScanCache.set(page, { ts: Date.now(), data });
    // Push to content scripts in that page to highlight/block
    try {
      chrome.tabs.query({}, (tabs) => {
        for (const t of tabs) {
          if (t && t.url === page) {
            chrome.tabs.sendMessage(t.id, { type: 'PAGE_ANALYSIS_RESULT', page, data });
          }
        }
      });
    } catch {}
    // If flagged banners exist, notify
    if (data && data.banner_flagged > 0) {
      const count = data.banner_flagged;
      const total = data.flagged;
      chrome.notifications.create(`phish-banners-${Date.now()}`, {
        type: 'basic',
        iconUrl: 'logo.png',
        title: 'Peringatan iklan berbahaya',
        message: `${count} banner iklan berisiko dari ${total} link mencurigakan di halaman ini.`,
        priority: 1
      });
    }
    return data;
  } catch (e) {
    return null;
  }
}
