// Content script: scans the page for external links and common ad/banner links
(function(){
  let settings = { highlightRisky: true, blockRisky: false };
  let lastAnalysis = null;
  let tooltipEl = null;

  chrome.storage?.sync?.get({ highlightRisky: true, blockRisky: false }, (cfg) => { settings = cfg; });
  chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area === 'sync') {
      if (changes.highlightRisky) settings.highlightRisky = !!changes.highlightRisky.newValue;
      if (changes.blockRisky) settings.blockRisky = !!changes.blockRisky.newValue;
      applyHighlights();
    }
  });
  function trimTxt(s, n=180) { return (s||'').replace(/\s+/g,' ').trim().slice(0,n); }
  function absUrl(u) { try { return new URL(u, location.href).href; } catch { return ''; } }
  function isHttp(u) { return typeof u === 'string' && (u.startsWith('http://') || u.startsWith('https://')); }
  function extractUrlFromOnclick(code) {
    if (!code || typeof code !== 'string') return '';
    // Common patterns: window.open('...'), location.href='...', location.assign("..."), document.location="..."
    const patterns = [
      /window\.open\((['"])(https?:\/\/[^'"\)]+)\1/,
      /(?:location\.href|document\.location|window\.location|top\.location)\s*=\s*(['"])(https?:\/\/[^'";]+)\1/,
      /location\.(?:assign|replace)\((['"])(https?:\/\/[^'"\)]+)\1/,
    ];
    for (const re of patterns) {
      const m = code.match(re);
      if (m && m[2]) return m[2];
    }
    // URLs present directly in the code
    const m2 = code.match(/https?:\/\/[^'"\s)]+/);
    return m2 ? m2[0] : '';
  }
  function extractUrlFromDataset(el) {
    if (!el || !el.dataset) return '';
    const keys = ['href','url','link','destination','redirect','target','out','to','u'];
    for (const k of keys) {
      const v = el.dataset[k];
      if (v && isHttp(v)) return v;
      if (v && /^\/?\//.test(v)) return location.protocol + v; // protocol-relative
      if (v) {
        const a = absUrl(v);
        if (isHttp(a)) return a;
      }
    }
    return '';
  }
  function collectLinks() {
    const anchors = Array.from(document.querySelectorAll('a[href]'));
  const imgs = Array.from(document.querySelectorAll('a[href] img, .banner a[href] img, img[usemap]'));
  const mapAreas = Array.from(document.querySelectorAll('map area[href]'));
  const frames = Array.from(document.querySelectorAll('iframe[src], frame[src]'));
  const banners = Array.from(document.querySelectorAll('[onclick], [data-href], [data-url], [data-link], [data-destination], [data-redirect], [role="banner"], .banner, [class*="ad"], [id*="banner"]'));
  const forms = Array.from(document.querySelectorAll('form[action]'));

    const links = [];
    const origin = location.host;

    // Anchor links
    for (const a of anchors) {
      const href = a.getAttribute('href');
      let url = '';
      try { url = new URL(href, location.href).href; } catch { continue; }
      const isHttp = url.startsWith('http://') || url.startsWith('https://');
      if (!isHttp) continue;
      const isExternal = (()=>{ try { return new URL(url).host !== origin; } catch { return false; } })();
      const cls = a.getAttribute('class')||''; const aid = a.getAttribute('id')||'';
      let bannerish = /banner|ads?|sponsor|promo/i.test(cls) || /ads?|sponsor|promo/i.test(aid);
      const text = trimTxt(a.textContent, 160);
      const title = trimTxt(a.getAttribute('title')||'', 120);
      const hasImg = !!a.querySelector('img');
      let host = '';
      try { host = new URL(url).host; } catch {}
      const shortener = /(?:bit\.ly|goo\.gl|t\.co|tinyurl|is\.gd|ow\.ly|adf\.ly|j\.mp|rb\.gy|cutt\.ly|lnkd\.in|t\.ly|rebrand\.ly|linktr\.ee|s\.id)/i.test(host) || /(?:t\.ly|rebrand\.ly)/i.test(url);
      // Heuristic: external + (explicit banner classes OR has image OR very short text OR known shortener)
      if (isExternal && (bannerish || hasImg || (text && text.length < 4) || shortener)) bannerish = true;
      // context: nearest block ancestor text
      let ctx = '';
      try {
        let node = a;
        for (let i=0;i<4 && node && node.parentElement;i++) {
          node = node.parentElement;
          const style = getComputedStyle(node);
          if (['block','grid','flex','table'].includes(style.display)) { ctx = trimTxt(node.innerText, 240); break; }
        }
      } catch {}
  links.push({ url, tag: 'a', banner: !!bannerish, external: isExternal, shortener: !!shortener, text, title, context: ctx });
    }

    // Image maps (area tags)
    for (const area of mapAreas) {
      const href = area.getAttribute('href');
      const url = absUrl(href);
      if (!isHttp(url)) continue;
      const isExternal = (()=>{ try { return new URL(url).host !== origin; } catch { return false; } })();
      const title = trimTxt(area.getAttribute('alt')||area.getAttribute('title')||'', 120);
      links.push({ url, tag: 'area', banner: true, external: isExternal, text: '', title, context: '' });
    }

    // iframe sources (often used for ads)
    for (const f of frames) {
      const src = f.getAttribute('src');
      let url = '';
      try { url = new URL(src, location.href).href; } catch { continue; }
      const isHttp = url.startsWith('http://') || url.startsWith('https://');
      if (!isHttp) continue;
      const title = trimTxt(f.getAttribute('title')||f.getAttribute('aria-label')||'', 120);
      links.push({ url, tag: 'iframe', banner: true, external: true, text: '', title, context: '' });
    }

    // Banner-like elements with onclick/data-* that navigate
    for (const el of banners) {
      // Skip if it contains a direct anchor (already collected)
      if (el.querySelector && el.querySelector('a[href]')) continue;
      let url = '';
      const onclick = el.getAttribute && el.getAttribute('onclick');
      if (onclick) url = extractUrlFromOnclick(String(onclick));
      if (!isHttp(url)) url = extractUrlFromDataset(el);
      if (!isHttp(url)) continue;
      url = absUrl(url);
      if (!isHttp(url)) continue;
      const isExternal = (()=>{ try { return new URL(url).host !== origin; } catch { return false; } })();
      const title = trimTxt(el.getAttribute('title')||el.getAttribute('aria-label')||'', 120);
      // Some text from within element
      const text = trimTxt(el.innerText || '', 160);
      links.push({ url, tag: el.tagName.toLowerCase(), banner: true, external: isExternal, text, title, context: text });
    }

    // Forms (submit targets). Useful to analyze exfiltration targets.
    for (const f of forms) {
      const act = f.getAttribute('action');
      const method = (f.getAttribute('method') || 'get').toLowerCase();
      const url = absUrl(act);
      if (!isHttp(url)) continue;
      const isExternal = (()=>{ try { return new URL(url).host !== origin; } catch { return false; } })();
      // Detect presence of sensitive inputs
      const sensitive = !!f.querySelector('input[type="password"], input[name*="pass" i], input[name*="card" i], input[name*="otp" i], input[name*="token" i], input[type="email"], input[name*="ssn" i]');
      const title = (f.getAttribute('name') || f.getAttribute('id') || '').toString().slice(0,120);
      const text = sensitive ? 'form:sensitive' : 'form';
      links.push({ url, tag: 'form', banner: false, external: isExternal, text, title, context: method });
    }

    // image map / banner images linked by parent anchors are covered via anchors
    return links;
  }

  function dedupe(arr) {
    const seen = new Set();
    const out = [];
    for (const it of arr) {
      if (!it || !it.url) continue;
      if (seen.has(it.url)) continue;
      seen.add(it.url);
      out.push(it);
    }
    return out;
  }

  function sendLinks() {
    try {
      const links = dedupe(collectLinks());
      chrome.runtime.sendMessage({ type: 'PAGE_LINKS', page: location.href, links });
    } catch {}
  }

  function applyHighlights() {
    if (!settings.highlightRisky || !lastAnalysis) return;
    const risky = new Set((lastAnalysis.items || []).filter(x => x.prediction === -1).map(x => x.url));
    const sel = 'a[href], iframe[src], frame[src], map area[href], [onclick], [data-href], [data-url], [data-link], [data-destination], [data-redirect]';
    document.querySelectorAll(sel).forEach(el => {
      let url = el.getAttribute('href') || el.getAttribute('src');
      if (!url) {
        const oc = el.getAttribute && el.getAttribute('onclick');
        if (oc) url = extractUrlFromOnclick(String(oc));
        if (!url && el.dataset) url = extractUrlFromDataset(el);
      }
      try { url = new URL(url, location.href).href; } catch { return; }
      if (risky.has(url)) {
        el.style.outline = '2px solid #dc2626';
        el.style.outlineOffset = '2px';
        // Tooltip hover
        el.addEventListener('mouseenter', (e) => showTooltipFor(url, el, e));
        el.addEventListener('mouseleave', hideTooltip);
      }
    });
  }

  function ensureTooltip() {
    if (tooltipEl) return tooltipEl;
    const tip = document.createElement('div');
    tip.style.position = 'fixed';
    tip.style.zIndex = '2147483647';
    tip.style.background = 'rgba(17,24,39,0.98)';
    tip.style.color = '#fff';
    tip.style.padding = '8px 10px';
    tip.style.borderRadius = '8px';
    tip.style.boxShadow = '0 6px 18px rgba(0,0,0,0.25)';
    tip.style.font = '12px/1.35 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell';
    tip.style.maxWidth = '320px';
    tip.style.pointerEvents = 'none';
    tip.style.display = 'none';
    document.documentElement.appendChild(tip);
    tooltipEl = tip;
    return tip;
  }

  function showTooltipFor(url, el, evt) {
    try {
      const tip = ensureTooltip();
      const item = (lastAnalysis.items || []).find(x => x.url === url);
      if (!item) return;
      const reasons = (item.reasons || []).slice(0, 3).join(' • ');
      const risk = item.risk != null ? `Risk ${item.risk}%` : '';
      const llm = item.llm_reason ? ` — ${item.llm_reason}` : '';
      const cat = item.category ? ` [${item.category}]` : '';
      tip.textContent = `${risk}${cat}${reasons ? ' — ' + reasons : ''}${llm}`.trim();
      positionTooltip(evt.clientX, evt.clientY);
      tip.style.display = 'block';
      // track mouse move while inside
      const move = (e) => positionTooltip(e.clientX, e.clientY);
      el.addEventListener('mousemove', move);
      el._gs_move = move;
    } catch {}
  }

  function positionTooltip(x, y) {
    const tip = ensureTooltip();
    const margin = 12;
    const vw = window.innerWidth; const vh = window.innerHeight;
    let left = x + margin; let top = y + margin;
    tip.style.display = 'block';
    const rect = tip.getBoundingClientRect();
    if (left + rect.width > vw - 8) left = x - rect.width - margin;
    if (top + rect.height > vh - 8) top = y - rect.height - margin;
    tip.style.left = `${Math.max(8, left)}px`;
    tip.style.top = `${Math.max(8, top)}px`;
  }

  function hideTooltip(e) {
    try {
      const tip = ensureTooltip();
      tip.style.display = 'none';
      const el = e && e.target;
      if (el && el._gs_move) {
        el.removeEventListener('mousemove', el._gs_move);
        delete el._gs_move;
      }
    } catch {}
  }

  function installClickBlocker() {
    if (!settings.blockRisky) return;
    document.addEventListener('click', (e) => {
      const a = e.target.closest('a[href], area[href]');
      if (!a || !lastAnalysis) return;
      let url = a.getAttribute('href');
      try { url = new URL(url, location.href).href; } catch { return; }
      const item = (lastAnalysis.items || []).find(x => x.url === url);
      if (item && item.prediction === -1) {
        e.preventDefault();
        const proceed = confirm('Link ini terdeteksi berisiko phishing. Tetap lanjut?');
        if (proceed) window.open(url, '_blank');
      }
    }, true);
  }

  // Form Guard: warn on external sensitive form submissions
  document.addEventListener('submit', (e) => {
    try {
      const f = e.target.closest('form');
      if (!f || !lastAnalysis) return;
      const act = f.getAttribute('action');
      let url = absUrl(act);
      if (!isHttp(url)) return;
      const item = (lastAnalysis.items || []).find(x => x.url === url) || {};
      const sensitive = !!f.querySelector('input[type="password"], input[name*="pass" i], input[name*="card" i], input[name*="otp" i], input[name*="token" i], input[type="email"], input[name*="ssn" i]');
      const isExternal = (()=>{ try { return new URL(url).host !== location.host; } catch { return false; } })();
      if (sensitive && (item.prediction === -1 || (item.risk||0) >= 35 || isExternal)) {
        e.preventDefault();
        const proceed = confirm('Form ini tampak sensitif dan akan dikirim ke domain eksternal. Lanjutkan submit?');
        if (proceed) f.submit();
      }
    } catch {}
  }, true);

  // Initial and on dynamic changes
  sendLinks();
  const obs = new MutationObserver(() => {
    // throttle via microtask
    clearTimeout(sendLinks._t);
    sendLinks._t = setTimeout(sendLinks, 500);
  });
  obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true });

  // Receive latest page analysis to highlight/block
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'PAGE_ANALYSIS_RESULT' && msg.page === location.href) {
      lastAnalysis = msg.data;
      applyHighlights();
      installClickBlocker();
    }
    if (msg && msg.type === 'GET_LINKS') {
      try {
        const links = dedupe(collectLinks());
        chrome.runtime.sendMessage({ type: 'PAGE_LINKS', page: location.href, links });
        chrome.runtime.sendMessage({ type: 'PAGE_LINKS_ACK', page: location.href });
      } catch {}
    }
  });
})();
