(async function(){
  async function getActiveTabUrl() {
    return new Promise((resolve) => chrome.tabs.query({ active:true, currentWindow:true }, tabs => resolve((tabs && tabs[0] && tabs[0].url) || '')));
  }
  async function getAnalysis(page) {
    return new Promise((resolve) => chrome.runtime.sendMessage({ type:'GET_PAGE_ANALYSIS', page }, res => {
      if (res && res.hit && res.data) return resolve(res.data);
      chrome.runtime.sendMessage({ type:'ANALYZE_PAGE', page }, r2 => resolve(r2 && r2.data));
    }));
  }
  function toCSV(rows) {
    const esc = (s) => '"' + String(s).replace(/"/g,'""') + '"';
    const header = ['risk','type','host','url','llm_reason'];
    const lines = [header.join(',')];
    for (const r of rows) lines.push([r.risk, r.type, r.host, r.url, r.llm_reason || ''].map(esc).join(','));
    return lines.join('\n');
  }
  async function render() {
    const page = await getActiveTabUrl();
    const pageEl = document.getElementById('page');
    const statusEl = document.getElementById('status');
    const tableBody = document.querySelector('#table tbody');
    pageEl.textContent = page;
    const scan = await getAnalysis(page);
    const rows = (scan?.items || []).filter(x => x.prediction === -1).map(x => ({
      risk: x.risk ?? 0,
      type: x.banner ? (x.shortener ? 'Banner/Shortener' : 'Banner') : (x.external ? 'External' : 'Internal'),
      host: (()=>{ try { return new URL(x.url).host; } catch { return x.url; } })(),
      url: x.url,
      llm_reason: x.llm_reason || ''
    })).sort((a,b)=> b.risk - a.risk);
    tableBody.innerHTML = rows.map((r,i) => `<tr>
      <td><span class="pill red">${r.risk}%</span></td>
      <td>${r.type}</td>
      <td>${r.host}</td>
      <td>
        <a href="${r.url}" target="_blank" rel="noreferrer">${r.url}</a>
      </td>
      <td class="muted">${r.llm_reason}</td>
    </tr>`).join('');
    statusEl.textContent = `${rows.length} flagged links`;

    document.getElementById('copy').onclick = async () => {
      const text = rows.map(r => `${r.risk}%\t${r.type}\t${r.host}\t${r.url}\t${r.llm_reason}`).join('\n');
      try { await navigator.clipboard.writeText(text); statusEl.textContent = 'Copied'; setTimeout(()=>statusEl.textContent='', 1200);} catch { statusEl.textContent = 'Copy failed'; }
    };
    document.getElementById('export').onclick = () => {
      const csv = toCSV(rows);
      const blob = new Blob([csv], { type: 'text/csv' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'guard-surfing-flagged.csv';
      a.click();
    };
    document.getElementById('refresh').onclick = render;
  }
  render();
})();
