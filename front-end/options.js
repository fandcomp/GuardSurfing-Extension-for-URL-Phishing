(function(){
  const apiBase = document.getElementById('apiBase');
  const mode = document.getElementById('mode');
  const saveBtn = document.getElementById('save');
  const fastOnSlow = document.getElementById('fastOnSlow');
  const resetBtn = document.getElementById('reset');
  const checkBtn = document.getElementById('checkBackend');
  const backendInfo = document.getElementById('backendInfo');
  const highlightRisky = document.getElementById('highlightRisky');
  const blockRisky = document.getElementById('blockRisky');
  const allowlist = document.getElementById('allowlist');
  const llmEnabled = document.getElementById('llmEnabled');
  const llmModel = document.getElementById('llmModel');
  const llmOnlyExternal = document.getElementById('llmOnlyExternal');
  const llmMax = document.getElementById('llmMax');
  const kidsMode = document.getElementById('kidsMode');

  function load() {
  chrome.storage.sync.get({ apiBase: '', mode: 'balanced', fastOnSlow: true, highlightRisky: true, blockRisky: false, allowlist: [], llmEnabled: false, llmModel: 'llama3.1:8b', llmOnlyExternal: false, llmMax: 10, kidsMode: false }, (cfg) => {
      apiBase.value = cfg.apiBase || '';
      mode.value = cfg.mode || 'balanced';
      fastOnSlow.checked = !!cfg.fastOnSlow;
      highlightRisky.checked = !!cfg.highlightRisky;
      blockRisky.checked = !!cfg.blockRisky;
      allowlist.value = (cfg.allowlist || []).join('\n');
      llmEnabled.checked = !!cfg.llmEnabled;
      llmModel.value = cfg.llmModel || 'llama3.1:8b';
  llmOnlyExternal.checked = !!cfg.llmOnlyExternal;
  llmMax.value = cfg.llmMax ?? 10;
      kidsMode.checked = !!cfg.kidsMode;
    });
  }

  function save() {
    const value = apiBase.value.trim();
  const domains = allowlist.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const cfg = { apiBase: value, mode: mode.value, fastOnSlow: !!fastOnSlow.checked, highlightRisky: !!highlightRisky.checked, blockRisky: !!blockRisky.checked, allowlist: domains, llmEnabled: !!llmEnabled.checked, llmModel: llmModel.value.trim() || 'llama3.1:8b', llmOnlyExternal: !!llmOnlyExternal.checked, llmMax: Math.max(0, parseInt(llmMax.value || '10', 10)), kidsMode: !!kidsMode.checked };
    chrome.storage.sync.set(cfg, () => {
      saveBtn.textContent = 'Saved';
      setTimeout(() => saveBtn.textContent = 'Save', 1200);
    });
  }

  function reset() {
    chrome.storage.sync.clear(() => {
      apiBase.value = '';
      mode.value = 'balanced';
  fastOnSlow.checked = true;
  highlightRisky.checked = true;
  blockRisky.checked = false;
  allowlist.value = '';
  llmEnabled.checked = false;
  llmModel.value = 'llama3.1:8b';
    kidsMode.checked = false;
    });
  }

  saveBtn.addEventListener('click', save);
  resetBtn.addEventListener('click', reset);
  checkBtn.addEventListener('click', async () => {
    const base = apiBase.value.trim() || 'http://127.0.0.1:5000';
    const API = base.replace(/\/$/, '');
    backendInfo.textContent = 'Checking…';
    try {
      const r = await fetch(`${API}/config`, { method: 'GET' });
      const j = await r.json();
      backendInfo.textContent = `Model: ${j.model || 'n/a'} • LLM: ${j.use_llm ? 'on' : 'off'} (${j.llm_model || '-'}) • Features: ${Array.isArray(j.features) ? j.features.length : '?'} • Timeout: ${j.llm_timeout || '?'}s`;
    } catch (e) {
      backendInfo.textContent = 'Backend not reachable or /config missing.';
    }
  });
  load();
})();
