const BackendClient = (() => {
  let _isOnline = false;
  let _pollTimer = null;
  let _retryTimer = null;
  let _lastLogTime = Date.now() - 5 * 60 * 1000; 
  function init() {
    _checkHealth();
  }
  async function _checkHealth() {
    const grafanaDot = document.getElementById('grafana-dot');
    const statusText = document.getElementById('grafana-status-text');
    if (grafanaDot) grafanaDot.className = 'grafana-dot loading';
    if (statusText) statusText.textContent = 'Connecting…';
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const resp = await fetch(CONFIG.HEALTH.PROMETHEUS, {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (resp.ok) {
        _setOnline();
      } else {
        _setOffline();
      }
    } catch (err) {
      _setOffline();
    }
  }
  function _setOnline() {
    _isOnline = true;
    const grafanaDot = document.getElementById('grafana-dot');
    const statusText = document.getElementById('grafana-status-text');
    if (grafanaDot) grafanaDot.className = 'grafana-dot online';
    if (statusText) statusText.textContent = 'Connected';
    document.getElementById('grafana-loading').style.display = 'none';
    document.getElementById('grafana-offline').style.display = 'none';
    document.getElementById('native-logs').style.display = 'block';
    _startPolling();
  }
  function _setOffline() {
    _isOnline = false;
    const grafanaDot = document.getElementById('grafana-dot');
    const statusText = document.getElementById('grafana-status-text');
    if (grafanaDot) grafanaDot.className = 'grafana-dot offline';
    if (statusText) statusText.textContent = 'Offline';
    document.getElementById('grafana-loading').style.display = 'none';
    document.getElementById('native-logs').style.display = 'none';
    document.getElementById('grafana-offline').style.display = 'flex';
    clearTimeout(_retryTimer);
    _retryTimer = setTimeout(_checkHealth, 15000);
  }
  function retry() {
    clearTimeout(_retryTimer);
    document.getElementById('grafana-loading').style.display = 'flex';
    document.getElementById('grafana-offline').style.display = 'none';
    _checkHealth();
  }
  function _startPolling() {
    _pollStats();
    _pollLogs();
    clearInterval(_pollTimer);
    _pollTimer = setInterval(() => {
      _pollStats();
      _pollLogs();
    }, 5000); 
  }
  async function _pollStats() {
    await Promise.allSettled([
      _queryProm(CONFIG.PROM_QUERIES.rps, _updateRPS),
      _queryProm(CONFIG.PROM_QUERIES.blocked, _updateBlocked),
      _queryProm(CONFIG.PROM_QUERIES.latency_p95, _updateLatency),
      _queryProm(CONFIG.PROM_QUERIES.mtls_ok, _updateMtlsOk),
    ]);
  }
  async function _queryProm(query, callback) {
    try {
      const url = `${CONFIG.PROMETHEUS_URL}/api/metrics?query=${encodeURIComponent(query)}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const resp = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (!resp.ok) return;
      const data = await resp.json();
      const results = data?.data?.result;
      if (results && results.length > 0) {
        const value = parseFloat(results[0].value[1]);
        callback(value);
      }
    } catch (_) {
    }
  }
  function _updateStatEl(id, text) {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.textContent === text) return;
    el.textContent = text;
    el.classList.add('updating');
    el.addEventListener('animationend', () => el.classList.remove('updating'), { once: true });
  }
  function _updateRPS(v) {
    _updateStatEl('stat-rps-value', isNaN(v) ? '—' : `${v.toFixed(1)}/s`);
  }
  function _updateBlocked(v) {
    _updateStatEl('stat-blocked-value', isNaN(v) ? '—' : v.toFixed(0));
  }
  function _updateLatency(v) {
    if (isNaN(v)) { _updateStatEl('stat-latency-value', '—'); return; }
    const ms = v * 1000;
    _updateStatEl('stat-latency-value', ms < 1 ? `${(ms * 1000).toFixed(0)}µs` : `${ms.toFixed(1)}ms`);
  }
  function _updateMtlsOk(v) {
    _updateStatEl('stat-uptime-value', isNaN(v) ? '—' : v.toFixed(0));
  }
  async function _pollLogs() {
    try {
      const lokiUrl = `${CONFIG.LOKI_URL}/api/logs`;
      const query = '{container=~"proxy|waf_service|webapp"}';
      const params = new URLSearchParams({
        query: query,
        start: (_lastLogTime * 1000000).toString(), 
        end: (Date.now() * 1000000).toString(),
        limit: 50,
        direction: 'forward'
      });
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const resp = await fetch(`${lokiUrl}?${params.toString()}`, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (!resp.ok) return;
      const data = await resp.json();
      const streams = data?.data?.result || [];
      let allLogs = [];
      streams.forEach(stream => {
        const container = stream.stream.container;
        stream.values.forEach(val => {
          allLogs.push({
            ts: parseInt(val[0]) / 1000000, 
            container: container,
            line: val[1]
          });
        });
      });
      allLogs.sort((a, b) => a.ts - b.ts);
      if (allLogs.length > 0) {
        _lastLogTime = allLogs[allLogs.length - 1].ts + 1; 
        _renderLogs(allLogs);
      }
    } catch (e) {
    }
  }
  function _renderLogs(logs) {
    const container = document.getElementById('native-logs');
    if (!container) return;
    while (container.childElementCount > 200) {
      container.removeChild(container.firstChild);
    }
    logs.forEach(log => {
      const el = document.createElement('div');
      el.className = 'log-line';
      const tsStr = new Date(log.ts).toISOString().split('T')[1].slice(0, -1);
      const tsEl = document.createElement('span');
      tsEl.className = 'log-timestamp';
      tsEl.textContent = tsStr;
      const sourceEl = document.createElement('span');
      let shortContainer = log.container;
      if (shortContainer === 'waf_service') shortContainer = 'waf';
      sourceEl.className = `log-source ${shortContainer}`;
      sourceEl.textContent = shortContainer.toUpperCase();
      const textNode = document.createTextNode(' ' + log.line.trim());
      el.appendChild(tsEl);
      el.appendChild(sourceEl);
      el.appendChild(textNode);
      container.appendChild(el);
    });
    container.scrollTop = container.scrollHeight;
  }
  return { init, retry };
})();