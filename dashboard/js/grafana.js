const GrafanaEmbed = (() => {
  let _isOnline = false;
  let _currentPanel = 'overview';
  let _pollTimer = null;
  let _retryTimer = null;
  function _buildGrafanaUrl(panelName) {
    const base = CONFIG.GRAFANA_URL;
    const uid  = CONFIG.GRAFANA_DASHBOARD_UID;
    const panelId = CONFIG.GRAFANA_PANELS[panelName];
    if (panelName === 'logs') {
      return `${base}/explore?orgId=1&left={"datasource":"loki","queries":[{"expr":"{container=~"proxy|waf_service|webapp"}"}],"range":{"from":"now-15m","to":"now"}}`;
    }
    if (panelId === null) {
      return `${base}/d/${uid}?orgId=1&kiosk=tv&refresh=5s&theme=dark`;
    }
    return `${base}/d-solo/${uid}?orgId=1&panelId=${panelId}&refresh=5s&theme=dark&kiosk`;
  }
  function switchPanel(panelName) {
    _currentPanel = panelName;
    document.querySelectorAll('.grafana-tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.panel === panelName);
    });
    if (!_isOnline) return;
    const frame = document.getElementById('grafana-frame');
    if (frame) {
      _showLoading();
      frame.style.display = 'none';
      frame.src = _buildGrafanaUrl(panelName);
      frame.onload = () => {
        _hideLoading();
        frame.style.display = 'block';
      };
    }
  }
  function init() {
    _checkHealth();
  }
  async function _checkHealth() {
    const grafanaDot  = document.getElementById('grafana-dot');
    const statusText  = document.getElementById('grafana-status-text');
    if (grafanaDot)  grafanaDot.className  = 'grafana-dot loading';
    if (statusText)  statusText.textContent = 'Connecting…';
    try {
      const resp = await fetch(CONFIG.HEALTH.GRAFANA, {
        method: 'GET',
        mode: 'no-cors',         
        signal: AbortSignal.timeout(4000),
      });
      _setOnline();
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
    const frame = document.getElementById('grafana-frame');
    if (frame) {
      frame.src = _buildGrafanaUrl(_currentPanel);
      frame.style.display = 'block';
      frame.onload = () => _hideLoading();
    }
    _startPolling();
  }
  function _setOffline() {
    _isOnline = false;
    const grafanaDot = document.getElementById('grafana-dot');
    const statusText = document.getElementById('grafana-status-text');
    if (grafanaDot) grafanaDot.className = 'grafana-dot offline';
    if (statusText) statusText.textContent = 'Offline';
    document.getElementById('grafana-loading').style.display = 'none';
    document.getElementById('grafana-offline').style.display = 'flex';
    const frame = document.getElementById('grafana-frame');
    if (frame) frame.style.display = 'none';
    clearTimeout(_retryTimer);
    _retryTimer = setTimeout(_checkHealth, 15000);
  }
  function retry() {
    clearTimeout(_retryTimer);
    _showLoading();
    document.getElementById('grafana-offline').style.display = 'none';
    _checkHealth();
  }
  function _startPolling() {
    _pollStats();
    clearInterval(_pollTimer);
    _pollTimer = setInterval(_pollStats, CONFIG.PROM_POLL_INTERVAL_MS);
  }
  async function _pollStats() {
    await Promise.allSettled([
      _queryProm(CONFIG.PROM_QUERIES.rps,         _updateRPS),
      _queryProm(CONFIG.PROM_QUERIES.blocked,      _updateBlocked),
      _queryProm(CONFIG.PROM_QUERIES.latency_p95,  _updateLatency),
      _queryProm(CONFIG.PROM_QUERIES.mtls_ok,      _updateMtlsOk),
    ]);
  }
  async function _queryProm(query, callback) {
    try {
      const url = `${CONFIG.PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(query)}`;
      const resp = await fetch(url, { signal: AbortSignal.timeout(4000) });
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
  function _showLoading() {
    const el = document.getElementById('grafana-loading');
    if (el) el.style.display = 'flex';
  }
  function _hideLoading() {
    const el = document.getElementById('grafana-loading');
    if (el) el.style.display = 'none';
  }
  return { init, switchPanel, retry };
})();