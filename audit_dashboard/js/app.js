const AUDIT_API = window.AUDIT_API_URL || 'http://localhost:8000';
const PAGE_SIZE  = 50;
const AUTO_REFRESH_MS = 5000;

const state = {
  page: 0,
  total: 0,
  filters: { service: '', result: '', search: '' },
  logs: [],
  autoRefresh: true,
  refreshTimer: null,
  connected: false,
};

const el = {};

function init() {
  el.connDot     = document.getElementById('conn-dot');
  el.connText    = document.getElementById('conn-text');
  el.totalStat   = document.getElementById('stat-total');
  el.successStat = document.getElementById('stat-success');
  el.rejectedStat= document.getElementById('stat-rejected');
  el.latencyStat = document.getElementById('stat-latency');
  el.tbody       = document.getElementById('log-tbody');
  el.tableMetaTxt= document.getElementById('table-meta');
  el.filterService= document.getElementById('filter-service');
  el.filterResult = document.getElementById('filter-result');
  el.filterSearch = document.getElementById('filter-search');
  el.toggleRefresh= document.getElementById('toggle-refresh');
  el.btnApply    = document.getElementById('btn-apply');
  el.btnReset    = document.getElementById('btn-reset-filter');
  el.paginationEl= document.getElementById('pagination');
  el.modalOverlay= document.getElementById('modal-overlay');
  el.modalBadge  = document.getElementById('modal-badge');
  el.modalId     = document.getElementById('modal-id');
  el.modalTs     = document.getElementById('modal-ts');
  el.modalReqId  = document.getElementById('modal-req-id');
  el.modalStep   = document.getElementById('modal-step');
  el.modalSvc    = document.getElementById('modal-svc');
  el.modalSubj   = document.getElementById('modal-subj');
  el.modalResult = document.getElementById('modal-result');
  el.modalReason = document.getElementById('modal-reason');
  el.modalLat    = document.getElementById('modal-lat');
  el.btnClose    = document.getElementById('btn-close-modal');

  // Event listeners
  el.btnApply.addEventListener('click', () => { state.page = 0; applyFilters(); fetchLogs(); });
  el.btnReset.addEventListener('click', resetFilters);
  el.filterSearch.addEventListener('keydown', e => { if (e.key === 'Enter') { state.page = 0; applyFilters(); fetchLogs(); } });
  el.toggleRefresh.addEventListener('change', toggleAutoRefresh);
  el.btnClose.addEventListener('click', closeModal);
  el.modalOverlay.addEventListener('click', e => { if (e.target === el.modalOverlay) closeModal(); });

  // Start
  fetchStats();
  fetchLogs();
  scheduleRefresh();
}

function applyFilters() {
  state.filters.service = el.filterService.value;
  state.filters.result  = el.filterResult.value;
  state.filters.search  = el.filterSearch.value.trim();
}

function resetFilters() {
  el.filterService.value = '';
  el.filterResult.value  = '';
  el.filterSearch.value  = '';
  state.filters = { service: '', result: '', search: '' };
  state.page = 0;
  fetchStats();
  fetchLogs();
}


function scheduleRefresh() {
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  if (!state.autoRefresh) return;
  state.refreshTimer = setInterval(() => {
    fetchStats();
    fetchLogs(true); // silent = no loading spinner
  }, AUTO_REFRESH_MS);
}

function toggleAutoRefresh() {
  state.autoRefresh = el.toggleRefresh.checked;
  scheduleRefresh();
  showToast(state.autoRefresh ? 'Auto-refresh ON (5s)' : 'Auto-refresh paused');
}


async function fetchStats() {
  try {
    const res = await fetch(`${AUDIT_API}/logs/stats`);
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    setConnected(true);
    el.totalStat.textContent    = data.total ?? '—';
    el.successStat.textContent  = data.success_count ?? '—';
    const totalRejected = (data.rejected_count || 0) + (data.failed_count || 0);
    el.rejectedStat.textContent = totalRejected || '0';
    const lat = data.avg_latency_ms != null ? `${data.avg_latency_ms} ms` : '—';
    el.latencyStat.textContent  = lat;
  } catch {
    setConnected(false);
  }
}

async function fetchLogs(silent = false) {
  if (!silent) renderLoading();

  const params = new URLSearchParams({
    limit:  PAGE_SIZE,
    offset: state.page * PAGE_SIZE,
  });
  if (state.filters.service) params.set('service', state.filters.service);
  if (state.filters.result)  params.set('result',  state.filters.result);
  if (state.filters.search)  params.set('search',  state.filters.search);

  try {
    const res = await fetch(`${AUDIT_API}/logs?${params}`);
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    setConnected(true);
    state.logs  = data.items;
    state.total = data.total;
    renderTable();
    renderPagination();
    updateTableMeta();
  } catch (err) {
    setConnected(false);
    if (!silent) renderError(err.message);
  }
}

function renderLoading() {
  el.tbody.innerHTML = `
    <tr class="state-row">
      <td colspan="9">
        <div class="spinner"></div>
        <div>Loading logs…</div>
      </td>
    </tr>`;
}

function renderError(msg) {
  el.tbody.innerHTML = `
    <tr class="state-row">
      <td colspan="9" style="color:var(--color-red)">
        ⚠ Unable to reach Audit API<br>
        <small style="color:var(--text-muted)">${escHtml(msg)}</small><br><br>
        <button class="btn-filter btn-apply" onclick="fetchLogs()">Retry</button>
      </td>
    </tr>`;
}

function renderTable() {
  if (!state.logs.length) {
    el.tbody.innerHTML = `<tr class="state-row"><td colspan="9">No log entries found.</td></tr>`;
    return;
  }
  el.tbody.innerHTML = state.logs.map(row => `
    <tr onclick="openModal(${row.id})" title="Click for details">
      <td class="cell-id">${row.id}</td>
      <td class="cell-ts">${formatTs(row.ts)}</td>
      <td class="cell-rid" title="${escHtml(row.request_id)}">${row.request_id ? row.request_id.slice(0,8)+'…' : '—'}</td>
      <td class="cell-step">${row.step}</td>
      <td class="cell-svc">${escHtml(row.service)}</td>
      <td class="cell-sub" title="${escHtml(row.client_subject)}">${escHtml(row.client_subject) || '—'}</td>
      <td>${resultBadge(row.result)}</td>
      <td class="cell-reason" title="${escHtml(row.reason)}">${escHtml(row.reason)}</td>
      <td class="cell-lat" style="color:${latColor(row.latency_ms)}">${row.latency_ms} ms</td>
    </tr>
  `).join('');
}

function renderPagination() {
  const totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
  const cur = state.page;

  let pages = [];
  // Always show first, last, current ±1
  const set = new Set([0, totalPages - 1, cur, cur - 1, cur + 1].filter(n => n >= 0 && n < totalPages));
  const sorted = [...set].sort((a, b) => a - b);

  let last = -1;
  sorted.forEach(p => {
    if (last !== -1 && p - last > 1) pages.push(null); // ellipsis
    pages.push(p);
    last = p;
  });

  el.paginationEl.innerHTML = `
    <span class="page-info">Page ${cur + 1} of ${totalPages} &nbsp;|&nbsp; ${state.total} entries</span>
    <button class="btn-page" onclick="goPage(${cur-1})" ${cur===0?'disabled':''}>‹</button>
    ${pages.map(p => p === null
      ? `<span class="btn-page" style="cursor:default;border:none">…</span>`
      : `<button class="btn-page ${p===cur?'active':''}" onclick="goPage(${p})">${p+1}</button>`
    ).join('')}
    <button class="btn-page" onclick="goPage(${cur+1})" ${cur>=totalPages-1?'disabled':''}>›</button>
  `;
}

function updateTableMeta() {
  const from = state.page * PAGE_SIZE + 1;
  const to   = Math.min((state.page + 1) * PAGE_SIZE, state.total);
  el.tableMetaTxt.textContent = state.total
    ? `Showing ${from}–${to} of ${state.total}`
    : 'No entries';
}

function goPage(p) {
  const totalPages = Math.ceil(state.total / PAGE_SIZE);
  if (p < 0 || p >= totalPages) return;
  state.page = p;
  fetchLogs();
}

async function openModal(logId) {
  try {
    const res  = await fetch(`${AUDIT_API}/logs/${logId}`);
    if (!res.ok) throw new Error(res.statusText);
    const row = await res.json();

    el.modalId.textContent    = row.id;
    el.modalTs.textContent    = row.ts ? new Date(row.ts).toLocaleString() : '—';
    el.modalReqId.textContent = row.request_id || '—';
    el.modalStep.textContent  = row.step;
    el.modalSvc.textContent   = row.service || '—';
    el.modalSubj.textContent  = row.client_subject || '—';
    el.modalResult.innerHTML  = resultBadge(row.result);
    el.modalReason.textContent= row.reason || '—';
    el.modalLat.textContent   = `${row.latency_ms} ms`;
    el.modalBadge.innerHTML   = resultBadge(row.result);

    el.modalOverlay.classList.add('open');
  } catch (err) {
    showToast(`Failed to load log #${logId}: ${err.message}`);
  }
}

function closeModal() {
  el.modalOverlay.classList.remove('open');
}

function setConnected(online) {
  state.connected = online;
  el.connDot.className = 'conn-dot ' + (online ? 'online' : 'offline');
  el.connText.textContent = online ? 'Connected' : 'Disconnected';
}

function resultBadge(result) {
  const r = (result || '').toLowerCase();
  if (r === 'success')  return `<span class="badge badge-success">✓ success</span>`;
  if (r === 'rejected') return `<span class="badge badge-rejected">✕ rejected</span>`;
  if (r.startsWith('fail') || r === 'cert_mismatch' || r === 'header_modified')
    return `<span class="badge badge-failed">⚠ ${escHtml(result)}</span>`;
  return `<span class="badge badge-other">${escHtml(result || '—')}</span>`;
}

function latColor(ms) {
  if (ms < 50)  return 'var(--color-green)';
  if (ms < 200) return 'var(--color-amber)';
  return 'var(--color-red)';
}

function formatTs(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    const date = d.toLocaleDateString('id-ID', { day:'2-digit', month:'short', year:'numeric' });
    const time = d.toLocaleTimeString('id-ID', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
    return `${date} ${time}`;
  } catch { return iso; }
}

function escHtml(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showToast(msg) {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

document.addEventListener('DOMContentLoaded', init);
