const Scenarios = (() => {
  let _running       = false;
  let _loadTestTimer = null;
  let _successCount  = 0;
  let _blockedCount  = 0;
  const NARRATIONS = {
    normal: [
      {
        num:    'Step 1 — Proxy',
        text:   'Client mengirim request ke Proxy. Proxy mengenkripsi payload dengan WebApp Certificate dan menandatangani dengan Client Certificate (CMS).',
        detail: 'cms_payload = CMS_pack(body, signer=client_key, recipient=webapp_pubkey)',
        state:  'active',
      },
      {
        num:    'Step 2 — mTLS Transport',
        text:   'Proxy mengirim request ke WAF melalui TLS mutual authentication menggunakan Client Certificate dan Server Certificate.',
        detail: 'TLS Handshake: Client Cert ↔ Server Cert verified',
        state:  'active',
      },
      {
        num:    'Step 3 — WAF Verification (3 Layer)',
        text:   'WAF Service memverifikasi: (1) mTLS X-SSL-Client-Verify=SUCCESS, (2) CA Trust Chain, (3) CMS Signature valid.',
        detail: 'layers_passed: [transport, trust_anchor, cms_signature, header_digest]',
        state:  'active',
      },
      {
        num:    'Step 4 — Web Application',
        text:   'WebApp mendekripsi payload dengan private key-nya, memverifikasi signature Client Certificate. Response dikemas ulang dengan CMS.',
        detail: 'cms_decrypt_request(der, webapp_privkey, client_cert) → sig_valid=True',
        state:  'active',
      },
      {
        num:    'Step 5 — Response Verified ✓',
        text:   'Proxy menerima response terenkripsi dari WAF. Proxy mendekripsi dengan Client private key dan memverifikasi signature WebApp. Semua layer PASSED.',
        detail: 'cms_unpack(der, client_key, trusted=webapp_cert) → sig_valid=True → 200 OK',
        state:  'success',
      },
    ],
    tamper: [
      {
        num:    'Step 1 — Proxy',
        text:   'Client mengirim request. Proxy mengemas payload dengan CMS (encrypted + signed).',
        detail: 'cms_payload = CMS_pack(body, signer=client_key, ...)',
        state:  'active',
      },
      {
        num:    'Step 2 — mTLS OK',
        text:   'Transport mTLS berhasil. Paket terkirim ke WAF.',
        detail: 'X-SSL-Client-Verify: SUCCESS',
        state:  'active',
      },
      {
        num:    'Step 3 — WAF: mTLS + CA + CMS OK',
        text:   'WAF memverifikasi semua 3 layer dan meneruskan ke WebApp.',
        detail: 'layers_passed: [transport, trust_anchor, cms_signature]',
        state:  'active',
      },
      {
        num:    'Step 4 — WebApp: Signature GAGAL ✗',
        text:   'ATTACKER mengubah byte payload di tengah jalan. WebApp mendeteksi: message-digest di signed_attributes TIDAK COCOK dengan payload yang diterima.',
        detail: '[Step 4] CMS signature TIDAK VALID — request mungkin dimanipulasi → HTTP 403',
        state:  'error',
      },
    ],
    bad_cert: [
      {
        num:    'Step 1 — Proxy',
        text:   'Client mengirim request. Proxy mencoba setup koneksi mTLS ke WAF, namun Client Certificate tidak valid/expired.',
        detail: 'X-SSL-Client-Verify: FAILED (cert invalid or not presented)',
        state:  'active',
      },
      {
        num:    'Step 3 — WAF: mTLS GAGAL ✗',
        text:   'WAF Service menerima X-SSL-Client-Verify=NONE atau FAILED. Layer 1 (mTLS Transport) DITOLAK. Request tidak diteruskan ke WebApp.',
        detail: '[Layer 1] mTLS transport verification gagal: X-SSL-Client-Verify=\'NONE\' → HTTP 401',
        state:  'error',
      },
    ],
  };
  function _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  function _setButtons(disabled) {
    document.querySelectorAll('.btn-scenario').forEach(btn => {
      btn.classList.toggle('running', disabled);
      btn.disabled = disabled;
    });
  }
  function _updateCounters() {
    const total = _successCount + _blockedCount;
    document.getElementById('count-success').textContent = _successCount;
    document.getElementById('count-blocked').textContent = _blockedCount;
    document.getElementById('count-total').textContent   = total;
  }
  function _renderNarration(steps) {
    const body = document.getElementById('narration-body');
    if (!body) return;
    body.innerHTML = '';
    steps.forEach(step => {
      const card = document.createElement('div');
      card.className = `narration-step step-${step.state}`;
      const num = document.createElement('div');
      num.className = 'narration-step-num';
      num.textContent = step.num;
      const text = document.createElement('div');
      text.className = 'narration-step-text';
      text.textContent = step.text;
      const detail = document.createElement('div');
      detail.className = 'narration-step-detail';
      detail.textContent = step.detail;
      card.appendChild(num);
      card.appendChild(text);
      card.appendChild(detail);
      body.appendChild(card);
    });
  }
  function _animPacketStep(src, dst, connId, type) {
    return new Promise(resolve => {
      Topology.setNodeStatus(src, 'active');
      Topology.setConnectionStatus(connId, 'active');
      Topology.animatePacket(src, dst, type, () => {
        Topology.setNodeStatus(dst, type === 'normal' ? 'active' : type);
        Topology.setConnectionStatus(connId, type === 'normal' ? 'active' : type);
        setTimeout(resolve, CONFIG.ANIM.PACKET_PAUSE);
      });
    });
  }
  async function _fireProxyRequest(scenarioHeader) {
    const headers = { 'Content-Type': 'application/json' };
    if (scenarioHeader) headers['X-Demo-Scenario'] = scenarioHeader;
    try {
      const res = await fetch('http://localhost:8080/api/demo', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ action: 'demo', ts: Date.now() })
      });
      const payload = res.headers.get('X-CMS-Payload') || res.headers.get('x-cms-payload');
      const text = await res.text();
      return { ok: res.ok, status: res.status, text, payload };
    } catch (e) {
      return { ok: false, status: 0, text: e.message, payload: null };
    }
  }
  async function _runNormal() {
    Inspector.clearLog();
    Inspector.appendLog('[Step 1] Mengirim HTTP Request ke Proxy...', 'info');
    Topology.setNodeStatus('client', 'active');
    const reqPromise = _fireProxyRequest('normal');
    await _animPacketStep('client', 'proxy', 'client-proxy', 'normal');
    Inspector.appendLog('[Step 1] Proxy: CMS_pack selesai', 'info');
    await _animPacketStep('proxy', 'waf', 'proxy-waf', 'normal');
    Inspector.appendLog('[Step 2] mTLS Handshake: X-SSL-Client-Verify = SUCCESS', 'success');
    await _animPacketStep('waf', 'webapp', 'waf-webapp', 'normal');
    Inspector.appendLog('[Step 3] WAF meneruskan ke WebApp', 'info');
    Topology.setNodeStatus('webapp', 'active');
    const resp = await reqPromise;
    if (resp.ok) {
      Inspector.appendLog('[Step 4] WebApp: cms_decrypt_request → sig_valid = True', 'success');
      Topology.setNodeStatus('webapp', 'success');
      await _delay(300);
      Topology.setNodeStatus('waf', 'success');
      Topology.setConnectionStatus('webapp-waf', 'success');
      await _delay(200);
      Topology.setNodeStatus('proxy', 'success');
      Topology.setConnectionStatus('waf-proxy', 'success');
      await _delay(200);
      Topology.setNodeStatus('client', 'success');
      Topology.setConnectionStatus('proxy-client', 'success');
      Inspector.appendLog('[Step 5] Proxy terima CMS response → 200 OK ✓', 'success');
      Inspector.showNormal();
      if (resp.payload) {
        document.getElementById('payload-encrypted').textContent = resp.payload.substring(0, 500) + '...';
        document.getElementById('payload-decrypted').textContent = JSON.stringify(JSON.parse(resp.text), null, 2);
      }
      _successCount++;
    } else {
      Inspector.appendLog(`[Step 4] Request gagal: HTTP ${resp.status}`, 'error');
      Topology.setNodeStatus('webapp', 'error');
      Inspector.showTamper();
      _blockedCount++;
    }
    _updateCounters();
    _renderNarration(NARRATIONS.normal);
  }
  async function _runTamper() {
    Inspector.clearLog();
    Inspector.appendLog('[Step 1] Mengirim request ke Proxy dengan skenario Tamper...', 'info');
    Topology.setNodeStatus('client', 'active');
    const reqPromise = _fireProxyRequest('tamper');
    await _animPacketStep('client', 'proxy', 'client-proxy', 'normal');
    await _animPacketStep('proxy', 'waf', 'proxy-waf', 'normal');
    Inspector.appendLog('[ATTACKER] Payload disimulasikan rusak sebelum WAF!', 'warn');
    await _animPacketStep('waf', 'webapp', 'waf-webapp', 'blocked');
    const resp = await reqPromise;
    if (!resp.ok) {
      Inspector.appendLog(`[Step 4] WebApp: CMS verification failed → HTTP ${resp.status}`, 'error');
      Topology.setNodeStatus('webapp', 'error');
      Inspector.showTamper();
      try {
         const d = JSON.parse(resp.text);
         if (d.waf_response_text) document.getElementById('payload-decrypted').textContent = d.waf_response_text;
      } catch (e) {}
      _blockedCount++;
    } else {
      Topology.setNodeStatus('webapp', 'success');
      _successCount++;
    }
    _updateCounters();
    _renderNarration(NARRATIONS.tamper);
  }
  async function _runBadCert() {
    Inspector.clearLog();
    Inspector.appendLog('[Step 1] Mengirim request dengan Bad Cert...', 'info');
    Topology.setNodeStatus('client', 'active');
    const reqPromise = _fireProxyRequest('bad_cert');
    await _animPacketStep('client', 'proxy', 'client-proxy', 'normal');
    Inspector.appendLog('[Step 2] Proxy ke WAF: Mengabaikan client certificate!', 'warn');
    await _animPacketStep('proxy', 'waf', 'proxy-waf', 'blocked');
    const resp = await reqPromise;
    if (!resp.ok) {
      Topology.setNodeStatus('waf', 'error');
      Inspector.appendLog(`[Step 3] WAF mTLS Layer: HTTP ${resp.status}`, 'error');
      Inspector.showBadCert();
      try {
         const d = JSON.parse(resp.text);
         if (d.waf_response_text) document.getElementById('payload-decrypted').textContent = d.waf_response_text;
      } catch (e) {}
      Topology.setNodeStatus('proxy', 'error');
      Topology.setNodeStatus('client', 'error');
      _blockedCount++;
    } else {
      _successCount++;
    }
    _updateCounters();
    _renderNarration(NARRATIONS.bad_cert);
  }
  async function _runLoadTest() {
    Inspector.clearLog();
    Inspector.appendLog(`[Load Test] Menjalankan ${CONFIG.ANIM.LOADTEST_COUNT} request secara paralel...`, 'info');
    const body = document.getElementById('narration-body');
    if (body) {
      body.innerHTML = '<p class="narration-idle">⚡ Load Test berjalan...<br/>Log sistem di bagian bawah akan terisi penuh dengan real data.</p>';
    }
    let sent = 0;
    const total = CONFIG.ANIM.LOADTEST_COUNT;
    function fireMany() {
        for (let i = 0; i < 5; i++) {
            if (sent >= total) break;
            sent++;
            const scenario = (Math.random() < 0.1) ? 'tamper' : 'normal';
            _fireProxyRequest(scenario).then(resp => {
                if (resp.ok) _successCount++; else _blockedCount++;
                _updateCounters();
            });
            const srcDst = [['client','proxy'], ['proxy','waf'], ['waf','webapp']][Math.floor(Math.random()*3)];
            Topology.animatePacket(srcDst[0], srcDst[1], scenario === 'normal' ? 'normal' : 'blocked');
        }
        if (sent < total && _running) {
            _loadTestTimer = setTimeout(fireMany, 150);
        } else {
            Inspector.appendLog(`[Load Test] Selesai mengirim ${total} request.`, 'success');
        }
    }
    fireMany();
  }
  async function run(scenarioName) {
    if (_running) return;
    _running = true;
    _setButtons(true);
    clearTimeout(_loadTestTimer);
    Topology.resetAll();
    Inspector.showIdle();
    document.getElementById('narration-body').innerHTML =
      '<p class="narration-idle">Memulai skenario…</p>';
    try {
      switch (scenarioName) {
        case 'normal':   await _runNormal();   break;
        case 'tamper':   await _runTamper();   break;
        case 'bad_cert': await _runBadCert();  break;
        case 'loadtest': await _runLoadTest(); break;
        default: break;
      }
    } catch (err) {
      console.error('[Scenario Error]', err);
    } finally {
      if (scenarioName !== 'loadtest') {
        _running = false;
        _setButtons(false);
      } else {
        setTimeout(() => {
          _running = false;
          _setButtons(false);
        }, CONFIG.ANIM.LOADTEST_COUNT * CONFIG.ANIM.LOADTEST_INTERVAL + 1000);
      }
    }
  }
  function reset() {
    clearTimeout(_loadTestTimer);
    _running = false;
    _setButtons(false);
    Topology.resetAll();
    Inspector.showIdle();
    Inspector.clearLog();
    _successCount = 0;
    _blockedCount = 0;
    _updateCounters();
    const body = document.getElementById('narration-body');
    if (body) {
      body.innerHTML = '<p class="narration-idle">Pilih skenario di atas untuk memulai simulasi keamanan.</p>';
    }
  }
  async function checkSystemStatus() {
    const endpoints = [
      { id: 'status-proxy',      url: CONFIG.HEALTH.PROXY,      label: 'Online' },
      { id: 'status-grafana',    url: CONFIG.HEALTH.GRAFANA,    label: 'Online' },
      { id: 'status-prometheus', url: CONFIG.HEALTH.PROMETHEUS, label: 'Online' },
    ];
    for (const ep of endpoints) {
      const badge = document.getElementById(ep.id);
      if (!badge) continue;
      try {
        await fetch(ep.url, { mode: 'no-cors', signal: AbortSignal.timeout(3000) });
        badge.classList.add('online');
        badge.classList.remove('offline');
        badge.querySelector('.status-value').textContent = ep.label;
      } catch (_) {
        badge.classList.add('offline');
        badge.classList.remove('online');
        badge.querySelector('.status-value').textContent = 'Offline';
      }
    }
    setTimeout(checkSystemStatus, 30000);
  }
  return { run, reset, checkSystemStatus };
})();