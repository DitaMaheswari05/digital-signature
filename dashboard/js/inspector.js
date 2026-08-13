const Inspector = (() => {
  const SAMPLE_CMS_ENCRYPTED =
`MIIBpAYJKoZIhvcNAQcDoIIBlTCCAZECAQAxggFGMIIBQgIBADA
qMCUxIzAhBgNVBAMTGmNsaWVudC5tdGxzLXByb3h5LmxvY2Fs
AgIBATANBgkqhkiG9w0BAQEFAASCAQBqm7V4X3r9Kd5...
[CMS EnvelopedData DER, Base64-encoded]
X-CMS-Payload: eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNT...`;
  const SAMPLE_CMS_TAMPERED =
`MIIBpAYJKoZIhvcNAQcDoIIBlTCCAZECAQAxggFGMIIBQgIBADA
[PAYLOAD MODIFIED — bytes 48-52 altered by attacker]
qMCUxIzAhBgNVBAMTGmNsaWVudC5tdGxzLXByb3h5LmxvY2Fs
X-CMS-Payload: *** TAMPERED *** ZXhhbXBsZS1wd...`;
  const SAMPLE_PLAINTEXT_OK = JSON.stringify({
    status: 'success',
    message: 'Data berhasil diproses secara rahasia di backend.',
    echo_path: '/api/data',
    processed_payload: {
      user_id: 'demo-user-42',
      action: 'fetch_records',
      timestamp: new Date().toISOString(),
    },
  }, null, 2);
  const SAMPLE_PLAINTEXT_REJECT = JSON.stringify({
    error: '[Step 5] Verifikasi CMS signature webapp GAGAL — response mungkin dimanipulasi atau bukan dari webapp asli (cert: webappcert.crt).',
  }, null, 2);
  const SAMPLE_PLAINTEXT_BADCERT = JSON.stringify({
    error: '[Layer 1] mTLS transport verification gagal: X-SSL-Client-Verify=\'NONE\'. Client certificate tidak ada atau tidak valid di TLS layer.',
    status_code: 401,
  }, null, 2);
  function showNormal() {
    _setEncrypted(SAMPLE_CMS_ENCRYPTED);
    _setDecrypted(SAMPLE_PLAINTEXT_OK);
    _setSigBadge('valid', '✓ Signature Valid');
  }
  function showTamper() {
    _setEncrypted(SAMPLE_CMS_TAMPERED, true);
    _setDecrypted(SAMPLE_PLAINTEXT_REJECT, true);
    _setSigBadge('invalid', '✗ Signature INVALID');
  }
  function showBadCert() {
    _setEncrypted('(Request ditolak sebelum payload diterima)\nX-SSL-Client-Verify: NONE\n— mTLS handshake gagal —', true);
    _setDecrypted(SAMPLE_PLAINTEXT_BADCERT, true);
    _setSigBadge('rejected', '✗ mTLS Cert REJECTED');
  }
  function showIdle() {
    _setEncrypted('-- Jalankan skenario untuk melihat payload --');
    _setDecrypted('-- Menunggu skenario --');
    _setSigBadge('idle', 'Menunggu');
  }
  function clearLog() {
    const log = document.getElementById('audit-log');
    if (log) log.innerHTML = '';
  }
  function appendLog(message, level = 'info') {
    const log = document.getElementById('audit-log');
    if (!log) return;
    const now = new Date();
    const ts = now.toTimeString().slice(0, 8);
    const entry = document.createElement('div');
    entry.className = `log-entry log-${level}`;
    const timeEl = document.createElement('span');
    timeEl.className = 'log-time';
    timeEl.textContent = ts;
    const msgEl = document.createElement('span');
    msgEl.className = 'log-msg';
    msgEl.textContent = message;
    entry.appendChild(timeEl);
    entry.appendChild(msgEl);
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
  }
  function _setEncrypted(text, isError = false) {
    const el = document.getElementById('payload-encrypted');
    if (!el) return;
    el.textContent = text;
    el.className = isError
      ? 'inspector-code inspector-code-enc inspector-code-error'
      : 'inspector-code inspector-code-enc';
  }
  function _setDecrypted(text, isError = false) {
    const el = document.getElementById('payload-decrypted');
    if (!el) return;
    el.textContent = text;
    el.className = isError
      ? 'inspector-code inspector-code-dec inspector-code-error'
      : 'inspector-code inspector-code-dec';
  }
  function _setSigBadge(state, label) {
    const badge = document.getElementById('sig-badge');
    if (!badge) return;
    badge.textContent = label;
    badge.className = `sig-badge sig-${state}`;
  }
  return { showNormal, showTamper, showBadCert, showIdle, appendLog, clearLog };
})();