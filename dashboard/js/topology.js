const Topology = (() => {
  let _svg = null;
  let _nodes = {};        
  let _connections = {};  
  let _packetId = 0;
  const NODE_DEFS = [
    {
      id: 'client',
      x: 90,
      label: 'Client Application',
      sub: 'HTTP Request',
      stepLabel: 'Step 1 & 5',
      certLabel: 'Client Certificate',
      certIcon: '🔑',
    },
    {
      id: 'proxy',
      x: 270,
      label: 'Proxy',
      sub: ':8080',
      stepLabel: 'Step 1 & 5',
      certLabel: 'Client Cert + mTLS',
      certIcon: '🔑',
    },
    {
      id: 'waf',
      x: 480,
      label: 'WAF + WAF Service',
      stepLabel: 'Step 2 & 3',
      certLabel: 'Server Certificate',
      certIcon: '🔑',
    },
    {
      id: 'webapp',
      x: 670,
      label: 'Web Application',
      sub: 'FastAPI Backend',
      stepLabel: 'Step 4',
      certLabel: 'WebApp Certificate',
      certIcon: '🔑',
    },
  ];
  const CONN_DEFS = [
    { id: 'client-proxy',  src: 'client',  dst: 'proxy',   label: 'HTTP' },
    { id: 'proxy-waf',     src: 'proxy',   dst: 'waf',     label: 'mTLS / HTTPS' },
    { id: 'waf-webapp',    src: 'waf',     dst: 'webapp',  label: 'Internal HTTP' },
  ];
  const RETURN_CONN_DEFS = [
    { id: 'webapp-waf',    src: 'webapp',  dst: 'waf',     label: '' },
    { id: 'waf-proxy',     src: 'waf',     dst: 'proxy',   label: '' },
    { id: 'proxy-client',  src: 'proxy',   dst: 'client',  label: '' },
  ];
  const W = 800;
  const H = 280;
  const NODE_Y = 100;
  const NODE_W = 130;
  const NODE_H = 72;
  const CERT_Y = 195;
  function init(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    _svg = _createSVG();
    container.appendChild(_svg);
    _renderDefs();
    _renderConnections();
    _renderReturnConnections();
    _renderNodes();
    _renderCerts();
  }
  function setNodeStatus(nodeId, status) {
    const n = _nodes[nodeId];
    if (!n) return;
    const bg = n.bg;
    bg.setAttribute('class', `topo-node-bg status-${status}`);
    if (status === 'active') {
      n.pulseRing.setAttribute('class', 'topo-pulse-ring pulsing');
    } else {
      n.pulseRing.setAttribute('class', 'topo-pulse-ring');
    }
    const labels = {
      idle:    '—',
      active:  '⏳ Processing…',
      success: '✓ OK',
      error:   '✗ BLOCKED',
      warn:    '⚠ WARNING',
    };
    n.statusText.textContent = labels[status] || '—';
    n.statusText.setAttribute('class', `topo-status-text topo-status-${status}`);
    if (status === 'error') {
      n.group.classList.add('shaking');
      setTimeout(() => n.group.classList.remove('shaking'), 600);
    }
  }
  function setConnectionStatus(connId, status) {
    const c = _connections[connId];
    if (!c) return;
    c.path.setAttribute('class', `topo-connection ${status !== 'idle' ? status : ''}`);
    if (c.label) {
      c.label.setAttribute('class', `topo-conn-label ${status !== 'idle' ? status : ''}`);
    }
  }
  function animatePacket(srcId, dstId, type = 'normal', onComplete) {
    const srcNode = NODE_DEFS.find(n => n.id === srcId);
    const dstNode = NODE_DEFS.find(n => n.id === dstId);
    if (!srcNode || !dstNode) {
      if (onComplete) onComplete();
      return;
    }
    const startX = srcNode.x + NODE_W / 2 + 14;
    const endX   = dstNode.x - 14;
    const y      = NODE_Y + NODE_H / 2;
    const circle = _createEl('circle');
    const cls = type === 'blocked' ? 'topo-packet blocked'
               : type === 'success' ? 'topo-packet success'
               : 'topo-packet';
    circle.setAttribute('class', cls);
    circle.setAttribute('cx', startX);
    circle.setAttribute('cy', y);
    _svg.appendChild(circle);
    const duration = CONFIG.ANIM.PACKET_STEP_DURATION;
    const startTime = performance.now();
    function step(now) {
      const elapsed = now - startTime;
      const t = Math.min(elapsed / duration, 1);
      const ease = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t; 
      const cx = startX + (endX - startX) * ease;
      circle.setAttribute('cx', cx);
      if (t < 1) {
        requestAnimationFrame(step);
      } else {
        _svg.removeChild(circle);
        if (onComplete) onComplete();
      }
    }
    requestAnimationFrame(step);
  }
  function resetAll() {
    NODE_DEFS.forEach(n => setNodeStatus(n.id, 'idle'));
    Object.keys(_connections).forEach(k => setConnectionStatus(k, 'idle'));
  }
  function _createSVG() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    svg.style.cssText = 'width:100%;height:100%;overflow:visible;';
    return svg;
  }
  function _createEl(tag) {
    return document.createElementNS('http://www.w3.org/2000/svg', tag);
  }
  function _createText(content, x, y, cls, anchor = 'middle') {
    const t = _createEl('text');
    t.setAttribute('x', x);
    t.setAttribute('y', y);
    t.setAttribute('class', cls);
    t.setAttribute('text-anchor', anchor);
    t.setAttribute('dominant-baseline', 'middle');
    t.textContent = content;
    return t;
  }
  function _renderDefs() {
    const defs = _createEl('defs');
    const grad = _createEl('linearGradient');
    grad.setAttribute('id', 'nodeGrad');
    grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0');
    grad.setAttribute('x2', '0'); grad.setAttribute('y2', '1');
    const s1 = _createEl('stop');
    s1.setAttribute('offset', '0%');
    s1.setAttribute('stop-color', '#141c30');
    const s2 = _createEl('stop');
    s2.setAttribute('offset', '100%');
    s2.setAttribute('stop-color', '#0a0e1a');
    grad.appendChild(s1); grad.appendChild(s2);
    defs.appendChild(grad);
    _svg.appendChild(defs);
  }
  function _renderNodes() {
    NODE_DEFS.forEach(def => {
      const g = _createEl('g');
      g.setAttribute('class', 'topo-node-group');
      g.setAttribute('id', `node-${def.id}`);
      const bg = _createEl('rect');
      bg.setAttribute('class', 'topo-node-bg status-idle');
      bg.setAttribute('x', def.x);
      bg.setAttribute('y', NODE_Y);
      bg.setAttribute('width', NODE_W);
      bg.setAttribute('height', NODE_H);
      bg.setAttribute('rx', '10');
      g.appendChild(bg);
      const pulse = _createEl('rect');
      pulse.setAttribute('class', 'topo-pulse-ring');
      pulse.setAttribute('x', def.x - 4);
      pulse.setAttribute('y', NODE_Y - 4);
      pulse.setAttribute('width', NODE_W + 8);
      pulse.setAttribute('height', NODE_H + 8);
      pulse.setAttribute('rx', '14');
      g.appendChild(pulse);
      const cx = def.x + 22;
      const cy = NODE_Y + NODE_H / 2;
      const iconCircle = _createEl('circle');
      iconCircle.setAttribute('class', 'topo-icon-circle');
      iconCircle.setAttribute('cx', cx);
      iconCircle.setAttribute('cy', cy);
      iconCircle.setAttribute('r', '16');
      g.appendChild(iconCircle);
      const iconText = _createEl('text');
      iconText.setAttribute('x', cx);
      iconText.setAttribute('y', cy);
      iconText.setAttribute('text-anchor', 'middle');
      iconText.setAttribute('dominant-baseline', 'middle');
      iconText.setAttribute('font-size', '14');
      iconText.textContent = def.icon;
      g.appendChild(iconText);
      g.appendChild(_createText(
        def.stepLabel,
        def.x + NODE_W / 2,
        NODE_Y + 10,
        'topo-node-step',
      ));
      g.appendChild(_createText(
        def.label,
        def.x + NODE_W / 2 + 4,
        cy - 8,
        'topo-node-title',
      ));
      g.appendChild(_createText(
        def.sub,
        def.x + NODE_W / 2 + 4,
        cy + 9,
        'topo-node-sub',
      ));
      const statusText = _createText(
        '—',
        def.x + NODE_W / 2,
        NODE_Y + NODE_H - 10,
        'topo-status-text topo-status-idle',
      );
      g.appendChild(statusText);
      _svg.appendChild(g);
      _nodes[def.id] = { group: g, bg, pulseRing: pulse, statusText };
    });
  }
  function _renderConnections() {
    CONN_DEFS.forEach(def => {
      const srcNode = NODE_DEFS.find(n => n.id === def.src);
      const dstNode = NODE_DEFS.find(n => n.id === def.dst);
      const y = NODE_Y + NODE_H / 2;
      const x1 = srcNode.x + NODE_W;
      const x2 = dstNode.x;
      const mx = (x1 + x2) / 2;
      const path = _createEl('line');
      path.setAttribute('class', 'topo-connection');
      path.setAttribute('x1', x1); path.setAttribute('y1', y);
      path.setAttribute('x2', x2); path.setAttribute('y2', y);
      _svg.insertBefore(path, _svg.firstChild);
      const arrow = _createEl('polygon');
      const ax = x2 - 2;
      arrow.setAttribute('points', `${ax},${y - 5} ${ax + 8},${y} ${ax},${y + 5}`);
      arrow.setAttribute('fill', '#334155');
      arrow.setAttribute('class', `conn-arrow conn-arrow-${def.id}`);
      _svg.insertBefore(arrow, _svg.firstChild);
      const label = _createText(def.label, mx, y - 12, 'topo-conn-label');
      _svg.appendChild(label);
      _connections[def.id] = { path, label, arrow };
    });
  }
  function _renderReturnConnections() {
    const RETURN_Y = NODE_Y + NODE_H + 14;
    RETURN_CONN_DEFS.forEach(def => {
      const srcNode = NODE_DEFS.find(n => n.id === def.src);
      const dstNode = NODE_DEFS.find(n => n.id === def.dst);
      const x1 = srcNode.x + NODE_W / 2;
      const x2 = dstNode.x + NODE_W / 2;
      const path = _createEl('line');
      path.setAttribute('class', 'topo-connection');
      path.setAttribute('x1', x1); path.setAttribute('y1', RETURN_Y);
      path.setAttribute('x2', x2); path.setAttribute('y2', RETURN_Y);
      path.setAttribute('stroke-dasharray', '4 3');
      path.setAttribute('opacity', '0.5');
      _svg.insertBefore(path, _svg.firstChild);
      [srcNode, dstNode].forEach(nd => {
        const vx = nd.x + NODE_W / 2;
        const vLine = _createEl('line');
        vLine.setAttribute('x1', vx); vLine.setAttribute('y1', NODE_Y + NODE_H);
        vLine.setAttribute('x2', vx); vLine.setAttribute('y2', RETURN_Y);
        vLine.setAttribute('stroke', '#1e293b');
        vLine.setAttribute('stroke-width', '1.5');
        _svg.insertBefore(vLine, _svg.firstChild);
      });
      _connections[def.id] = { path, label: null };
    });
    const label = _createEl('text');
    label.setAttribute('x', W / 2);
    label.setAttribute('y', RETURN_Y + 12);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('class', 'topo-conn-label');
    label.textContent = '← Response (CMS Encrypted + Signed)';
    _svg.appendChild(label);
  }
  function _renderCerts() {
    const certs = [
      { nodeId: 'client', label: 'Client Certificate' },
      { nodeId: 'waf',    label: 'Server Certificate' },
      { nodeId: 'webapp', label: 'WebApp Certificate' },
    ];
    certs.forEach(c => {
      const nodeDef = NODE_DEFS.find(n => n.id === c.nodeId);
      if (!nodeDef) return;
      const cx = nodeDef.x + NODE_W / 2;
      const icon = _createEl('text');
      icon.setAttribute('x', cx);
      icon.setAttribute('y', CERT_Y);
      icon.setAttribute('text-anchor', 'middle');
      icon.setAttribute('font-size', '18');
      icon.setAttribute('opacity', '0.7');
      icon.textContent = '🔑';
      _svg.appendChild(icon);
      const lbl = _createEl('text');
      lbl.setAttribute('x', cx);
      lbl.setAttribute('y', CERT_Y + 18);
      lbl.setAttribute('text-anchor', 'middle');
      lbl.setAttribute('class', 'topo-cert-label');
      lbl.textContent = c.label;
      _svg.appendChild(lbl);
    });
  }
  return { init, setNodeStatus, setConnectionStatus, animatePacket, resetAll };
})();