/**
 * HostTrace AI – script.js  v4.0
 * Frontend Logic: Scanning, UI, Charts, PDF Export
 * New: Origin Discovery, ASN Mismatch, Redirect Chain, AI Confidence,
 *      Infrastructure Map, Why Risky, OSINT Simulation panels
 */

/* ════════════════════════════════════════════
   PARTICLE BACKGROUND
═══════════════════════════════════════════ */
(function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];
  function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);
  const COLORS = ['#00ff9f','#00eaff','#bc5af7'];
  for (let i = 0; i < 80; i++) {
    particles.push({ x:Math.random()*9999, y:Math.random()*9999,
      vx:(Math.random()-0.5)*0.4, vy:(Math.random()-0.5)*0.4,
      r:Math.random()*1.6+0.4, c:COLORS[Math.floor(Math.random()*COLORS.length)],
      a:Math.random()*0.5+0.2 });
  }
  function drawGrid() {
    ctx.strokeStyle='rgba(0,234,255,0.03)'; ctx.lineWidth=1;
    for (let x=0;x<W;x+=60){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
    for (let y=0;y<H;y+=60){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
  }
  function frame() {
    ctx.clearRect(0,0,W,H); drawGrid();
    for (let i=0;i<particles.length;i++) {
      for (let j=i+1;j<particles.length;j++) {
        const dx=particles[i].x-particles[j].x, dy=particles[i].y-particles[j].y;
        const dist=Math.hypot(dx,dy);
        if(dist<120){ctx.strokeStyle=`rgba(0,234,255,${0.06*(1-dist/120)})`;ctx.lineWidth=0.5;
          ctx.beginPath();ctx.moveTo(particles[i].x,particles[i].y);ctx.lineTo(particles[j].x,particles[j].y);ctx.stroke();}
      }
    }
    for (const p of particles) {
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0)p.x=W; if(p.x>W)p.x=0; if(p.y<0)p.y=H; if(p.y>H)p.y=0;
      ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=p.c; ctx.globalAlpha=p.a; ctx.fill(); ctx.globalAlpha=1;
    }
    requestAnimationFrame(frame);
  }
  frame();
})();

/* ════════════════════════════════════════════
   GLOBAL STATE
═══════════════════════════════════════════ */
let currentReport = null;
let riskChart = null;
let ipChart = null;

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const API_BASE = isLocal && window.location.port !== '5000' && window.location.port !== '' ? 'http://127.0.0.1:5000' : '';

/* ════════════════════════════════════════════
   HEALTH CHECK
═══════════════════════════════════════════ */
(async function checkHealth() {
  const badge = document.getElementById('healthBadge');
  try {
    const r = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(4000) });
    if (r.ok) { badge.textContent = 'BACKEND ONLINE'; badge.classList.add('online'); }
    else       { badge.textContent = 'BACKEND ERROR';  badge.classList.add('offline'); }
  } catch {
    badge.textContent = 'BACKEND OFFLINE'; badge.classList.add('offline');
  }
})();

document.getElementById('domainInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startAnalysis();
});

/* ════════════════════════════════════════════
   SCANNER STEPS  (v4.0 — 18 steps)
═══════════════════════════════════════════ */
const SCAN_STEPS = [
  { pct:  5,  msg: '> Initializing OSINT engine v4.0…',         cls: 'header'  },
  { pct: 12,  msg: '> Resolving DNS records…',                   cls: 'info'    },
  { pct: 19,  msg: '> Querying WHOIS database…',                 cls: 'info'    },
  { pct: 26,  msg: '> Checking CIDR / ASN ranges…',              cls: 'info'    },
  { pct: 33,  msg: '> Inspecting SSL certificate…',              cls: 'info'    },
  { pct: 39,  msg: '> Analyzing HTTP security headers…',         cls: 'info'    },
  { pct: 45,  msg: '> Mapping IP geolocation…',                  cls: 'info'    },
  { pct: 51,  msg: '> Analyzing URL patterns…',                  cls: 'warn'    },
  { pct: 57,  msg: '> 🔥 Enumerating subdomains for origin leak…',cls: 'warn'   },
  { pct: 63,  msg: '> Probing origin infrastructure…',           cls: 'warn'    },
  { pct: 68,  msg: '> Detecting ASN / hosting mismatch…',        cls: 'warn'    },
  { pct: 73,  msg: '> Tracing redirect chain…',                  cls: 'info'    },
  { pct: 78,  msg: '> Running OSINT simulation…',                cls: 'info'    },
  { pct: 83,  msg: '> Running AI prediction model…',             cls: 'info'    },
  { pct: 87,  msg: '> Correlating threat intelligence…',         cls: 'warn'    },
  { pct: 92,  msg: '> Calculating risk score (engine v4.0)…',    cls: 'warn'    },
  { pct: 97,  msg: '> Generating AI confidence score…',          cls: 'success' },
  { pct: 100, msg: '> Finalising forensic report…',              cls: 'success' },
];
const SCAN_TITLES = [
  'INITIALIZING','DNS LOOKUP','WHOIS QUERY','CIDR ANALYSIS','SSL INSPECTION',
  'HTTP HEADERS','GEO-IP','URL ANALYSIS','ORIGIN DISCOVERY','PROBING ORIGIN',
  'ASN MISMATCH','REDIRECT CHAIN','OSINT SIM','AI PREDICTION',
  'THREAT INTEL','RISK ENGINE v4','AI CONFIDENCE','FINALIZING'
];

/* ════════════════════════════════════════════
   MAIN ENTRY POINT
═══════════════════════════════════════════ */
async function startAnalysis() {
  const input  = document.getElementById('domainInput');
  const domain = input.value.trim();
  if (!domain) { shakeInput(); return; }

  showScanner();
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), 60000);

  let apiResp = null, apiErr = null;

  const apiCall = fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
    signal: controller.signal,
  })
  .then(async r => {
    clearTimeout(timeoutId);
    if (!r.ok) { const t = await r.text(); throw new Error(`Server ${r.status}: ${t.slice(0,60)}`); }
    return r.json();
  })
  .catch(err => { clearTimeout(timeoutId); apiErr = err; return null; });

  runScanAnimation(async (currentStep, totalSteps) => {
    if (currentStep === totalSteps - 1) {
      apiResp = await apiCall;
      if (apiErr) {
        const isOffline = apiErr.message.includes('Failed to fetch') || apiErr.name === 'AbortError';
        hideScanner();
        showFatalError(isOffline ? 'Could not reach backend. Is app.py running?' : apiErr.message);
        return false;
      }
      if (apiResp && apiResp.error) {
        logToScanner(`[ERROR] ${apiResp.error.toUpperCase()}`, 'danger');
        document.getElementById('scannerTitle').textContent = 'SCAN HALTED';
        return false;
      }
    }
    return true;
  }, () => {
    if (apiResp) { currentReport = apiResp; hideScanner(); renderResults(apiResp); }
  });
}

/* ════════════════════════════════════════════
   SCANNER ANIMATION
═══════════════════════════════════════════ */
function showScanner() {
  document.getElementById('scannerOverlay').classList.remove('hidden');
  document.getElementById('resultsSection').classList.add('hidden');
  document.getElementById('scanBar').style.width     = '0%';
  document.getElementById('scanPercent').textContent = '0%';
  document.getElementById('scannerLog').innerHTML    = '';
  document.getElementById('scannerTitle').textContent = 'INITIALIZING SCAN';
}
function hideScanner() { document.getElementById('scannerOverlay').classList.add('hidden'); }
function showFatalError(msg) {
  document.getElementById('fatalMsg').textContent = msg || 'Unknown error.';
  document.getElementById('fatalErrorOverlay').classList.remove('hidden');
}
function closeFatalError() { document.getElementById('fatalErrorOverlay').classList.add('hidden'); }

function runScanAnimation(onStep, onComplete) {
  const bar=document.getElementById('scanBar'), pctEl=document.getElementById('scanPercent');
  const titleEl=document.getElementById('scannerTitle');
  let stepIdx=0;
  const tick = setInterval(async () => {
    if (stepIdx >= SCAN_STEPS.length) { clearInterval(tick); onComplete(); return; }
    const proceed = await onStep(stepIdx, SCAN_STEPS.length);
    if (!proceed) { clearInterval(tick); return; }
    const s = SCAN_STEPS[stepIdx];
    bar.style.width=s.pct+'%'; pctEl.textContent=s.pct+'%';
    titleEl.textContent=SCAN_TITLES[stepIdx]||'SCANNING';
    logToScanner(s.msg, s.cls); stepIdx++;
  }, 320);
}

function logToScanner(msg, cls) {
  const logEl=document.getElementById('scannerLog');
  const line=document.createElement('div');
  line.textContent=msg; line.className=`term-line ${cls}`;
  logEl.appendChild(line); logEl.scrollTop=logEl.scrollHeight;
}

/* ════════════════════════════════════════════
   RENDER RESULTS (master)
═══════════════════════════════════════════ */
function renderResults(data) {
  const sec = document.getElementById('resultsSection');
  sec.classList.remove('hidden');
  sec.scrollIntoView({ behavior: 'smooth', block: 'start' });

  renderVerdictBar(data);
  renderSummaryCards(data);
  renderInfrastructureMap(data.infrastructure_map || []);
  renderWhyRisky(data);
  renderAiConfidence(data.ai_confidence || {});
  renderConfidenceMeter(data);
  renderRiskGauge(data.risk_score, data.risk_level);
  renderRiskBreakdown(data.risk_breakdown || {});
  renderRiskFactors(data.explanation || []);
  renderAttackSurface(data.attack_surface || {});
  renderOriginDiscovery(data.origin_discovery || {});
  renderAsnMismatch(data.asn_analysis || {});
  renderRedirectChain(data.redirect_chain || {});
  renderTerminal(data);
  renderIpHistory(data.ip_history || []);
  renderOsintSim(data.osint_simulation || {});
  renderSslHttp(data.ssl_analysis || {}, data.http_analysis || {});
  renderWhois(data.whois || {});
  renderGeoIp(data.geo_analysis || {}, data.threat_region || {});
  renderUrlAnalysis(data.url_analysis || {}, data.lookalike || {});
  renderThreatIntel(data.threat_intel || {});
  renderBreakdown(data.score_breakdown || {});
  updateDashboard(data);
  renderV8Modules(data);
}

/* ════════════════════════════════════════════
   VERDICT BAR
═══════════════════════════════════════════ */
function renderVerdictBar(data) {
  document.getElementById('traceId').textContent      = data.trace_id  || '—';
  document.getElementById('reportIdBadge').textContent = data.report_id || '—';
  document.getElementById('scanTs').textContent        = data.scan_timestamp || '—';
  const v = data.verdict || {};
  const badge = document.getElementById('verdictBadge');
  badge.textContent = v.badge || v.status || '—';
  badge.className   = 'verdict-status-badge';
  const s = (v.status||'').toLowerCase().replace(' ','');
  if (s==='safe') badge.classList.add('safe');
  else if (s==='suspicious') badge.classList.add('suspicious');
  else badge.classList.add('high-risk');
  document.getElementById('verdictConf').textContent = `Confidence: ${v.confidence||'—'}%`;
}

/* ════════════════════════════════════════════
   SUMMARY CARDS
═══════════════════════════════════════════ */
function renderSummaryCards(data) {
  document.getElementById('resDomain').textContent = data.domain;
  document.getElementById('resIPs').innerHTML = data.ip_addresses?.length
    ? data.ip_addresses.map(ip => `<a href="#" class="ip-link" style="color:var(--cyan);text-decoration:underline;cursor:pointer;" onclick="resolveIp('${ip}'); return false;">${ip}</a>`).join(' &middot; ') : 'Resolution failed';


  const proxyVal=document.getElementById('resProxy'), proxySub=document.getElementById('resProxyProvider');
  const proxyIcon=document.getElementById('proxyIcon');
  if (data.proxy_detected) {
    proxyVal.textContent='PROXY ACTIVE'; proxyVal.className='card-value proxy-yes';
    proxyIcon.textContent='🔴'; proxySub.textContent=data.proxy_provider||'Unknown';
  } else if (data.cdn_detected) {
    proxyVal.textContent='CDN LAYER'; proxyVal.className='card-value risk-medium';
    proxyIcon.textContent='🟡'; proxySub.textContent=data.cdn_provider||'Unknown CDN';
  } else {
    proxyVal.textContent='DIRECT HOST'; proxyVal.className='card-value proxy-no';
    proxyIcon.textContent='🟢'; proxySub.textContent='No proxy detected';
  }

  document.getElementById('resHosting').textContent   = data.real_hosting || '—';
  document.getElementById('resConfidence').textContent = `Confidence: ${data.confidence}%`;
  const possEl = document.getElementById('resPossibleHosting');
  if (data.possible_hosting) {
    possEl.textContent='Possible: '+data.possible_hosting; possEl.className='card-sub possible-hosting-hint';
  } else { possEl.textContent=''; }

  const riskLvl=document.getElementById('resRiskLevel');
  riskLvl.textContent=data.risk_level||'—';
  riskLvl.className=`card-value risk-${(data.risk_level||'').toLowerCase()}`;
  document.getElementById('resRiskScore').textContent=`Score: ${data.risk_score}/100`;

  // AI confidence card
  const ai = data.ai_confidence || {};
  document.getElementById('resAiConf').textContent = `${ai.ai_confidence_pct||0}%`;
  document.getElementById('resInfraPattern').textContent = ai.infrastructure_pattern || '—';
}

/* ════════════════════════════════════════════
   IP RESOLUTION FLOW (NEW)
═══════════════════════════════════════════ */
async function resolveIp(ip) {
  try {
    const res = await fetch(`${API_BASE}/resolve-ip?ip=${encodeURIComponent(ip)}`);
    const data = await res.json();
    
    if (data.status === 'SUCCESS' && data.redirect_url) {
      window.open(data.redirect_url, '_blank');
    } else if (data.status === 'PARTIAL' && data.shared_infrastructure) {
      alert(`[SHARED INFRASTRUCTURE PROTECTED]\n\nIP: ${data.ip}\nResolution Method: ${data.resolution_method}\nNote: ${data.note}\n\nCannot redirect directly using IP. Please perform domain-level navigation.`);
    } else {
      alert(`[NO DOMAIN DIRECTLY FOUND]\n\nIP: ${data.ip}\nStatus: ${data.status}\nNote: ${data.note}`);
    }
  } catch (e) {
    alert("Error communicating with resolution backend: " + e.message);
  }
}


/* ════════════════════════════════════════════
   INFRASTRUCTURE MAP  (NEW 🔥)
═══════════════════════════════════════════ */
function renderInfrastructureMap(nodes) {
  const container = document.getElementById('infraMapContainer');
  if (!nodes.length) { container.innerHTML='<div class="infra-empty">No infrastructure data available</div>'; return; }

  const typeColors = {
    user:'#00eaff', proxy:'#ff4f6d', cdn:'#ffd166',
    origin_leaked:'#ff9a3c', origin_hidden:'#bc5af7', direct:'#00ff9f'
  };

  let html = '<div class="infra-map">';
  nodes.forEach((n, i) => {
    const col = typeColors[n.type] || '#00eaff';
    html += `<div class="infra-node" style="--node-color:${col}">
      <div class="infra-node-icon">${n.node.split(' ')[0]}</div>
      <div class="infra-node-label">${escapeHtml(n.node.replace(/^.\s/,''))}</div>
      <div class="infra-node-note">${escapeHtml(n.note||'')}</div>
      ${n.ips ? `<div class="infra-node-ips">${n.ips.map(ip=>`<span class="ip-pill">${ip}</span>`).join('')}</div>` : ''}
    </div>`;
    if (i < nodes.length - 1) {
      html += `<div class="infra-arrow"><span>→</span></div>`;
    }
  });
  html += '</div>';
  container.innerHTML = html;
}

/* ════════════════════════════════════════════
   WHY RISKY  (Gemini AI — Explainable Output)
═══════════════════════════════════════════ */
function renderWhyRisky(data) {
  const p = document.getElementById('riskReason');
  if (!p) return;

  const riskData = data.risk_reason;
  
  if (!riskData || !riskData.title || !Array.isArray(riskData.points) || riskData.points.length === 0) {
    p.innerText = 'No risk factors analyzed yet.';
    p.style.color = 'var(--cyan)';
    return;
  }

  p.innerHTML = '';
  
  const title = riskData.title;
  const pointsList = riskData.points;

  const header = document.createElement('h3');
  header.innerText = title;
  header.style.marginBottom = '12px';
  header.style.fontSize = '1.1em';
  header.style.fontWeight = 'bold';
  
  // Decide color intuitively
  if (title.toUpperCase().includes('SAFE')) {
    header.style.color = '#00ff9f'; // Green
    p.style.color = '#00ff9f';
  } else {
    header.style.color = '#ff4f6d'; // Red
    p.style.color = '#ff4f6d';
  }

  p.appendChild(header);

  const ul = document.createElement('ul');
  ul.style.listStyleType = 'disc';
  ul.style.paddingLeft = '20px';
  ul.style.marginTop = '10px';
  ul.style.textAlign = 'left';

  pointsList.forEach(text => {
    const li = document.createElement('li');
    li.style.marginBottom = '8px';
    li.style.lineHeight = '1.4';
    li.innerText = text;
    ul.appendChild(li);
  });

  p.appendChild(ul);
}


/* ════════════════════════════════════════════
   AI CONFIDENCE MODULE  (NEW)
═══════════════════════════════════════════ */
function renderAiConfidence(ai) {
  const pct  = ai.ai_confidence_pct || 0;
  const color = pct >= 75 ? '#ff4f6d' : pct >= 50 ? '#ffd166' : '#00ff9f';

  // Animate ring via CSS custom property
  const ring = document.getElementById('aiRing');
  ring.style.setProperty('--ai-pct', pct);
  ring.style.setProperty('--ai-color', color);
  ring.style.background = `conic-gradient(${color} ${pct*3.6}deg, rgba(0,234,255,0.08) 0deg)`;

  setTimeout(() => {
    document.getElementById('aiRingPct').textContent = pct + '%';
    document.getElementById('aiRingPct').style.color = color;
  }, 300);

  const pat = document.getElementById('aiPatternBadge');
  pat.textContent  = ai.infrastructure_pattern || '—';
  pat.style.color  = color;
  pat.style.borderColor = color;

  document.getElementById('aiSummary').textContent = ai.summary || '—';

  const signals = document.getElementById('aiSignals');
  signals.innerHTML = (ai.ai_explanation || []).map(s =>
    `<div class="ai-signal-item">⬡ ${escapeHtml(s)}</div>`
  ).join('');
}

/* ════════════════════════════════════════════
   ORIGIN DISCOVERY  (NEW 🔥)
═══════════════════════════════════════════ */
function renderOriginDiscovery(od) {
  const el = document.getElementById('originContent');
  const ips  = od.possible_origin_ips || [];
  const conf = od.confidence || 'Low';
  const confColor = { High:'#ff4f6d', Medium:'#ffd166', Low:'#00ff9f' }[conf] || '#00eaff';
  const leaks = (od.subdomain_leaks || []).filter(l => !l.is_proxy);

  let html = `<div class="origin-header">
    <div class="origin-stat"><span class="os-label">SUBDOMAINS CHECKED</span><span class="os-val">${od.subdomains_checked||0}</span></div>
    <div class="origin-stat"><span class="os-label">ORIGIN IPs FOUND</span><span class="os-val ${ips.length?'val-warn':''}">${ips.length}</span></div>
    <div class="origin-stat"><span class="os-label">CONFIDENCE</span><span class="os-val" style="color:${confColor}">${conf}</span></div>
    <div class="origin-stat"><span class="os-label">INFRASTRUCTURE TYPE</span><span class="os-val" style="color:var(--cyan)">${od.proxy_detected ? 'CDN Protected' : (ips.length > 1 ? 'Enterprise Distributed' : 'Single Host')}</span></div>
  </div>`;

  if (ips.length) {
    html += `<div class="origin-ips"><div class="origin-label">🎯 POSSIBLE ORIGIN IP(S)</div>${ips.map(ip=>`<span class="origin-ip-pill">${ip}</span>`).join('')}</div>`;
  }

  if (leaks.length) {
    html += `<div class="origin-leaks"><div class="origin-label">⚠ SUBDOMAIN LEAKS (non-proxy IPs)</div>`;
    leaks.slice(0,6).forEach(l => {
      html += `<div class="leak-row"><span class="leak-sub">${escapeHtml(l.subdomain)}</span><span class="leak-ip">${l.ip}</span><span class="leak-note">${escapeHtml(l.note)}</span></div>`;
    });
    html += `</div>`;
  } else if (!od.origin_suspected) {
    html += `<div class="origin-clean">✓ No origin IP leaks detected through subdomain enumeration</div>`;
  }

  el.innerHTML = html;
}

/* ════════════════════════════════════════════
   ASN MISMATCH  (NEW)
═══════════════════════════════════════════ */
function renderAsnMismatch(asn) {
  const el = document.getElementById('asnContent');
  const mismatch = asn.mismatch_detected;
  let html = `<div class="asn-grid">
    <div class="asn-card">
      <div class="asn-label">PROXY LAYER</div>
      <div class="asn-val">${escapeHtml(asn.proxy_provider||'—')}</div>
    </div>
    <div class="asn-arrow">⟶</div>
    <div class="asn-card ${mismatch?'asn-mismatch':''}">
      <div class="asn-label">ORIGIN ASN</div>
      <div class="asn-val">${escapeHtml(asn.origin_asn_provider||'Unknown')}</div>
    </div>
  </div>`;

  if (mismatch) {
    html += `<div class="mismatch-alert">⚡ MISMATCH DETECTED<div class="mismatch-note">${escapeHtml(asn.mismatch_note||'')}</div></div>`;
  } else {
    html += `<div class="asn-clean">✓ ${asn.proxy_provider?'Proxy and origin provider appear consistent':'No mismatch detected'}</div>`;
  }

  if ((asn.origin_asn_providers||[]).length > 1) {
    html += `<div class="asn-multi">Multiple origin providers detected: ${asn.origin_asn_providers.join(', ')}</div>`;
  }
  el.innerHTML = html;
}

/* ════════════════════════════════════════════
   REDIRECT CHAIN  (NEW)
═══════════════════════════════════════════ */
function renderRedirectChain(rc) {
  const el = document.getElementById('redirectContent');
  const chain = rc.chain || [];
  const suspicious = rc.suspicious;

  let html = `<div class="redirect-stats">
    <span class="rs-item">Total Hops: <b>${rc.total_hops||0}</b></span>
    <span class="rs-item">Redirects: <b style="color:${suspicious?'#ff4f6d':'#00ff9f'}">${rc.redirect_count||0}</b></span>
    <span class="rs-item ${suspicious?'rs-warn':'rs-ok'}">${suspicious?'⚠ SUSPICIOUS':'✓ NORMAL'}</span>
  </div>`;

  if (chain.length) {
    html += `<div class="redirect-chain">`;
    chain.forEach(hop => {
      const statusColor = hop.status >= 300 && hop.status < 400 ? '#ffd166'
        : hop.status >= 200 && hop.status < 300 ? '#00ff9f' : '#ff4f6d';
      html += `<div class="rchain-hop">
        <span class="rchain-num">${hop.hop}</span>
        <span class="rchain-url">${escapeHtml((hop.url||'').slice(0,60))}${(hop.url||'').length>60?'…':''}</span>
        <span class="rchain-status" style="color:${statusColor}">${hop.status}</span>
        ${hop.final?'<span class="rchain-final">FINAL</span>':'<span class="rchain-arrow">→</span>'}
      </div>`;
    });
    html += `</div>`;
  } else {
    html += `<div class="redirect-none">✓ No redirects detected — direct connection</div>`;
  }
  el.innerHTML = html;
}

/* ════════════════════════════════════════════
   OSINT SIMULATION
═══════════════════════════════════════════ */
function renderOsintSim(osint) {
  const el = document.getElementById('osintSim');
  if (!osint || !osint.records) { el.innerHTML=''; return; }
  const expColor = osint.exposure_detected ? '#ffd166' : '#00ff9f';
  let html = `<div class="osint-header" style="color:${expColor}">${escapeHtml(osint.exposure_note||'')}</div>
  <div class="osint-records">`;
  (osint.records||[]).forEach(r => {
    html += `<div class="osint-row">
      <span class="osint-date">${r.date}</span>
      <span class="osint-ip">${r.ip}</span>
      <span class="osint-prov">${escapeHtml(r.provider)}</span>
      <span class="osint-type">${escapeHtml(r.type)}</span>
    </div>`;
  });
  html += '</div>';
  el.innerHTML = html;
}

/* ════════════════════════════════════════════
   CONFIDENCE METER
═══════════════════════════════════════════ */
function renderConfidenceMeter(data) {
  document.getElementById('confProvider').textContent = data.real_hosting || '—';
  setTimeout(() => {
    document.getElementById('meterFill').style.width  = data.confidence + '%';
    document.getElementById('meterValue').textContent = data.confidence + '%';
  }, 200);
}

/* ════════════════════════════════════════════
   BREAKDOWN BARS
═══════════════════════════════════════════ */
function renderBreakdown(scores) {
  const container = document.getElementById('breakdownList');
  container.innerHTML = '';
  const maxVal = Math.max(...Object.values(scores), 1);
  const colors = ['#00ff9f','#00eaff','#bc5af7','#ffd166','#ff4f6d','#ff9a3c','#00ff9f','#00eaff','#bc5af7','#ffd166'];
  let i = 0;
  for (const [provider, score] of Object.entries(scores)) {
    if (score === 0) { i++; continue; }
    const pct=Math.round((score/maxVal)*100), color=colors[i%colors.length];
    const item=document.createElement('div'); item.className='breakdown-item';
    item.innerHTML=`<span class="breakdown-name">${provider}</span>
      <div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:0%;background:${color}" data-target="${pct}"></div></div>
      <span class="breakdown-score">${score}</span>`;
    container.appendChild(item); i++;
  }
  setTimeout(() => {
    container.querySelectorAll('.breakdown-bar').forEach(b => { b.style.width=b.dataset.target+'%'; });
  }, 300);
}

/* ════════════════════════════════════════════
   RISK GAUGE
═══════════════════════════════════════════ */
function renderRiskGauge(score, level) {
  const ctx = document.getElementById('riskGauge').getContext('2d');
  if (riskChart) { riskChart.destroy(); }
  const colorMap = { Low:'#00ff9f', Medium:'#ffd166', High:'#ff4f6d' };
  const color    = colorMap[level] || '#00eaff';
  riskChart = new Chart(ctx, {
    type: 'doughnut',
    data: { datasets: [{ data:[score,100-score],
      backgroundColor:[color,'rgba(0,234,255,0.06)'],
      borderColor:[color,'rgba(0,234,255,0.06)'], borderWidth:2, hoverOffset:4 }] },
    options: { cutout:'72%', animation:{animateRotate:true,duration:1000},
      plugins:{legend:{display:false},tooltip:{enabled:false}} },
    plugins: [{ id:'centerText', afterDraw(chart) {
      const {ctx:c,width:w,height:h}=chart; c.save();
      c.font=`bold 22px "Orbitron",sans-serif`; c.fillStyle=color;
      c.textAlign='center'; c.textBaseline='middle';
      c.fillText(score,w/2,h/2-10);
      c.font=`9px "Share Tech Mono",monospace`; c.fillStyle='#4a7a9b';
      c.fillText('RISK SCORE',w/2,h/2+12); c.restore();
    }}],
  });
}

/* ════════════════════════════════════════════
   RISK BREAKDOWN GRID  (v4.0 — new weights)
═══════════════════════════════════════════ */
function renderRiskBreakdown(rb) {
  const grid = document.getElementById('riskBreakdownGrid');
  const items = [
    { label:'PROXY RISK',      key:'proxy_risk' },
    { label:'HIDDEN ORIGIN',   key:'hidden_origin' },
    { label:'BLACKLIST',       key:'blacklist_hits' },
    { label:'SUSP. TLD',       key:'suspicious_tld' },
    { label:'NEW DOMAIN',      key:'new_domain' },
    { label:'LOGIN KW',        key:'login_keywords' },
    { label:'REDIRECTS',       key:'redirect_chain' },
    { label:'GEO MISMATCH',    key:'geo_mismatch' },
    { label:'HOST MISMATCH',   key:'hosting_mismatch' },
    { label:'CLEAN INTEL',     key:'clean_threat_intel' },
  ];
  grid.innerHTML = items.map(({ label, key }) => {
    const val = rb[key] || 0;
    const cls = val > 0 ? 'rbi-positive' : val < 0 ? 'rbi-negative' : 'rbi-neutral';
    return `<div class="risk-breakdown-item">
      <div class="rbi-label">${label}</div>
      <div class="rbi-value ${cls}">${val>0?'+':''}${val}</div>
    </div>`;
  }).join('');
}

/* ════════════════════════════════════════════
   RISK FACTORS
═══════════════════════════════════════════ */
function renderRiskFactors(items) {
  const el = document.getElementById('riskFactors');
  el.innerHTML = items.slice(0,8).map(f => `<div class="risk-factor-item">${escapeHtml(f)}</div>`).join('');
}

/* ════════════════════════════════════════════
   ATTACK SURFACE
═══════════════════════════════════════════ */
function renderAttackSurface(atk) {
  const grid = document.getElementById('atkSurfaceGrid');
  const layers = [
    { icon:'🛡', title:'PROXY LAYER',      data: atk.proxy_layer },
    { icon:'🌐', title:'DNS STRENGTH',     data: atk.dns_strength },
    { icon:'👣', title:'THREAT FOOTPRINT', data: atk.threat_footprint },
    { icon:'📡', title:'EXPOSURE LEVEL',   data: atk.exposure_level },
  ];
  grid.innerHTML = layers.map(({ icon, title, data }) => {
    if (!data) return '';
    const riskCls = (data.risk||'MEDIUM').toLowerCase();
    return `<div class="atk-item">
      <div class="atk-icon">${icon}</div>
      <div class="atk-text">
        <div class="atk-title">${title}</div>
        <div class="atk-detail">${escapeHtml(data.detail||'—')}</div>
      </div>
      <div class="atk-badge atk-${riskCls}">${data.status||'—'}</div>
    </div>`;
  }).join('');
}

/* ════════════════════════════════════════════
   TERMINAL OUTPUT  (v4.0 — new fields)
═══════════════════════════════════════════ */
function renderTerminal(data) {
  const body = document.getElementById('terminalBody');
  body.innerHTML = '';
  const ssl=data.ssl_analysis||{}, http=data.http_analysis||{};
  const geo=data.geo_analysis||{}, url=data.url_analysis||{};
  const v=data.verdict||{}, od=data.origin_discovery||{};
  const asn=data.asn_analysis||{}, rc=data.redirect_chain||{};
  const ai=data.ai_confidence||{};

  const lines = [
    { cls:'header',  text:`══════ HostTrace AI v4.0 — ${data.domain} ══════` },
    { cls:'info',    text:`> Trace ID        : ${data.trace_id||'—'}` },
    { cls:'info',    text:`> Report ID       : ${data.report_id||'—'}` },
    { cls:'info',    text:`> Scan Timestamp  : ${data.scan_timestamp}` },
    { cls:'info',    text:`> IP Addresses    : ${(data.ip_addresses||[]).join(', ')||'N/A'}` },
    { cls:data.proxy_detected?'danger':'success',
      text:`> Proxy/CDN Layer : ${data.proxy_detected?'Detected — '+data.proxy_provider:'Not Detected'}` },
    { cls:data.cdn_detected?'warn':'info',
      text:`> CDN Detected    : ${data.cdn_detected?'YES — '+data.cdn_provider:'NO'}` },
    { cls:'success', text:`> Real Hosting    : ${data.real_hosting} (${data.confidence}% conf.)` },
    data.possible_hosting?{ cls:'warn', text:`> Possible Host   : ${data.possible_hosting}` }:null,
    { cls:'header',  text:'─────── 🔥 ORIGIN DISCOVERY ───────' },
    { cls:'info',
      text:`> Infra Type      : ${data.proxy_detected ? 'CDN Protected' : (data.ip_addresses?.length > 1 ? 'Enterprise Distributed' : 'Single Host')} (Confidence: ${od.confidence||'—'})` },
    { cls:od.origin_suspected?'warn':'info',
      text:`> Possible IPs    : ${(od.possible_origin_ips||[]).join(', ')||'None found'}` },
    { cls:'info',    text:`> Subdomains Scan : ${od.subdomains_checked||0} checked` },
    { cls:'header',  text:'─────── ASN ANALYSIS ───────' },
    { cls:asn.mismatch_detected?'danger':'success',
      text:`> Mismatch        : ${asn.mismatch_detected?'YES ⚠ '+asn.mismatch_note:'NO — consistent'}` },
    { cls:'info',    text:`> Proxy Layer     : ${asn.proxy_provider||'—'}` },
    { cls:'info',    text:`> Origin ASN      : ${asn.origin_asn_provider||'Unknown'}` },
    { cls:'header',  text:'─────── REDIRECT CHAIN ───────' },
    { cls:rc.suspicious?'danger':'success',
      text:`> Redirects       : ${rc.redirect_count||0} hops ${rc.suspicious?'⚠ SUSPICIOUS':'✓ Normal'}` },
    { cls:'header',  text:'─────── AI CONFIDENCE ───────' },
    { cls:'info',    text:`> AI Confidence   : ${ai.ai_confidence_pct||0}%` },
    { cls:'info',    text:`> Infra Pattern   : ${ai.infrastructure_pattern||'—'}` },
    { cls:'header',  text:'─────── SSL ANALYSIS ───────' },
    { cls:ssl.ssl_valid?'success':'danger',
      text:`> SSL Valid       : ${ssl.ssl_valid?'YES':'NO'}` },
    { cls:ssl.ssl_expired?'danger':'info',
      text:`> SSL Expired     : ${ssl.ssl_expired?'YES ⚠':'NO'}` },
    { cls:'info',    text:`> SSL Grade       : ${ssl.grade||'N/A'} | Expires: ${ssl.valid_until||'?'}` },
    { cls:'header',  text:'─────── VERDICT ───────' },
    { cls:v.status==='SAFE'?'success':v.status==='HIGH RISK'?'danger':'warn',
      text:`> Final Status    : ${v.badge||v.status||'—'} (${v.confidence||0}% confidence)` },
    { cls:'info',    text:`> ${v.note||''}` },
    { cls:'success', text:'> Analysis complete ✓' },
  ].filter(Boolean);

  let i=0;
  const cursor=document.createElement('span'); cursor.className='term-cursor';
  function addLine() {
    if (i>=lines.length) { body.appendChild(cursor); return; }
    const div=document.createElement('div');
    div.className=`term-line ${lines[i].cls}`; div.textContent=lines[i].text;
    body.appendChild(div); body.scrollTop=body.scrollHeight;
    i++; setTimeout(addLine, 30);
  }
  addLine();
}

/* ════════════════════════════════════════════
   IP HISTORY CHART
═══════════════════════════════════════════ */
function renderIpHistory(history) {
  const ctx = document.getElementById('ipHistoryChart').getContext('2d');
  if (ipChart) { ipChart.destroy(); }
  const labels=history.map(h=>h.timestamp), ips=history.map(h=>h.ip);
  const ipSet=[...new Set(ips)], dataVals=ips.map(ip=>ipSet.indexOf(ip)+1);
  ipChart = new Chart(ctx, {
    type:'line',
    data:{ labels, datasets:[{ label:'IP Change Events', data:dataVals,
      borderColor:'#00eaff', backgroundColor:'rgba(0,234,255,0.06)',
      pointBackgroundColor:'#00ff9f', pointRadius:5, fill:true, tension:0.4, borderWidth:2 }] },
    options:{ responsive:true, maintainAspectRatio:true, animation:{duration:1000},
      scales:{
        x:{ticks:{color:'#4a7a9b',font:{family:'Share Tech Mono',size:10}},grid:{color:'rgba(0,234,255,0.05)'}},
        y:{ticks:{color:'#4a7a9b',font:{family:'Share Tech Mono',size:10},stepSize:1,
           callback:(v)=>ips[v-1]||v},grid:{color:'rgba(0,234,255,0.05)'}}},
      plugins:{ legend:{display:false},
        tooltip:{ backgroundColor:'rgba(4,20,36,0.95)', titleColor:'#00eaff',
          bodyColor:'#c8e4f0', callbacks:{label:(ctx)=>` IP: ${ips[ctx.dataIndex]}`} } } },
  });
}

/* ════════════════════════════════════════════
   SSL / HTTP PANEL
═══════════════════════════════════════════ */
function renderSslHttp(ssl, http) {
  const grid=document.getElementById('sslHttpGrid');
  const sslGrade=ssl.grade||'N/A';
  const gc={ A:'ssl-val-ok',B:'ssl-val-ok',C:'ssl-val-warn',F:'ssl-val-bad','N/A':'ssl-val-warn' }[sslGrade]||'ssl-val-warn';
  const httpScore=http.security_score??null;
  const httpCls=httpScore>=70?'ssl-val-ok':httpScore>=40?'ssl-val-warn':'ssl-val-bad';
  const present=http.present_security_headers||[], missing=http.missing_security_headers||[];
  const allHdrs=[...present.map(h=>({h,ok:true})),...missing.map(h=>({h,ok:false}))];
  grid.innerHTML=`
    <div class="ssl-card">
      <div class="ssl-card-title">SSL / TLS</div>
      <div class="ssl-stat"><span>Valid</span><span class="${ssl.ssl_valid?'ssl-val-ok':'ssl-val-bad'}">${ssl.ssl_valid?'YES ✓':'NO ✗'}</span></div>
      <div class="ssl-stat"><span>Expired</span><span class="${ssl.ssl_expired?'ssl-val-bad':'ssl-val-ok'}">${ssl.ssl_expired?'YES ⚠':'NO ✓'}</span></div>
      <div class="ssl-stat"><span>Self-signed</span><span class="${ssl.self_signed?'ssl-val-bad':'ssl-val-ok'}">${ssl.self_signed?'YES ⚠':'NO ✓'}</span></div>
      <div class="ssl-stat"><span>Expires</span><span>${ssl.valid_until||'Unknown'}</span></div>
      <div class="ssl-stat"><span>Grade</span><span class="${gc}">${sslGrade}</span></div>
    </div>
    <div class="ssl-card">
      <div class="ssl-card-title">HTTP SECURITY</div>
      <div class="ssl-stat"><span>Server</span><span>${escapeHtml(http.server||'?')}</span></div>
      <div class="ssl-stat"><span>Security Score</span><span class="${httpCls}">${httpScore!=null?httpScore+'%':'N/A'}</span></div>
      <div class="ssl-stat"><span>HSTS</span><span class="${http.hsts?'ssl-val-ok':'ssl-val-bad'}">${http.hsts?'✓':'✗ Missing'}</span></div>
      <div class="ssl-stat"><span>CSP</span><span class="${http.csp?'ssl-val-ok':'ssl-val-bad'}">${http.csp?'✓':'✗ Missing'}</span></div>
      <div class="ssl-stat"><span>CDN via Header</span><span>${escapeHtml(http.cdn_via_header||'None')}</span></div>
      <div class="header-tags">${allHdrs.map(({h,ok})=>`<span class="htag ${ok?'present':'missing'}">${h}</span>`).join('')}</div>
    </div>`;
}

/* ════════════════════════════════════════════
   WHOIS TABLE
═══════════════════════════════════════════ */
function renderWhois(w) {
  const tbl=document.getElementById('whoisTable');
  const rows=[
    ['Registrar',w.registrar||'—'],['Org',w.org||'—'],['Country',w.country||'—'],
    ['Created',w.creation_date||'—'],['Expires',w.expiry_date||'—'],
    ['DNSSEC',w.dnssec||'—'],['Name Servers',(w.name_servers||[]).join('\n')||'—'],
  ];
  tbl.innerHTML=rows.map(([k,v])=>`<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join('');
}

/* ════════════════════════════════════════════
   GEO-IP
═══════════════════════════════════════════ */
function renderGeoIp(geo, region) {
  const el=document.getElementById('geoInfo');
  const flags={US:'🇺🇸',GB:'🇬🇧',DE:'🇩🇪',FR:'🇫🇷',CN:'🇨🇳',RU:'🇷🇺',IN:'🇮🇳',JP:'🇯🇵',
    BR:'🇧🇷',CA:'🇨🇦',AU:'🇦🇺',SG:'🇸🇬',NL:'🇳🇱',KP:'🇰🇵',IR:'🇮🇷',NG:'🇳🇬',BY:'🇧🇾',UA:'🇺🇦'};
  const flag=flags[geo.country_code]||'🌍';
  let flaggedHtml = '';
  if (region && region.risk_level) {
    let col = region.risk_level.includes('High') ? 'var(--accent-magenta)' : 'var(--green)';
    flaggedHtml = `<div style="margin-top:8px; font-size:12px; font-family:'Share Tech Mono';">Threat Region: <span style="color:${col};">${region.risk_level}</span></div>`;
  }
  if (!flaggedHtml) {
      flaggedHtml=geo.is_flagged_region
        ?`<div class="geo-flagged">⚠ ${escapeHtml(geo.risk_note||'Flagged region')}</div>`
        :`<div class="geo-clean">✓ Geographic origin within normal parameters</div>`;
  }
  el.innerHTML=`<div class="geo-country">
    <div class="geo-flag">${flag}</div>
    <div><div class="geo-country-name">${escapeHtml(geo.primary_country||'Unknown')}</div>
    <div class="geo-country-code">${geo.country_code||'?'} · ${geo.geo_source||'WHOIS'}</div></div>
  </div>${flaggedHtml}`;
}

/* ════════════════════════════════════════════
   URL ANALYSIS
═══════════════════════════════════════════ */
function renderUrlAnalysis(url, lookalike) {
  const el=document.getElementById('urlInfo');
  const score=url.phishing_score||0;
  const scoreColor=score>=60?'var(--red)':score>=30?'var(--yellow)':'var(--green)';
  const flags=url.flags||[];
  let lHtml = '';
  if (lookalike && lookalike.is_lookalike) {
      lHtml = `<div class="url-stat-row" style="color:var(--accent-magenta); font-weight:bold; margin-top:8px;">[!] LOOK-ALIKE MATCH: ${lookalike.matched_domain} (${lookalike.similarity_score}%)</div>`;
  } else if (lookalike && lookalike.matched_domain !== "None") {
      lHtml = `<div class="url-stat-row" style="color:var(--yellow); font-weight:bold; margin-top:8px;">Anti-Phishing Match: ${lookalike.matched_domain}</div>`;
  }
  
  el.innerHTML=`
    <div class="url-stat-row"><span>URL Length</span><span>${url.url_length||0} chars</span></div>
    <div class="url-stat-row"><span>TLD</span><span style="color:${url.suspicious_tld?'var(--red)':'var(--green)'}">${url.tld||'N/A'} ${url.suspicious_tld?'⚠':''}</span></div>
    <div class="url-stat-row"><span>Subdomain Depth</span><span>${url.subdomain_depth||0}</span></div>
    <div class="url-stat-row"><span>Phishing Score</span><span style="color:${scoreColor};font-weight:700">${score}/100</span></div>
    <div class="phishing-score-bar"><div class="phishing-score-fill" style="width:${score}%"></div></div>
    ${flags.length?`<div class="url-flags">${flags.map(f=>`<div class="url-flag-item">${escapeHtml(f)}</div>`).join('')}</div>`:''}${lHtml}`;
}

/* ════════════════════════════════════════════
   THREAT INTEL
═══════════════════════════════════════════ */
function renderThreatIntel(t) {
  const vt=t.virustotal_flags||0, blk=t.blacklist_hits||0;
  document.getElementById('vtNum').textContent=vt;
  document.getElementById('blNum').textContent=blk;
  setTimeout(()=>{
    document.getElementById('vtBar').style.width=Math.min(100,vt*10)+'%';
    document.getElementById('blBar').style.width=Math.min(100,blk*15)+'%';
  },400);
  const total=vt+blk;
  let txt,col;
  if(total===0){txt='✅ Clear — No threats detected';col='#00ff9f';}
  else if(total<=3){txt='⚠ Low threat signals found';col='#ffd166';}
  else{txt='🚨 HIGH THREAT — Multiple detections!';col='#ff4f6d';}
  const el=document.getElementById('threatStatus');
  el.textContent=txt; el.style.color=col;
  if(vt>5)document.getElementById('vtNum').style.color='#ff4f6d';
  else if(vt>0)document.getElementById('vtNum').style.color='#ffd166';
  if(blk>3)document.getElementById('blNum').style.color='#ff4f6d';
  else if(blk>0)document.getElementById('blNum').style.color='#ffd166';
}

/* ════════════════════════════════════════════
   PDF REPORT  (v4.0 — all new sections)
═══════════════════════════════════════════ */
async function downloadReport() {
  if (!currentReport) { alert('Run a scan first!'); return; }
  try {
    const payload = {
      ...currentReport,
      scan_history: globalScanHistory,
      input_url: document.getElementById('domainInput').value.trim()
    };
    const res = await fetch(`${API_BASE}/download-pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
        const text = await res.text();
        alert('Failed to generate PDF: ' + text);
        return;
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = `HostTrace_Report_${currentReport.domain}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
  } catch (err) {
    alert('Error generating PDF: ' + err.message);
  }
}

/* ════════════════════════════════════════════
   WORD REPORT DOWNLOAD
═══════════════════════════════════════════ */
async function downloadWord() {
  if (!currentReport) { alert('Run a scan first!'); return; }
  const status = document.getElementById('reportStatusMsg');
  status.textContent = '⟳ Generating Word document…';
  try {
    const payload = {
      ...currentReport,
      scan_history: globalScanHistory,
      input_url: document.getElementById('domainInput').value.trim()
    };
    const res = await fetch(`${API_BASE}/download-word`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const text = await res.text();
      status.textContent = '✗ Failed: ' + text;
      return;
    }
    const blob = await res.blob();
    const url  = window.URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = `HostTrace_Report_${currentReport.domain}.docx`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
    status.textContent = '✔ Word report downloaded!';
    setTimeout(() => { status.textContent = ''; }, 3000);
  } catch (err) {
    status.textContent = '✗ Error: ' + err.message;
  }
}

/* ════════════════════════════════════════════
   TEXT REPORT PREVIEW & DOWNLOAD
═══════════════════════════════════════════ */
let _cachedTextReport = '';

async function previewReport() {
  if (!currentReport) { alert('Run a scan first!'); return; }
  const btn   = document.getElementById('previewReportBtn');
  const status = document.getElementById('reportStatusMsg');
  btn.disabled = true;
  status.textContent = '⟳ Fetching text report…';

  try {
    const payload = {
      ...currentReport,
      scan_history: globalScanHistory,
      input_url: document.getElementById('domainInput').value.trim()
    };
    const res = await fetch(`${API_BASE}/report-text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) { throw new Error(`Server ${res.status}`); }
    const text = await res.text();
    _cachedTextReport = text;

    document.getElementById('textReportContent').textContent = text;
    document.getElementById('textReportModal').classList.remove('hidden');
    status.textContent = '✔ Report ready';
    setTimeout(() => { status.textContent = ''; }, 3000);
  } catch (err) {
    status.textContent = '✗ Error: ' + err.message;
  } finally {
    btn.disabled = false;
  }
}

function closeTextReport() {
  document.getElementById('textReportModal').classList.add('hidden');
}

async function copyTextReport() {
  if (!_cachedTextReport) return;
  try {
    await navigator.clipboard.writeText(_cachedTextReport);
    const btn = document.getElementById('copyReportBtn');
    btn.textContent = '✔ Copied!';
    setTimeout(() => { btn.textContent = '⎘ Copy'; }, 2000);
  } catch { alert('Clipboard copy failed — please select and copy manually.'); }
}

function downloadTextReport() {
  if (!_cachedTextReport) return;
  const blob = new Blob([_cachedTextReport], { type: 'text/markdown;charset=utf-8' });
  const url  = window.URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = `HostTrace_Report_${currentReport?.domain || 'scan'}.md`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  a.remove();
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeTextReport();
});

/* ════════════════════════════════════════════
   UTILITIES
═══════════════════════════════════════════ */
function shakeInput() {
  const box=document.getElementById('searchBox');
  box.style.animation='none'; box.offsetHeight;
  box.style.animation='shake 0.4s ease';
  box.addEventListener('animationend',()=>{box.style.animation='';},{once:true});
}
const shakeStyle=document.createElement('style');
shakeStyle.textContent=`@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-5px)}80%{transform:translateX(5px)}}`;
document.head.appendChild(shakeStyle);

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/\n/g,'<br>');
}

/* ════════════════════════════════════════════
   v7.0 LIVE THREAT DASHBOARD (ML)
═══════════════════════════════════════════ */
let globalScanHistory = [];
let dashPieChart, dashLineChart, dashBarChart;

function updateDashboard(data) {
  const v = data.verdict || {};
  const pred = data.ai_prediction || {};
  const acc = (pred.accuracy || 0).toFixed(1) + '%';
  const confidence = (pred.confidence || 0).toFixed(1) + '%';
  const ml_class = pred.prediction || v.status || 'UNKNOWN';

  // 1. Maintain History
  globalScanHistory.push({
    domain: data.domain,
    risk: data.risk_score || 0,
    pred: ml_class,
    conf: confidence,
    acc: acc
  });
  
  // 2. Render Table
  const tbody = document.getElementById('historyTableBody');
  tbody.innerHTML = globalScanHistory.map(h => {
    let color = h.pred === 'SAFE' ? '#00ff9f' : (h.pred === 'SUSPICIOUS' ? '#ffd166' : '#ff4f6d');
    return `<tr style="border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.2);">
      <td style="padding: 6px;">${h.domain}</td>
      <td style="padding: 6px;">${h.risk}</td>
      <td style="padding: 6px; color: ${color}; font-weight: bold;">${h.pred}</td>
      <td style="padding: 6px;">${h.conf}</td>
      <td style="padding: 6px;">${h.acc}</td>
    </tr>`;
  }).join('');

  // 3. Render Pie Chart (Safe/Susp/Danger Distribution overall)
  const pieCtx = document.getElementById('dashPieChart');
  let safe=0, susp=0, danger=0;
  globalScanHistory.forEach(h => {
    if (h.pred === 'SAFE') safe++;
    else if (h.pred === 'SUSPICIOUS') susp++;
    else danger++;
  });
  if (dashPieChart) dashPieChart.destroy();
  dashPieChart = new Chart(pieCtx, {
    type: 'pie',
    data: {
      labels: ['Safe', 'Suspicious', 'Dangerous'],
      datasets: [{
        data: [safe, susp, danger],
        backgroundColor: ['#00ff9f', '#ffd166', '#ff4f6d'],
        borderWidth: 1, borderColor: '#061624'
      }]
    },
    options: { responsive: true, plugins: { legend: { labels: { color: 'white' } } } }
  });

  // 4. Render Line Chart (Risk Trend)
  const lineCtx = document.getElementById('dashLineChart');
  if (dashLineChart) dashLineChart.destroy();
  dashLineChart = new Chart(lineCtx, {
    type: 'line',
    data: {
      labels: globalScanHistory.map((_, i) => '#' + (i+1)),
      datasets: [{
        label: 'Risk Score Over Time',
        data: globalScanHistory.map(h => h.risk),
        borderColor: '#00eaff',
        backgroundColor: 'rgba(0,234,255,0.1)',
        tension: 0.4, fill: true
      }]
    },
    options: { responsive: true, scales: { y: { min: 0, max: 100, grid: { color: 'rgba(255,255,255,0.1)' } } }, plugins: { legend: { labels: { color: 'white' } } } }
  });

  // 5. Render Bar Chart (Feature Importance for THIS scan)
  const barCtx = document.getElementById('dashBarChart');
  const features = data.features || {};
  if (dashBarChart) dashBarChart.destroy();
  dashBarChart = new Chart(barCtx, {
    type: 'bar',
    data: {
      labels: Object.keys(features),
      datasets: [{
        label: 'Raw Feature Metric',
        data: Object.values(features),
        backgroundColor: '#bc5af7'
      }]
    },
    options: { recursive: true, indexAxis: 'y', scales: { x: { grid: { color: 'rgba(255,255,255,0.1)' } } }, plugins: { legend: { labels: { color: 'white' } } } }
  });
}

/* ════════════════════════════════════════════
   v8.0 DATA RENDERING
═══════════════════════════════════════════ */
function renderV8Modules(data) {
  // 1. Phishing Simulation
  const phish = data.phish_sim || {};
  let phtml = `<div style="font-size:13px; margin-bottom:8px;">Harvesting Behavior Probability: <strong style="color:var(--accent-cyan);">${phish.phishing_probability||0}%</strong></div>`;
  let pcol = phish.behavior_classification === 'HIGH RISK PHISHING' ? 'var(--accent-magenta)' : (phish.behavior_classification === 'SAFE' ? 'var(--green)' : 'var(--yellow)');
  phtml += `<div style="font-weight:bold; color:${pcol};">[ ${phish.behavior_classification || 'UNKNOWN'} ]</div>`;
  document.getElementById('phishSimContent').innerHTML = phtml;

  // 2. Domain DNA
  const dna = data.domain_dna || {};
  let dhtml = `<div style="display:flex; justify-content:space-between; margin-bottom:4px;"><span>Structure:</span> <span>${dna.structure_type||'—'}</span></div>`;
  dhtml += `<div style="display:flex; justify-content:space-between; margin-bottom:4px;"><span>Entropy:</span> <span>${dna.entropy_level||'—'}</span></div>`;
  dhtml += `<div style="display:flex; justify-content:space-between; margin-bottom:4px;"><span>Behavior:</span> <span>${dna.behavioral_pattern||'—'}</span></div>`;
  dhtml += `<hr style="border-color:var(--border); margin:8px 0;"/><div style="display:flex; justify-content:space-between; font-weight:bold;"><span>DNA Score:</span> <span style="color:var(--accent-cyan);">${dna.summary_score||0}/10</span></div>`;
  document.getElementById('dnaContent').innerHTML = dhtml;

  // 3. XAI Explainable AI
  const xai = data.xai_signals || [];
  let xhtml = '';
  xai.forEach(s => {
    let clr = s.signal === 'Positive' ? 'var(--green)' : 'var(--accent-magenta)';
    xhtml += `<div style="border-left: 2px solid ${clr}; padding-left: 10px; margin-bottom: 8px; font-size:12px;">`;
    xhtml += `<div style="color:${clr}; font-weight:bold; font-family:'Share Tech Mono';">${s.feature} [${s.impact}]</div>`;
    xhtml += `<div style="color:var(--muted);">${s.desc}</div>`;
    xhtml += `</div>`;
  });
  if(!xhtml) xhtml = '<div class="muted">No prominent localized features evaluated.</div>';
  document.getElementById('xaiGrid').innerHTML = xhtml;

  // 4. Threat Alerts
  const alerts = data.threat_alerts || [];
  let ahtml = '';
  alerts.forEach(a => {
    let clr = a.level === 'CRITICAL' ? 'var(--accent-magenta)' : (a.level === 'WARNING' ? 'var(--yellow)' : 'var(--accent-cyan)');
    ahtml += `<div style="background:rgba(0,0,0,0.3); border:1px solid ${clr}; padding:8px; margin-bottom:8px; border-radius:4px; font-size:12px;">`;
    ahtml += `<strong style="color:${clr};">${a.level}</strong>: ${a.msg}`;
    ahtml += `</div>`;
  });
  document.getElementById('threatAlertsList').innerHTML = ahtml;
}

