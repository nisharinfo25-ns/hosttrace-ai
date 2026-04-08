/**
 * HostTrace AI – script.js  v3.0
 * Frontend Logic: Scanning, UI, Charts, PDF Export
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

/* ════════════════════════════════════════════
   ENTER KEY SUPPORT
═══════════════════════════════════════════ */
document.getElementById('domainInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startAnalysis();
});

/* ════════════════════════════════════════════
   SCANNER STEPS  (14 steps per requirement)
═══════════════════════════════════════════ */
const SCAN_STEPS = [
  { pct:  7,  msg: '> Initializing OSINT engine…',           cls: 'header'  },
  { pct: 15,  msg: '> Resolving DNS records…',               cls: 'info'    },
  { pct: 23,  msg: '> Querying WHOIS database…',             cls: 'info'    },
  { pct: 31,  msg: '> Checking CIDR ranges…',                cls: 'info'    },
  { pct: 40,  msg: '> Inspecting SSL certificate…',          cls: 'info'    },
  { pct: 49,  msg: '> Analyzing HTTP security headers…',     cls: 'info'    },
  { pct: 57,  msg: '> Mapping IP geolocation…',              cls: 'info'    },
  { pct: 65,  msg: '> Analyzing URL patterns…',              cls: 'warn'    },
  { pct: 73,  msg: '> Scanning proxy indicators…',           cls: 'warn'    },
  { pct: 81,  msg: '> Running AI prediction model…',         cls: 'info'    },
  { pct: 87,  msg: '> Correlating threat intelligence…',     cls: 'warn'    },
  { pct: 92,  msg: '> Calculating risk score…',              cls: 'warn'    },
  { pct: 97,  msg: '> Generating forensic trace ID…',        cls: 'success' },
  { pct: 100, msg: '> Finalising forensic report…',          cls: 'success' },
];

const SCAN_TITLES = [
  'INITIALIZING','DNS LOOKUP','WHOIS QUERY','CIDR ANALYSIS',
  'SSL INSPECTION','HTTP HEADERS','GEO-IP MAPPING','URL ANALYSIS',
  'PROXY DETECTION','AI PREDICTION','THREAT INTEL','RISK SCORING',
  'TRACE ID GEN','FINALIZING'
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
  const timeoutId  = setTimeout(() => controller.abort(), 45000);

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
        const isOffline = apiErr.message.includes('Failed to fetch') || apiErr.message.includes('NetworkError') || apiErr.name === 'AbortError';
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
  document.getElementById('scannerTitle').style.color = '';
}
function hideScanner() { document.getElementById('scannerOverlay').classList.add('hidden'); }

function showFatalError(msg) {
  document.getElementById('fatalMsg').textContent = msg || 'Unknown error.';
  document.getElementById('fatalErrorOverlay').classList.remove('hidden');
}
function closeFatalError() { document.getElementById('fatalErrorOverlay').classList.add('hidden'); }

function runScanAnimation(onStep, onComplete) {
  const bar    = document.getElementById('scanBar');
  const pctEl  = document.getElementById('scanPercent');
  const titleEl= document.getElementById('scannerTitle');
  let stepIdx  = 0;

  const tick = setInterval(async () => {
    if (stepIdx >= SCAN_STEPS.length) { clearInterval(tick); onComplete(); return; }
    const proceed = await onStep(stepIdx, SCAN_STEPS.length);
    if (!proceed) { clearInterval(tick); return; }
    const s = SCAN_STEPS[stepIdx];
    bar.style.width     = s.pct + '%';
    pctEl.textContent   = s.pct + '%';
    titleEl.textContent = SCAN_TITLES[stepIdx] || 'SCANNING';
    logToScanner(s.msg, s.cls);
    stepIdx++;
  }, 340);
}

function logToScanner(msg, cls) {
  const logEl = document.getElementById('scannerLog');
  const line  = document.createElement('div');
  line.textContent = msg; line.className = `term-line ${cls}`;
  logEl.appendChild(line); logEl.scrollTop = logEl.scrollHeight;
}

/* ════════════════════════════════════════════
   RENDER RESULTS
═══════════════════════════════════════════ */
function renderResults(data) {
  const sec = document.getElementById('resultsSection');
  sec.classList.remove('hidden');
  sec.scrollIntoView({ behavior: 'smooth', block: 'start' });

  renderVerdictBar(data);
  renderSummaryCards(data);
  renderConfidenceMeter(data);
  renderRiskGauge(data.risk_score, data.risk_level);
  renderRiskBreakdown(data.risk_breakdown || {});
  renderRiskFactors(data.explanation || []);
  renderAttackSurface(data.attack_surface || {});
  renderTerminal(data);
  renderIpHistory(data.ip_history || []);
  renderSslHttp(data.ssl_analysis || {}, data.http_analysis || {});
  renderWhois(data.whois || {});
  renderGeoIp(data.geo_analysis || {});
  renderUrlAnalysis(data.url_analysis || {});
  renderThreatIntel(data.threat_intel || {});
  renderBreakdown(data.score_breakdown || {});
}

/* ════════════════════════════════════════════
   VERDICT BAR
═══════════════════════════════════════════ */
function renderVerdictBar(data) {
  document.getElementById('traceId').textContent     = data.trace_id  || '—';
  document.getElementById('reportIdBadge').textContent = data.report_id || '—';
  document.getElementById('scanTs').textContent      = data.scan_timestamp || '—';

  const v = data.verdict || {};
  const badge = document.getElementById('verdictBadge');
  badge.textContent = v.badge || v.status || '—';
  badge.className   = 'verdict-status-badge';
  const s = (v.status || '').toLowerCase().replace(' ','');
  if (s === 'safe') badge.classList.add('safe');
  else if (s === 'suspicious') badge.classList.add('suspicious');
  else badge.classList.add('high-risk');

  document.getElementById('verdictConf').textContent = `Confidence: ${v.confidence || '—'}%`;
}

/* ════════════════════════════════════════════
   SUMMARY CARDS
═══════════════════════════════════════════ */
function renderSummaryCards(data) {
  document.getElementById('resDomain').textContent = data.domain;
  document.getElementById('resIPs').textContent = data.ip_addresses && data.ip_addresses.length
    ? data.ip_addresses.join(' · ') : 'Resolution failed';

  const proxyVal  = document.getElementById('resProxy');
  const proxySub  = document.getElementById('resProxyProvider');
  const proxyIcon = document.getElementById('proxyIcon');
  if (data.proxy_detected) {
    proxyVal.textContent = 'PROXY ACTIVE'; proxyVal.className = 'card-value proxy-yes';
    proxyIcon.textContent = '🔴'; proxySub.textContent = data.proxy_provider || 'Unknown';
  } else if (data.cdn_detected) {
    proxyVal.textContent = 'CDN LAYER'; proxyVal.className = 'card-value risk-medium';
    proxyIcon.textContent = '🟡'; proxySub.textContent = data.cdn_provider || 'Unknown CDN';
  } else {
    proxyVal.textContent = 'DIRECT HOST'; proxyVal.className = 'card-value proxy-no';
    proxyIcon.textContent = '🟢'; proxySub.textContent = 'No proxy detected';
  }

  // CDN sub info (fix: show CDN provider when proxy IS Cloudflare)
  if (data.cdn_detected && data.cdn_provider) {
    const cdnInfo = document.createElement('div');
    cdnInfo.className = 'card-sub';
    cdnInfo.style.marginTop = '2px';
    cdnInfo.innerHTML = `CDN: <span style="color:var(--blue)">${data.cdn_provider}</span>`;
    const proxyCard = document.getElementById('proxyCard');
    // Remove old CDN hint if exists
    const old = proxyCard.querySelector('.cdn-hint');
    if (old) old.remove();
    cdnInfo.classList.add('cdn-hint');
    proxyCard.appendChild(cdnInfo);
  }

  document.getElementById('resHosting').textContent   = data.real_hosting || '—';
  document.getElementById('resConfidence').textContent = `Confidence: ${data.confidence}%`;

  const possEl = document.getElementById('resPossibleHosting');
  if (data.possible_hosting) {
    possEl.textContent = `Possible: ${data.possible_hosting} (low confidence)`;
    possEl.className   = 'card-sub possible-hosting-hint';
  } else {
    possEl.textContent = '';
  }

  const riskLvl = document.getElementById('resRiskLevel');
  riskLvl.textContent = data.risk_level || '—';
  riskLvl.className   = `card-value risk-${(data.risk_level||'').toLowerCase()}`;
  document.getElementById('resRiskScore').textContent = `Score: ${data.risk_score}/100`;
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
    const pct   = Math.round((score / maxVal) * 100);
    const color = colors[i % colors.length];
    const item  = document.createElement('div');
    item.className = 'breakdown-item';
    item.innerHTML = `
      <span class="breakdown-name">${provider}</span>
      <div class="breakdown-bar-wrap">
        <div class="breakdown-bar" style="width:0%;background:${color}" data-target="${pct}"></div>
      </div>
      <span class="breakdown-score">${score}</span>`;
    container.appendChild(item); i++;
  }
  setTimeout(() => {
    container.querySelectorAll('.breakdown-bar').forEach(b => { b.style.width = b.dataset.target + '%'; });
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
      const {ctx:c,width:w,height:h} = chart; c.save();
      c.font=`bold 22px "Orbitron",sans-serif`; c.fillStyle=color;
      c.textAlign='center'; c.textBaseline='middle';
      c.fillText(score,w/2,h/2-10);
      c.font=`9px "Share Tech Mono",monospace`; c.fillStyle='#4a7a9b';
      c.fillText('RISK SCORE',w/2,h/2+12); c.restore();
    }}],
  });
}

/* ════════════════════════════════════════════
   RISK BREAKDOWN GRID
═══════════════════════════════════════════ */
function renderRiskBreakdown(rb) {
  const grid = document.getElementById('riskBreakdownGrid');
  const items = [
    { label:'PROXY RISK',       key:'proxy_risk' },
    { label:'BLACKLIST',        key:'blacklist_hits' },
    { label:'SUSP. TLD',        key:'suspicious_tld' },
    { label:'NEW DOMAIN',       key:'new_domain' },
    { label:'TRUSTED REG.',     key:'trusted_registrar' },
    { label:'CLEAN INTEL',      key:'clean_threat_intel' },
  ];
  grid.innerHTML = items.map(({ label, key }) => {
    const val = rb[key] || 0;
    const cls = val > 0 ? 'rbi-positive' : val < 0 ? 'rbi-negative' : 'rbi-neutral';
    const sign = val > 0 ? '+' : '';
    return `<div class="risk-breakdown-item">
      <div class="rbi-label">${label}</div>
      <div class="rbi-value ${cls}">${sign}${val}</div>
    </div>`;
  }).join('');
}

/* ════════════════════════════════════════════
   RISK FACTORS
═══════════════════════════════════════════ */
function renderRiskFactors(items) {
  const el = document.getElementById('riskFactors');
  el.innerHTML = items.slice(0,7).map(f => `<div class="risk-factor-item">${escapeHtml(f)}</div>`).join('');
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
        <div class="atk-detail">${escapeHtml(data.detail || '—')}</div>
      </div>
      <div class="atk-badge atk-${riskCls}">${data.status || '—'}</div>
    </div>`;
  }).join('');
}

/* ════════════════════════════════════════════
   TERMINAL OUTPUT
═══════════════════════════════════════════ */
function renderTerminal(data) {
  const body = document.getElementById('terminalBody');
  body.innerHTML = '';

  const ssl   = data.ssl_analysis  || {};
  const http  = data.http_analysis || {};
  const geo   = data.geo_analysis  || {};
  const url   = data.url_analysis  || {};
  const v     = data.verdict       || {};

  const lines = [
    { cls:'header',  text:`══════ HostTrace AI v3.0 — ${data.domain} ══════` },
    { cls:'info',    text:`> Trace ID        : ${data.trace_id || '—'}` },
    { cls:'info',    text:`> Report ID       : ${data.report_id || '—'}` },
    { cls:'info',    text:`> Scan timestamp  : ${data.scan_timestamp}` },
    { cls:'info',    text:`> IP addresses    : ${(data.ip_addresses||[]).join(', ') || 'N/A'}` },
    { cls: data.proxy_detected?'danger':'success',
      text:`> Proxy detected  : ${data.proxy_detected ? 'YES — '+data.proxy_provider : 'NO'}` },
    { cls: data.cdn_detected?'warn':'info',
      text:`> CDN detected    : ${data.cdn_detected ? 'YES — '+data.cdn_provider : 'NO'}` },
    { cls:'success', text:`> Real hosting    : ${data.real_hosting} (${data.confidence}% conf.)` },
    data.possible_hosting ? { cls:'warn', text:`> Possible host   : ${data.possible_hosting} (low confidence)` } : null,
    { cls:'header',  text:'─────── SSL ANALYSIS ───────' },
    { cls: ssl.ssl_valid?'success':'danger',
      text:`> SSL Valid       : ${ssl.ssl_valid ? 'YES' : 'NO'} ${ssl.error ? '('+ssl.error.slice(0,40)+')' : ''}` },
    { cls: ssl.ssl_expired?'danger':'info',
      text:`> SSL Expired     : ${ssl.ssl_expired ? 'YES ⚠' : 'NO'}` },
    { cls: ssl.self_signed?'danger':'info',
      text:`> Self-signed     : ${ssl.self_signed ? 'YES ⚠' : 'NO'}` },
    { cls:'info',    text:`> SSL Grade       : ${ssl.grade || 'N/A'}  |  Expires: ${ssl.valid_until || 'Unknown'}` },
    { cls:'header',  text:'─────── HTTP HEADERS ───────' },
    { cls: http.hsts?'success':'warn',
      text:`> HSTS            : ${http.hsts ? 'PRESENT ✓' : 'MISSING ⚠'}` },
    { cls: http.csp?'success':'warn',
      text:`> CSP             : ${http.csp ? 'PRESENT ✓' : 'MISSING ⚠'}` },
    { cls:'info',    text:`> Server Header   : ${http.server || 'Unknown'}` },
    { cls: http.cdn_via_header?'warn':'info',
      text:`> CDN via Header  : ${http.cdn_via_header || 'Not detected'}` },
    { cls:'header',  text:'─────── GEO-IP ───────' },
    { cls: geo.is_flagged_region?'danger':'success',
      text:`> IP Region       : ${geo.primary_country || 'Unknown'} (${geo.country_code || '?'}) ${geo.is_flagged_region ? '⚠ FLAGGED' : '✓ Clean'}` },
    { cls:'header',  text:'─────── URL ANALYSIS ───────' },
    { cls: url.suspicious_tld?'danger':'info',
      text:`> Suspicious TLD  : ${url.suspicious_tld ? 'YES — '+url.tld : 'NO'}` },
    url.suspicious_keywords && url.suspicious_keywords.length ? { cls:'warn', text:`> Phishing KWords : ${url.suspicious_keywords.slice(0,4).join(', ')}` } : null,
    { cls:'info',    text:`> URL Length      : ${url.url_length || 0} chars  |  Phishing Score: ${url.phishing_score || 0}/100` },
    { cls:'header',  text:'─────── VERDICT ───────' },
    { cls: v.status==='SAFE'?'success':v.status==='HIGH RISK'?'danger':'warn',
      text:`> Final Status    : ${v.badge || v.status || '—'} (${v.confidence || 0}% confidence)` },
    { cls:'info',    text:`> ${v.note || ''}` },
    { cls:'header',  text:'─────── THREAT INTEL ───────' },
    { cls:'warn',    text:`> VT Flags        : ${data.threat_intel?.virustotal_flags ?? 0}` },
    { cls:'warn',    text:`> Blacklist hits  : ${data.threat_intel?.blacklist_hits ?? 0}` },
    { cls:'header',  text:'─────── EXPLANATION LOG ───────' },
    ...(data.explanation||[]).slice(0,8).map(e => ({ cls:'info', text:`  • ${e}` })),
    { cls:'success', text:'> Analysis complete ✓' },
  ].filter(Boolean);

  let i = 0;
  const cursor = document.createElement('span');
  cursor.className = 'term-cursor';
  function addLine() {
    if (i >= lines.length) { body.appendChild(cursor); return; }
    const div = document.createElement('div');
    div.className = `term-line ${lines[i].cls}`;
    div.textContent = lines[i].text;
    body.appendChild(div);
    body.scrollTop = body.scrollHeight;
    i++; setTimeout(addLine, 35);
  }
  addLine();
}

/* ════════════════════════════════════════════
   IP HISTORY CHART
═══════════════════════════════════════════ */
function renderIpHistory(history) {
  const ctx = document.getElementById('ipHistoryChart').getContext('2d');
  if (ipChart) { ipChart.destroy(); }
  const labels  = history.map(h => h.timestamp);
  const ips     = history.map(h => h.ip);
  const ipSet   = [...new Set(ips)];
  const dataVals= ips.map(ip => ipSet.indexOf(ip) + 1);
  ipChart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [{ label:'IP Change Events', data:dataVals,
      borderColor:'#00eaff', backgroundColor:'rgba(0,234,255,0.06)',
      pointBackgroundColor:'#00ff9f', pointBorderColor:'#010d14',
      pointRadius:5, pointHoverRadius:8, fill:true, tension:0.4, borderWidth:2 }] },
    options: { responsive:true, maintainAspectRatio:true, animation:{duration:1000},
      scales: {
        x: { ticks:{color:'#4a7a9b',font:{family:'Share Tech Mono',size:10}}, grid:{color:'rgba(0,234,255,0.05)'} },
        y: { ticks:{color:'#4a7a9b',font:{family:'Share Tech Mono',size:10}, stepSize:1,
             callback:(v)=>ips[v-1]||v}, grid:{color:'rgba(0,234,255,0.05)'} } },
      plugins: { legend:{display:false},
        tooltip:{ backgroundColor:'rgba(4,20,36,0.95)', titleColor:'#00eaff',
          bodyColor:'#c8e4f0', borderColor:'rgba(0,234,255,0.2)', borderWidth:1,
          callbacks:{ label:(ctx)=>` IP: ${ips[ctx.dataIndex]} (${history[ctx.dataIndex].provider})` } } } },
  });
}

/* ════════════════════════════════════════════
   SSL / HTTP PANEL
═══════════════════════════════════════════ */
function renderSslHttp(ssl, http) {
  const grid = document.getElementById('sslHttpGrid');

  const sslGrade = ssl.grade || 'N/A';
  const gradeColor = { A:'ssl-val-ok', B:'ssl-val-ok', C:'ssl-val-warn', F:'ssl-val-bad', 'N/A':'ssl-val-warn' };
  const gc = gradeColor[sslGrade] || 'ssl-val-warn';

  const httpScore = http.security_score ?? null;
  const httpCls   = httpScore >= 70 ? 'ssl-val-ok' : httpScore >= 40 ? 'ssl-val-warn' : 'ssl-val-bad';

  // Security header tags
  const present = http.present_security_headers || [];
  const missing  = http.missing_security_headers || [];
  const allHdrs  = [...present.map(h=>({h,ok:true})), ...missing.map(h=>({h,ok:false}))];

  grid.innerHTML = `
    <div class="ssl-card">
      <div class="ssl-card-title">SSL / TLS</div>
      <div class="ssl-stat"><span>Valid</span><span class="${ssl.ssl_valid?'ssl-val-ok':'ssl-val-bad'}">${ssl.ssl_valid?'YES ✓':'NO ✗'}</span></div>
      <div class="ssl-stat"><span>Expired</span><span class="${ssl.ssl_expired?'ssl-val-bad':'ssl-val-ok'}">${ssl.ssl_expired?'YES ⚠':'NO ✓'}</span></div>
      <div class="ssl-stat"><span>Self-signed</span><span class="${ssl.self_signed?'ssl-val-bad':'ssl-val-ok'}">${ssl.self_signed?'YES ⚠':'NO ✓'}</span></div>
      <div class="ssl-stat"><span>Expires</span><span>${ssl.valid_until||'Unknown'}</span></div>
      <div class="ssl-stat"><span>Days Left</span><span class="${(ssl.days_remaining||999)<30?'ssl-val-warn':'ssl-val-ok'}">${ssl.days_remaining!=null?ssl.days_remaining:'N/A'}</span></div>
      <div class="ssl-stat"><span>Grade</span><span class="${gc}">${sslGrade}</span></div>
    </div>
    <div class="ssl-card">
      <div class="ssl-card-title">HTTP SECURITY</div>
      <div class="ssl-stat"><span>Server</span><span>${escapeHtml(http.server||'?')}</span></div>
      <div class="ssl-stat"><span>Security Score</span><span class="${httpCls}">${httpScore!=null?httpScore+'%':'N/A'}</span></div>
      <div class="ssl-stat"><span>HSTS</span><span class="${http.hsts?'ssl-val-ok':'ssl-val-bad'}">${http.hsts?'✓':'✗ Missing'}</span></div>
      <div class="ssl-stat"><span>CSP</span><span class="${http.csp?'ssl-val-ok':'ssl-val-bad'}">${http.csp?'✓':'✗ Missing'}</span></div>
      <div class="ssl-stat"><span>CDN via header</span><span>${escapeHtml(http.cdn_via_header||'None')}</span></div>
      <div class="header-tags">${allHdrs.map(({h,ok})=>`<span class="htag ${ok?'present':'missing'}">${h}</span>`).join('')}</div>
    </div>`;
}

/* ════════════════════════════════════════════
   WHOIS TABLE
═══════════════════════════════════════════ */
function renderWhois(w) {
  const tbl = document.getElementById('whoisTable');
  const rows = [
    ['Registrar',    w.registrar     || '—'],
    ['Org',          w.org           || '—'],
    ['Country',      w.country       || '—'],
    ['Created',      w.creation_date || '—'],
    ['Expires',      w.expiry_date   || '—'],
    ['DNSSEC',       w.dnssec        || '—'],
    ['Name Servers', (w.name_servers||[]).join('\n') || '—'],
  ];
  tbl.innerHTML = rows.map(([k,v]) =>
    `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`
  ).join('');
}

/* ════════════════════════════════════════════
   GEO-IP
═══════════════════════════════════════════ */
function renderGeoIp(geo) {
  const el = document.getElementById('geoInfo');
  const countryEmojis = { US:'🇺🇸',GB:'🇬🇧',DE:'🇩🇪',FR:'🇫🇷',CN:'🇨🇳',RU:'🇷🇺',
    IN:'🇮🇳',JP:'🇯🇵',BR:'🇧🇷',CA:'🇨🇦',AU:'🇦🇺',SG:'🇸🇬',NL:'🇳🇱',KP:'🇰🇵',
    IR:'🇮🇷',NG:'🇳🇬',BY:'🇧🇾',UA:'🇺🇦' };
  const flag = countryEmojis[geo.country_code] || '🌍';
  const flaggedHtml = geo.is_flagged_region
    ? `<div class="geo-flagged">⚠ ${escapeHtml(geo.risk_note || 'Flagged region detected')}</div>`
    : `<div class="geo-clean">✓ Geographic origin within normal parameters</div>`;
  el.innerHTML = `
    <div class="geo-country">
      <div class="geo-flag">${flag}</div>
      <div>
        <div class="geo-country-name">${escapeHtml(geo.primary_country || 'Unknown')}</div>
        <div class="geo-country-code">${geo.country_code || '?'} · ${geo.geo_source || 'WHOIS'}</div>
      </div>
    </div>
    ${flaggedHtml}`;
}

/* ════════════════════════════════════════════
   URL PATTERN ANALYSIS
═══════════════════════════════════════════ */
function renderUrlAnalysis(url) {
  const el = document.getElementById('urlInfo');
  const flags = url.flags || [];
  const score = url.phishing_score || 0;
  const scoreColor = score >= 60 ? 'var(--red)' : score >= 30 ? 'var(--yellow)' : 'var(--green)';
  el.innerHTML = `
    <div class="url-stat-row"><span>URL Length</span><span>${url.url_length || 0} chars</span></div>
    <div class="url-stat-row"><span>TLD</span><span style="color:${url.suspicious_tld?'var(--red)':'var(--green)'}">${url.tld || 'N/A'} ${url.suspicious_tld?'⚠':''}</span></div>
    <div class="url-stat-row"><span>Subdomain Depth</span><span>${url.subdomain_depth || 0}</span></div>
    <div class="url-stat-row"><span>Phishing Score</span><span style="color:${scoreColor};font-weight:700">${score}/100</span></div>
    <div class="phishing-score-bar"><div class="phishing-score-fill" style="width:${score}%"></div></div>
    ${flags.length ? `<div class="url-flags">${flags.map(f=>`<div class="url-flag-item">${escapeHtml(f)}</div>`).join('')}</div>` : ''}`;
}

/* ════════════════════════════════════════════
   THREAT INTEL
═══════════════════════════════════════════ */
function renderThreatIntel(t) {
  const vt  = t.virustotal_flags || 0;
  const blk = t.blacklist_hits   || 0;
  document.getElementById('vtNum').textContent = vt;
  document.getElementById('blNum').textContent = blk;
  setTimeout(() => {
    document.getElementById('vtBar').style.width  = Math.min(100, vt  * 10) + '%';
    document.getElementById('blBar').style.width  = Math.min(100, blk * 15) + '%';
  }, 400);
  const total = vt + blk;
  let statusText, col;
  if      (total === 0) { statusText = '✅ Clear — No threats detected';         col = '#00ff9f'; }
  else if (total <= 3)  { statusText = '⚠ Low threat signals found';             col = '#ffd166'; }
  else                  { statusText = '🚨 HIGH THREAT — Multiple detections!';  col = '#ff4f6d'; }
  const el = document.getElementById('threatStatus');
  el.textContent = statusText; el.style.color = col;
  if (vt  > 5)  document.getElementById('vtNum').style.color  = '#ff4f6d';
  else if (vt  > 0) document.getElementById('vtNum').style.color = '#ffd166';
  if (blk > 3)  document.getElementById('blNum').style.color = '#ff4f6d';
  else if (blk > 0) document.getElementById('blNum').style.color = '#ffd166';
}

/* ════════════════════════════════════════════
   PDF REPORT  (v3.0 — full forensic report)
═══════════════════════════════════════════ */
function downloadReport() {
  if (!currentReport) { alert('Run a scan first!'); return; }
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit:'mm', format:'a4' });
  const d   = currentReport;
  const LM  = 15, RW = 180;
  let y     = 18;

  doc.setFillColor(2, 12, 18);
  doc.rect(0, 0, 210, 297, 'F');

  doc.setFontSize(20); doc.setTextColor(0, 234, 255); doc.setFont('helvetica','bold');
  doc.text('HostTrace AI — Forensic Report v3.0', LM, y); y += 8;

  doc.setFontSize(8.5); doc.setTextColor(74, 122, 155); doc.setFont('helvetica','normal');
  doc.text(`Trace ID: ${d.trace_id || '—'}   |   Report ID: ${d.report_id || '—'}   |   ${d.scan_timestamp}`, LM, y); y += 8;

  doc.setDrawColor(0, 234, 255); doc.setLineWidth(0.4);
  doc.line(LM, y, LM + RW, y); y += 8;

  function section(title) {
    if (y > 265) { doc.addPage(); doc.setFillColor(2,12,18); doc.rect(0,0,210,297,'F'); y = 18; }
    doc.setFontSize(10); doc.setTextColor(0,255,159); doc.setFont('helvetica','bold');
    doc.text(title, LM, y); y += 6;
  }
  function row(label, value, valColor) {
    if (y > 275) { doc.addPage(); doc.setFillColor(2,12,18); doc.rect(0,0,210,297,'F'); y = 18; }
    doc.setFontSize(8.5); doc.setTextColor(200,228,240); doc.setFont('helvetica','bold');
    doc.text(label + ':', LM, y);
    if (valColor) doc.setTextColor(...valColor); else doc.setTextColor(180,210,230);
    doc.setFont('helvetica','normal');
    const lines = doc.splitTextToSize(String(value||'—'), 118);
    doc.text(lines, LM + 54, y);
    y += lines.length * 5 + 1.5;
    doc.setTextColor(200,228,240);
  }

  // ── Domain ──
  section('DOMAIN INFORMATION');
  row('Domain',       d.domain);
  row('IP Addresses', (d.ip_addresses||[]).join(', '));
  row('Scan Time',    d.scan_timestamp);
  y += 3;

  // ── Final Verdict ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('FINAL VERDICT');
  const v = d.verdict || {};
  const vcol = v.status==='SAFE'?[0,255,159]:v.status==='HIGH RISK'?[255,79,109]:[255,209,102];
  row('Status',       v.badge || v.status, vcol);
  row('Confidence',   (v.confidence||0)+'%');
  row('Assessment',   v.note || '—');
  row('Trace ID',     d.trace_id || '—');
  y += 3;

  // ── Proxy ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('PROXY / CDN DETECTION');
  row('Proxy Detected',  d.proxy_detected ? 'YES' : 'NO', d.proxy_detected?[255,79,109]:[0,255,159]);
  row('Proxy Provider',  d.proxy_provider  || 'N/A');
  row('CDN Detected',    d.cdn_detected ? 'YES' : 'NO',  d.cdn_detected?[255,209,102]:[0,255,159]);
  row('CDN Provider',    d.cdn_provider    || 'N/A');
  row('Masking Level',   d.masking_level   || '—');
  y += 3;

  // ── Hosting ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('AI HOSTING PREDICTION');
  row('Real Hosting',    d.real_hosting);
  if (d.possible_hosting) row('Possible Hosting', d.possible_hosting + ' (low confidence, behind proxy)');
  row('Confidence',      d.confidence + '%');
  y += 3;

  // ── Risk Breakdown ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('RISK ASSESSMENT & BREAKDOWN');
  row('Risk Score',  d.risk_score + '/100');
  row('Risk Level',  d.risk_level);
  const rb = d.risk_breakdown || {};
  const rbItems = [
    ['Proxy Risk',       rb.proxy_risk],
    ['Blacklist Hits',   rb.blacklist_hits],
    ['Suspicious TLD',   rb.suspicious_tld],
    ['New Domain',       rb.new_domain],
    ['Trusted Registrar',rb.trusted_registrar],
    ['Clean Threat Intel',rb.clean_threat_intel],
  ];
  for (const [k,v2] of rbItems) {
    if (v2 !== undefined && v2 !== 0) row(k, (v2>0?'+':'')+v2);
  }
  y += 3;

  // ── SSL ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('SSL / TLS ANALYSIS');
  const ssl = d.ssl_analysis || {};
  row('SSL Valid',    ssl.ssl_valid ? 'YES' : 'NO', ssl.ssl_valid?[0,255,159]:[255,79,109]);
  row('Expired',      ssl.ssl_expired ? 'YES ⚠' : 'NO');
  row('Self-signed',  ssl.self_signed ? 'YES ⚠' : 'NO');
  row('Grade',        ssl.grade || 'N/A');
  row('Expires',      ssl.valid_until || 'Unknown');
  row('Days Left',    ssl.days_remaining != null ? String(ssl.days_remaining) : 'N/A');
  if (ssl.error) row('Error', ssl.error);
  y += 3;

  // ── HTTP Headers ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('HTTP SECURITY HEADERS');
  const http = d.http_analysis || {};
  row('Security Score', (http.security_score ?? 'N/A')+'%');
  row('HSTS',     http.hsts  ? 'Present ✓' : 'Missing ⚠');
  row('CSP',      http.csp   ? 'Present ✓' : 'Missing ⚠');
  row('Server',   http.server || 'Unknown');
  if (http.missing_security_headers && http.missing_security_headers.length)
    row('Missing Headers', http.missing_security_headers.join(', '));
  if (http.cdn_via_header) row('CDN via Header', http.cdn_via_header);
  y += 3;

  // ── GeoIP ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('GEO-IP ANALYSIS');
  const geo = d.geo_analysis || {};
  row('Country',        geo.primary_country || 'Unknown');
  row('Country Code',   geo.country_code    || '?');
  row('Flagged Region', geo.is_flagged_region ? 'YES ⚠' : 'NO ✓', geo.is_flagged_region?[255,79,109]:[0,255,159]);
  if (geo.risk_note) row('Note', geo.risk_note);
  y += 3;

  // ── URL Analysis ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('URL PATTERN ANALYSIS');
  const url = d.url_analysis || {};
  row('URL Length',      url.url_length || 0);
  row('TLD',             url.tld || 'N/A');
  row('Suspicious TLD',  url.suspicious_tld ? 'YES ⚠' : 'NO ✓');
  row('Phishing Score',  (url.phishing_score || 0)+'/100');
  if (url.suspicious_keywords && url.suspicious_keywords.length)
    row('Suspicious Keywords', url.suspicious_keywords.join(', '));
  y += 3;

  // ── WHOIS ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('WHOIS FORENSICS');
  const w = d.whois || {};
  row('Registrar',    w.registrar);
  row('Organization', w.org);
  row('Country',      w.country);
  row('Created',      w.creation_date);
  row('Expires',      w.expiry_date);
  row('DNSSEC',       w.dnssec);
  row('Name Servers', (w.name_servers||[]).join(', '));
  y += 3;

  // ── Attack Surface ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('ATTACK SURFACE SUMMARY');
  const atk = d.attack_surface || {};
  for (const [key, label] of [['proxy_layer','Proxy Layer'],['dns_strength','DNS Strength'],['threat_footprint','Threat Footprint'],['exposure_level','Exposure Level']]) {
    if (atk[key]) row(label, `${atk[key].status} — ${atk[key].detail}`);
  }
  y += 3;

  // ── Threat Intel ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('THREAT INTELLIGENCE');
  row('VirusTotal Flags', d.threat_intel?.virustotal_flags ?? 0);
  row('Blacklist Hits',   d.threat_intel?.blacklist_hits   ?? 0);
  y += 3;

  // ── Explanation ──
  doc.line(LM,y,LM+RW,y); y+=6;
  section('AI EXPLANATION LOG');
  for (const exp of (d.explanation||[])) {
    if (y > 275) { doc.addPage(); doc.setFillColor(2,12,18); doc.rect(0,0,210,297,'F'); y=18; }
    doc.setFontSize(8.5); doc.setTextColor(74,122,155); doc.setFont('helvetica','normal');
    const lines = doc.splitTextToSize(`• ${exp}`, RW);
    doc.text(lines, LM+4, y); y += lines.length*4.5+1;
  }

  doc.setFontSize(7); doc.setTextColor(40,80,100);
  doc.text(`HostTrace AI © 2025 — For authorized security research only | Trace: ${d.trace_id||'—'}`, LM, 290);

  doc.save(`hosttrace_${d.domain}_${d.trace_id||Date.now()}.pdf`);
}

/* ════════════════════════════════════════════
   UTILITIES
═══════════════════════════════════════════ */
function shakeInput() {
  const box = document.getElementById('searchBox');
  box.style.animation = 'none'; box.offsetHeight;
  box.style.animation = 'shake 0.4s ease';
  box.addEventListener('animationend', () => { box.style.animation=''; }, { once:true });
}
const shakeStyle = document.createElement('style');
shakeStyle.textContent = `@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-5px)}80%{transform:translateX(5px)}}`;
document.head.appendChild(shakeStyle);

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/\n/g,'<br>');
}
