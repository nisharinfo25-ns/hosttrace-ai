/**
 * HostTrace AI – script.js
 * Frontend Logic: Scanning, UI Updates, Charts, PDF Export
 */

/* ════════════════════════════════════════════
   PARTICLE BACKGROUND
═══════════════════════════════════════════ */
(function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const COLORS = ['#00ff9f', '#00eaff', '#bc5af7'];
  const COUNT  = 80;

  for (let i = 0; i < COUNT; i++) {
    particles.push({
      x: Math.random() * 9999,
      y: Math.random() * 9999,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r:  Math.random() * 1.6 + 0.4,
      c:  COLORS[Math.floor(Math.random() * COLORS.length)],
      a:  Math.random() * 0.5 + 0.2,
    });
  }

  // Grid lines in background
  function drawGrid() {
    ctx.strokeStyle = 'rgba(0,234,255,0.03)';
    ctx.lineWidth   = 1;
    const step = 60;
    for (let x = 0; x < W; x += step) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    for (let y = 0; y < H; y += step) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }
  }

  function frame() {
    ctx.clearRect(0, 0, W, H);
    drawGrid();
    // Connect nearby particles
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.hypot(dx, dy);
        if (dist < 120) {
          ctx.strokeStyle = `rgba(0,234,255,${0.06 * (1 - dist / 120)})`;
          ctx.lineWidth   = 0.5;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
    // Draw particles
    for (const p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.c;
      ctx.globalAlpha = p.a;
      ctx.fill();
      ctx.globalAlpha = 1;
    }
    requestAnimationFrame(frame);
  }
  frame();
})();

/* ════════════════════════════════════════════
   GLOBAL STATE
═══════════════════════════════════════════ */
let currentReport = null;
let riskChart     = null;
let ipChart       = null;

// Always call Flask API on port 5000 regardless of how the HTML was opened
const API_BASE = window.location.port === '5000'
  ? ''
  : 'http://127.0.0.1:5000';


/* ════════════════════════════════════════════
   ENTER KEY SUPPORT
═══════════════════════════════════════════ */
document.getElementById('domainInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startAnalysis();
});

/* ════════════════════════════════════════════
   SCANNER STEPS
═══════════════════════════════════════════ */
const SCAN_STEPS = [
  { pct:  8,  msg: '> Initializing OSINT engine…',          cls: 'header' },
  { pct: 18,  msg: '> Resolving DNS records…',              cls: 'info'   },
  { pct: 30,  msg: '> Querying WHOIS database…',            cls: 'info'   },
  { pct: 42,  msg: '> Checking CIDR ranges (CF/AWS/GCP)…',  cls: 'info'   },
  { pct: 55,  msg: '> Scanning proxy indicators…',          cls: 'warn'   },
  { pct: 65,  msg: '> Running AI prediction model…',        cls: 'info'   },
  { pct: 75,  msg: '> Querying threat intelligence…',       cls: 'warn'   },
  { pct: 85,  msg: '> Calculating risk score…',             cls: 'warn'   },
  { pct: 94,  msg: '> Finalising forensic report…',         cls: 'success'},
  { pct: 100, msg: '> SCAN COMPLETE ✓',                     cls: 'success'},
];

/* ════════════════════════════════════════════
   MAIN ENTRY POINT
═══════════════════════════════════════════ */
async function startAnalysis() {
  const input  = document.getElementById('domainInput');
  const domain = input.value.trim();
  if (!domain) { shakeInput(); return; }

  showScanner();
  
  // Create AbortController for fetch timeout
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), 30000); // 30s timeout

  let apiResp = null;
  let apiErr  = null;

  // Start API call in parallel with animation initialization
  const apiCall = fetch(`${API_BASE}/analyze`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ domain }),
    signal:  controller.signal,
  })
  .then(async r => {
    clearTimeout(timeoutId);
    if (!r.ok) {
      const text = await r.text();
      throw new Error(`Server ${r.status}: ${text.slice(0,50)}`);
    }
    return r.json();
  })
  .catch(err => {
    clearTimeout(timeoutId);
    apiErr = err;
    return null;
  });

  runScanAnimation(async (currentStep, totalSteps) => {
    // If we've reached the penultimate step, wait for API
    if (currentStep === totalSteps - 1) {
      apiResp = await apiCall;
      
      if (apiErr) {
        logToScanner(`[FATAL] ERROR: ${apiErr.message.includes('Failed to fetch') ? 'BACKEND OFFLINE' : apiErr.message.toUpperCase()}`, 'danger');
        if (apiErr.message.includes('Failed to fetch')) {
          logToScanner(`> Ensure app.py is running on port 5000`, 'warn');
        }
        document.getElementById('scannerTitle').textContent = 'SYSTEM FAILURE';
        document.getElementById('scannerTitle').style.color = '#ff4f6d';
        return false; // Stop animation
      }
      
      if (apiResp && apiResp.error) {
        logToScanner(`[ERROR] ${apiResp.error.toUpperCase()}`, 'danger');
        document.getElementById('scannerTitle').textContent = 'SCAN HALTED';
        return false;
      }
    }
    return true; // Continue animation
  }, (data) => {
    // Final completion callback
    if (apiResp) {
      currentReport = apiResp;
      hideScanner();
      renderResults(apiResp);
    }
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
function hideScanner() {
  document.getElementById('scannerOverlay').classList.add('hidden');
}

function runScanAnimation(onStep, onComplete) {
  const bar    = document.getElementById('scanBar');
  const pctEl  = document.getElementById('scanPercent');
  const logEl  = document.getElementById('scannerLog');
  const titleEl= document.getElementById('scannerTitle');
  let stepIdx = 0;

  const TITLES = [
    'INITIALIZING', 'DNS LOOKUP', 'WHOIS QUERY',
    'CIDR ANALYSIS', 'PROXY DETECTION', 'AI PREDICTION',
    'THREAT INTEL', 'RISK SCORING', 'FINALIZING', 'COMPLETE'
  ];

  const tick = setInterval(async () => {
    if (stepIdx >= SCAN_STEPS.length) {
      clearInterval(tick);
      onComplete();
      return;
    }

    // Call step hook (can halt animation)
    const proceed = await onStep(stepIdx, SCAN_STEPS.length);
    if (!proceed) {
      clearInterval(tick);
      return;
    }

    const s = SCAN_STEPS[stepIdx];
    bar.style.width     = s.pct + '%';
    pctEl.textContent   = s.pct + '%';
    titleEl.textContent = TITLES[stepIdx] || 'SCANNING';
    
    logToScanner(s.msg, s.cls);
    stepIdx++;
  }, 320);
}

function logToScanner(msg, cls) {
  const logEl = document.getElementById('scannerLog');
  const line = document.createElement('div');
  line.textContent = msg;
  line.className   = `term-line ${cls}`;
  logEl.appendChild(line);
  logEl.scrollTop  = logEl.scrollHeight;
}

/* ════════════════════════════════════════════
   RENDER RESULTS
═══════════════════════════════════════════ */
function renderResults(data) {
  const sec = document.getElementById('resultsSection');
  sec.classList.remove('hidden');
  sec.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // ── Summary Cards ────────────────────────
  document.getElementById('resDomain').textContent = data.domain;
  const ipsText = data.ip_addresses && data.ip_addresses.length
    ? data.ip_addresses.join(' • ')
    : 'Resolution failed';
  document.getElementById('resIPs').textContent = ipsText;

  const proxyVal = document.getElementById('resProxy');
  const proxySub = document.getElementById('resProxyProvider');
  const proxyIcon= document.getElementById('proxyIcon');
  if (data.proxy_detected) {
    proxyVal.textContent = 'PROXY ACTIVE';
    proxyVal.className   = 'card-value proxy-yes';
    proxyIcon.textContent= '🔴';
    proxySub.textContent = data.proxy_provider || 'Unknown';
  } else if (data.cdn_detected) {
    proxyVal.textContent = 'CDN LAYER';
    proxyVal.className   = 'card-value risk-medium';
    proxyIcon.textContent= '🟡';
    proxySub.textContent = data.cdn_provider || 'Unknown CDN';
  } else {
    proxyVal.textContent = 'DIRECT HOST';
    proxyVal.className   = 'card-value proxy-no';
    proxyIcon.textContent= '🟢';
    proxySub.textContent = 'No proxy detected';
  }

  document.getElementById('resHosting').textContent   = data.real_hosting      || '—';
  document.getElementById('resConfidence').textContent = `Confidence: ${data.confidence}%`;

  const riskLvl = document.getElementById('resRiskLevel');
  riskLvl.textContent = data.risk_level || '—';
  riskLvl.className   = `card-value risk-${(data.risk_level||'').toLowerCase()}`;
  document.getElementById('resRiskScore').textContent  = `Score: ${data.risk_score}/100`;

  // ── Confidence Meter ─────────────────────
  document.getElementById('confProvider').textContent  = data.real_hosting || '—';
  setTimeout(() => {
    document.getElementById('meterFill').style.width   = data.confidence + '%';
    document.getElementById('meterValue').textContent  = data.confidence + '%';
  }, 200);

  // Score breakdown bars
  renderBreakdown(data.score_breakdown || {});

  // ── Risk Gauge ───────────────────────────
  renderRiskGauge(data.risk_score, data.risk_level);
  renderRiskFactors(data.explanation || []);

  // ── Terminal ─────────────────────────────
  renderTerminal(data);

  // ── IP History Chart ─────────────────────
  renderIpHistory(data.ip_history || []);

  // ── WHOIS ────────────────────────────────
  renderWhois(data.whois || {});

  // ── Threat Intel ─────────────────────────
  renderThreatIntel(data.threat_intel || {});
}

/* ════════════════════════════════════════════
   BREAKDOWN BARS
═══════════════════════════════════════════ */
function renderBreakdown(scores) {
  const container = document.getElementById('breakdownList');
  container.innerHTML = '';
  const maxVal = Math.max(...Object.values(scores), 1);
  const colors  = ['#00ff9f','#00eaff','#bc5af7','#ffd166','#ff4f6d',
                    '#00ff9f','#00eaff','#bc5af7','#ffd166','#ff4f6d'];
  let i = 0;
  for (const [provider, score] of Object.entries(scores)) {
    if (score === 0) { i++; continue; }
    const pct  = Math.round((score / maxVal) * 100);
    const color = colors[i % colors.length];
    const item = document.createElement('div');
    item.className = 'breakdown-item';
    item.innerHTML = `
      <span class="breakdown-name">${provider}</span>
      <div class="breakdown-bar-wrap">
        <div class="breakdown-bar" style="width:0%;background:${color}" data-target="${pct}"></div>
      </div>
      <span class="breakdown-score">${score}</span>`;
    container.appendChild(item);
    i++;
  }
  // Animate bars
  setTimeout(() => {
    container.querySelectorAll('.breakdown-bar').forEach(b => {
      b.style.width = b.dataset.target + '%';
    });
  }, 300);
}

/* ════════════════════════════════════════════
   RISK GAUGE (Chart.js doughnut)
═══════════════════════════════════════════ */
function renderRiskGauge(score, level) {
  const ctx = document.getElementById('riskGauge').getContext('2d');
  if (riskChart) { riskChart.destroy(); }

  const colorMap = { Low: '#00ff9f', Medium: '#ffd166', High: '#ff4f6d' };
  const color    = colorMap[level] || '#00eaff';

  riskChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data:            [score, 100 - score],
        backgroundColor: [color, 'rgba(0,234,255,0.06)'],
        borderColor:     [color, 'rgba(0,234,255,0.06)'],
        borderWidth:     2,
        hoverOffset:     4,
      }],
    },
    options: {
      cutout:   '72%',
      animation:{ animateRotate: true, duration: 1000 },
      plugins: {
        legend:  { display: false },
        tooltip: { enabled: false },
      },
    },
    plugins: [{
      id: 'centerText',
      afterDraw(chart) {
        const { ctx: c, width: w, height: h } = chart;
        c.save();
        c.font         = `bold 22px "Orbitron", sans-serif`;
        c.fillStyle    = color;
        c.textAlign    = 'center';
        c.textBaseline = 'middle';
        c.fillText(score, w / 2, h / 2 - 10);
        c.font         = `9px "Share Tech Mono", monospace`;
        c.fillStyle    = '#4a7a9b';
        c.fillText('RISK SCORE', w / 2, h / 2 + 12);
        c.restore();
      },
    }],
  });
}

/* ════════════════════════════════════════════
   RISK FACTORS LIST
═══════════════════════════════════════════ */
function renderRiskFactors(items) {
  const el = document.getElementById('riskFactors');
  el.innerHTML = items.slice(0, 6).map(f =>
    `<div class="risk-factor-item">${escapeHtml(f)}</div>`
  ).join('');
}

/* ════════════════════════════════════════════
   TERMINAL OUTPUT
═══════════════════════════════════════════ */
function renderTerminal(data) {
  const body = document.getElementById('terminalBody');
  body.innerHTML = '';

  const lines = [
    { cls: 'header',  text: `══════ HostTrace AI — ${data.domain} ══════` },
    { cls: 'info',    text: `> Scan timestamp  : ${data.scan_timestamp}` },
    { cls: 'info',    text: `> IP addresses    : ${(data.ip_addresses||[]).join(', ') || 'N/A'}` },
  ];

  if (data.proxy_detected) {
    lines.push({ cls: 'danger', text: `> Proxy detected  : YES — ${data.proxy_provider}` });
  } else if (data.cdn_detected) {
    lines.push({ cls: 'warn',  text: `> CDN detected    : YES — ${data.cdn_provider}` });
  } else {
    lines.push({ cls: 'success', text: '> Proxy detected  : NO — Direct host' });
  }

  lines.push(
    { cls: 'success', text: `> Real hosting    : ${data.real_hosting} (${data.confidence}% confidence)` },
    { cls: data.risk_level==='High'?'danger':data.risk_level==='Medium'?'warn':'success',
              text: `> Risk level      : ${data.risk_level} (score: ${data.risk_score}/100)` },
    { cls: 'info',    text: `> Registrar       : ${data.whois?.registrar || 'Unknown'}` },
    { cls: 'info',    text: `> Org             : ${data.whois?.org || 'Unknown'}` },
    { cls: 'info',    text: `> Country         : ${data.whois?.country || 'Unknown'}` },
    { cls: 'info',    text: `> WHOIS Created   : ${data.whois?.creation_date || 'Unknown'}` },
    { cls: 'info',    text: `> WHOIS Expires   : ${data.whois?.expiry_date || 'Unknown'}` },
    { cls: 'warn',    text: `> VT Flags        : ${data.threat_intel?.virustotal_flags ?? 0}` },
    { cls: 'warn',    text: `> Blacklist hits  : ${data.threat_intel?.blacklist_hits ?? 0}` },
    { cls: 'header',  text: '─────── EXPLANATION LOG ───────' },
    ...(data.explanation||[]).slice(0,10).map(e => ({ cls: 'info', text: `  • ${e}` })),
    { cls: 'success', text: '> Analysis complete ✓' },
  );

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
    i++;
    setTimeout(addLine, 40);
  }
  addLine();
}

/* ════════════════════════════════════════════
   IP HISTORY CHART (Chart.js line)
═══════════════════════════════════════════ */
function renderIpHistory(history) {
  const ctx = document.getElementById('ipHistoryChart').getContext('2d');
  if (ipChart) { ipChart.destroy(); }

  const labels   = history.map(h => h.timestamp);
  const ips      = history.map(h => h.ip);
  // Encode IPs as numbers for chart
  const ipSet    = [...new Set(ips)];
  const dataVals = ips.map(ip => ipSet.indexOf(ip) + 1);

  ipChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label:           'IP Change Events',
        data:            dataVals,
        borderColor:     '#00eaff',
        backgroundColor: 'rgba(0,234,255,0.06)',
        pointBackgroundColor: '#00ff9f',
        pointBorderColor:     '#010d14',
        pointRadius:          5,
        pointHoverRadius:     8,
        fill:            true,
        tension:         0.4,
        borderWidth:     2,
      }],
    },
    options: {
      responsive:       true,
      maintainAspectRatio: true,
      animation:        { duration: 1000 },
      scales: {
        x: {
          ticks:  { color: '#4a7a9b', font: { family: 'Share Tech Mono', size: 10 } },
          grid:   { color: 'rgba(0,234,255,0.05)' },
        },
        y: {
          ticks:  {
            color: '#4a7a9b',
            font:  { family: 'Share Tech Mono', size: 10 },
            stepSize: 1,
            callback: (v) => ips[v - 1] || v,
          },
          grid:   { color: 'rgba(0,234,255,0.05)' },
        },
      },
      plugins: {
        legend:  { display: false },
        tooltip: {
          backgroundColor: 'rgba(4,20,36,0.95)',
          titleColor:      '#00eaff',
          bodyColor:       '#c8e4f0',
          borderColor:     'rgba(0,234,255,0.2)',
          borderWidth:     1,
          callbacks: {
            label: (ctx) => ` IP: ${ips[ctx.dataIndex]} (${history[ctx.dataIndex].provider})`,
          },
        },
      },
    },
  });
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
    ['Name Servers', (w.name_servers||[]).join('\n') || '—'],
  ];
  tbl.innerHTML = rows.map(([k, v]) =>
    `<tr>
      <td>${escapeHtml(k)}</td>
      <td>${escapeHtml(String(v))}</td>
    </tr>`
  ).join('');
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
  if (total === 0) {
    statusText = '✅ Clear — No threats detected';
    col = '#00ff9f';
  } else if (total <= 3) {
    statusText = '⚠ Low threat signals found';
    col = '#ffd166';
  } else {
    statusText = '🚨 HIGH THREAT — Multiple detections!';
    col = '#ff4f6d';
  }
  const el = document.getElementById('threatStatus');
  el.textContent = statusText;
  el.style.color  = col;

  // Colour the numbers
  const vtCard  = document.getElementById('vtNum');
  const blkCard = document.getElementById('blNum');
  if (vt  > 5)  vtCard.style.color  = '#ff4f6d';
  else if (vt  > 0) vtCard.style.color = '#ffd166';
  if (blk > 3)  blkCard.style.color = '#ff4f6d';
  else if (blk > 0) blkCard.style.color = '#ffd166';
}

/* ════════════════════════════════════════════
   PDF REPORT
═══════════════════════════════════════════ */
function downloadReport() {
  if (!currentReport) { alert('Run a scan first!'); return; }
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const d   = currentReport;
  const LM  = 15, RW = 180;
  let y     = 18;

  // ── Header ──
  doc.setFillColor(2, 12, 18);
  doc.rect(0, 0, 210, 297, 'F');

  doc.setFontSize(20); doc.setTextColor(0, 234, 255);
  doc.setFont('helvetica', 'bold');
  doc.text('HostTrace AI — Proxy Breaker', LM, y); y += 10;

  doc.setFontSize(9); doc.setTextColor(74, 122, 155);
  doc.setFont('helvetica', 'normal');
  doc.text(`Forensic Analysis Report  •  ${d.scan_timestamp}`, LM, y); y += 8;

  // Divider
  doc.setDrawColor(0, 234, 255); doc.setLineWidth(0.4);
  doc.line(LM, y, LM + RW, y); y += 8;

  // ── Section Helper ──
  function section(title) {
    doc.setFontSize(10); doc.setTextColor(0, 255, 159);
    doc.setFont('helvetica', 'bold');
    doc.text(title, LM, y); y += 6;
  }
  function row(label, value) {
    doc.setFontSize(9); doc.setTextColor(200, 228, 240);
    doc.setFont('helvetica', 'bold');
    doc.text(label + ':', LM, y);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(String(value || '—'), 120);
    doc.text(lines, LM + 52, y);
    y += lines.length * 5 + 2;
    if (y > 275) { doc.addPage(); doc.setFillColor(2,12,18); doc.rect(0,0,210,297,'F'); y = 18; }
  }

  // ── Domain Info ──
  section('DOMAIN INFORMATION');
  row('Domain',     d.domain);
  row('IP Addresses', (d.ip_addresses||[]).join(', '));
  row('Scan Time',  d.scan_timestamp);
  y += 3;

  // ── Proxy / CDN ──
  doc.setDrawColor(0,234,255,0.2); doc.line(LM, y, LM+RW, y); y += 6;
  section('PROXY / CDN DETECTION');
  row('Proxy Detected',  d.proxy_detected ? 'YES' : 'NO');
  row('Proxy Provider',  d.proxy_provider  || 'N/A');
  row('CDN Detected',    d.cdn_detected    ? 'YES' : 'NO');
  row('CDN Provider',    d.cdn_provider    || 'N/A');
  y += 3;

  // ── Hosting Prediction ──
  doc.line(LM, y, LM+RW, y); y += 6;
  section('AI HOSTING PREDICTION');
  row('Real Hosting',    d.real_hosting);
  row('Confidence',      d.confidence + '%');
  y += 3;

  // ── Risk ──
  doc.line(LM, y, LM+RW, y); y += 6;
  section('RISK ASSESSMENT');
  row('Risk Score',  d.risk_score + '/100');
  row('Risk Level',  d.risk_level);
  y += 3;

  // ── WHOIS ──
  doc.line(LM, y, LM+RW, y); y += 6;
  section('WHOIS FORENSICS');
  if (d.whois) {
    row('Registrar',    d.whois.registrar);
    row('Organization', d.whois.org);
    row('Country',      d.whois.country);
    row('Created',      d.whois.creation_date);
    row('Expires',      d.whois.expiry_date);
    row('Name Servers', (d.whois.name_servers||[]).join(', '));
  }
  y += 3;

  // ── Threat Intel ──
  doc.line(LM, y, LM+RW, y); y += 6;
  section('THREAT INTELLIGENCE');
  row('VirusTotal Flags', d.threat_intel?.virustotal_flags ?? 0);
  row('Blacklist Hits',   d.threat_intel?.blacklist_hits   ?? 0);
  y += 3;

  // ── Explanation ──
  doc.line(LM, y, LM+RW, y); y += 6;
  section('AI EXPLANATION LOG');
  for (const exp of (d.explanation || [])) {
    doc.setFontSize(8.5); doc.setTextColor(74, 122, 155);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(`• ${exp}`, RW);
    doc.text(lines, LM + 4, y);
    y += lines.length * 4.5 + 1;
    if (y > 275) { doc.addPage(); doc.setFillColor(2,12,18); doc.rect(0,0,210,297,'F'); y = 18; }
  }
  y += 4;

  // Footer
  doc.setFontSize(7); doc.setTextColor(40, 80, 100);
  doc.text('HostTrace AI © 2025 — For authorized security research only', LM, 290);

  doc.save(`hosttrace_${d.domain}_${Date.now()}.pdf`);
}

/* ════════════════════════════════════════════
   UTILITIES
═══════════════════════════════════════════ */
function shakeInput() {
  const box = document.getElementById('searchBox');
  box.style.animation = 'none';
  box.offsetHeight; // reflow
  box.style.animation = 'shake 0.4s ease';
  box.addEventListener('animationend', () => { box.style.animation = ''; }, { once: true });
}

// Inject shake keyframe dynamically
const shakeStyle = document.createElement('style');
shakeStyle.textContent = `
@keyframes shake {
  0%,100% { transform: translateX(0); }
  20%      { transform: translateX(-8px); }
  40%      { transform: translateX(8px); }
  60%      { transform: translateX(-5px); }
  80%      { transform: translateX(5px); }
}`;
document.head.appendChild(shakeStyle);

function showError(msg) {
  alert('⚠ Error: ' + msg);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/\n/g, '<br>');
}

// Override escapeHtml for innerHTML usage in terminal – return plain text there
// (terminal uses textContent so XSS is not an issue)
