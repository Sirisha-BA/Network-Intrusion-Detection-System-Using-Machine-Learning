/* ═══════════════════════════════════════════
   NIDS Frontend — app.js
═══════════════════════════════════════════ */

const API = `http://localhost:3000`;
const WS_URL = `ws://localhost:3000`;

let ws = null;
let allRows = [];
let allLogs = [];
let chartDist = null;
let chartAcc = null;
let chartType = 'bar';
let showAccChart = false;
let lastPacketCount = 0;
let prevPacketCount = 0;

// ─── Init ──────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  startClock();
  connectWS();
  fetchInitialData();
});

function startClock() {
  setInterval(() => {
    document.getElementById('clock').textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
  }, 1000);
}

// ─── WebSocket ─────────────────────────────────────
function connectWS() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    setWsStatus(true);
  };

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    handleMessage(msg);
  };

  ws.onclose = () => {
    setWsStatus(false);
    setTimeout(connectWS, 2000);
  };

  ws.onerror = () => {
    setWsStatus(false);
  };
}

function setWsStatus(ok) {
  const dot = document.getElementById('wsDot');
  const label = document.getElementById('wsLabel');
  dot.className = 'dot ' + (ok ? 'connected' : 'error');
  label.textContent = ok ? 'CONNECTED' : 'RECONNECTING';
}

function handleMessage(msg) {
  switch (msg.type) {
    case 'init':
      applyInit(msg.data);
      break;
    case 'update':
      applyUpdate(msg.data);
      break;
    case 'monitoring':
      setMonitoringUI(msg.data.active);
      break;
    case 'model':
      updateModelBadge(msg.data.model);
      break;
    case 'dataset':
      document.getElementById('uploadStatus').textContent = `✓ ${msg.data.count} records loaded`;
      break;
    case 'reset':
      resetUI();
      break;
  }
}

function applyInit(data) {
  updateStats(data.stats);
  data.detectionTable.forEach(p => addRowToTable(p));
  data.logs.forEach(l => allLogs.push(l));
  renderLogs();
  updateChartDist(data.attackDistribution);
  updateMatrix(data.confusionMatrix, data.accuracy);
  setMonitoringUI(data.monitoringActive);
  updateModelBadge(data.selectedModel);
}

function applyUpdate(data) {
  prevPacketCount = lastPacketCount;
  lastPacketCount = data.stats.packets;
  updateStats(data.stats);

  if (data.newPackets) {
    data.newPackets.forEach(p => {
      allRows.unshift(p);
      addRowToTable(p, true);
    });
    if (allRows.length > 200) allRows.splice(200);
  }

  if (data.logs) {
    data.logs.forEach(l => {
      if (!allLogs.find(x => x.timestamp === l.timestamp && x.message === l.message)) {
        allLogs.unshift(l);
        addAlertFeed(l);
      }
    });
    if (allLogs.length > 500) allLogs.splice(500);
    renderLogs();
  }

  updateChartDist(data.attackDistribution);
  updateMatrix(data.confusionMatrix, data.accuracy);

  if (data.accuracyHistory) updateAccChart(data.accuracyHistory);
  updateThreatLevel(data.stats);
}

// ─── Stats ─────────────────────────────────────────
function updateStats(s) {
  animateValue('statPackets', s.packets);
  animateValue('statAttacks', s.attacks);
  animateValue('statBenign', s.benign);
  animateValue('statAlerts', s.alerts);

  const total = s.packets || 1;
  document.getElementById('trendAttacks').textContent = ((s.attacks / total) * 100).toFixed(1) + '%';
  document.getElementById('trendBenign').textContent = ((s.benign / total) * 100).toFixed(1) + '%';

  const rate = lastPacketCount - prevPacketCount;
  document.getElementById('trendPackets').textContent = `+${rate}/s`;
}

function animateValue(id, target) {
  const el = document.getElementById(id);
  const start = parseInt(el.textContent.replace(/,/g, '')) || 0;
  const diff = target - start;
  if (diff === 0) return;
  const steps = 12;
  let i = 0;
  const tick = setInterval(() => {
    i++;
    el.textContent = numberFormat(Math.round(start + diff * (i / steps)));
    if (i >= steps) { clearInterval(tick); el.textContent = numberFormat(target); }
  }, 30);
}

function numberFormat(n) {
  return n.toLocaleString();
}

function updateThreatLevel(s) {
  const el = document.getElementById('tlValue');
  const total = s.packets || 1;
  const ratio = s.attacks / total;
  if (ratio > 0.5) { el.textContent = 'CRITICAL'; el.className = 'tl-value critical'; }
  else if (ratio > 0.3) { el.textContent = 'HIGH'; el.className = 'tl-value high'; }
  else if (ratio > 0.15) { el.textContent = 'MEDIUM'; el.className = 'tl-value medium'; }
  else { el.textContent = 'NORMAL'; el.className = 'tl-value'; }
}

// ─── Detection Table ───────────────────────────────
function addRowToTable(p, isNew = false) {
  const tbody = document.getElementById('detTable');
  const tr = document.createElement('tr');
  if (isNew) tr.classList.add('row-new');

  const time = new Date(p.timestamp).toLocaleTimeString('en-US', { hour12: false });
  const badge = getLabelBadge(p.label);
  const sevClass = 'sev-' + p.severity.toLowerCase();
  const confPct = Math.round(parseFloat(p.confidence) * 100);

  tr.innerHTML = `
    <td>${time}</td>
    <td>${p.srcIP}:${p.srcPort}</td>
    <td>${p.dstIP}:${p.dstPort}</td>
    <td>${p.protocol}</td>
    <td>${p.length}B</td>
    <td><span class="badge ${badge}">${p.label}</span></td>
    <td>
      <span class="conf-bar"><span class="conf-fill" style="width:${confPct}%"></span></span>
      ${confPct}%
    </td>
    <td class="${sevClass}">${p.severity}</td>
  `;

  if (isNew) {
    tbody.insertBefore(tr, tbody.firstChild);
    if (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);
  } else {
    tbody.appendChild(tr);
  }

  document.getElementById('tableCount').textContent = `${tbody.children.length} records`;
}

function getLabelBadge(label) {
  if (label === 'BENIGN') return 'badge-benign';
  if (label.includes('DoS') || label.includes('DDoS')) return label.includes('DDoS') ? 'badge-ddos' : 'badge-dos';
  if (label.includes('Scan') || label.includes('PortScan')) return 'badge-scan';
  if (label.includes('Brute') || label.includes('XSS') || label.includes('SQL')) return 'badge-brute';
  return 'badge-other';
}

function filterTable() {
  const q = document.getElementById('filterInput').value.toLowerCase();
  const rows = document.querySelectorAll('#detTable tr');
  let visible = 0;
  rows.forEach(r => {
    const show = r.textContent.toLowerCase().includes(q);
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.getElementById('tableCount').textContent = `${visible} records`;
}

// ─── Charts ────────────────────────────────────────
const COLORS = ['#ff3366','#a855f7','#ff8c00','#ffe033','#00e5ff','#00ff88','#e879f9','#38bdf8'];

function updateChartDist(dist) {
  const labels = Object.keys(dist);
  const values = Object.values(dist);
  if (labels.length === 0) return;

  if (!chartDist) {
    const ctx = document.getElementById('chartDist').getContext('2d');
    chartDist = new Chart(ctx, {
      type: chartType,
      data: { labels, datasets: [{ data: values, backgroundColor: COLORS, borderColor: COLORS.map(c => c + '88'), borderWidth: 1, borderRadius: chartType === 'bar' ? 4 : 0 }] },
      options: getChartOptions(chartType)
    });
  } else {
    chartDist.data.labels = labels;
    chartDist.data.datasets[0].data = values;
    chartDist.update('none');
  }
}

function getChartOptions(type) {
  const base = {
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { display: type !== 'bar', labels: { color: '#5a7a90', font: { family: 'Share Tech Mono', size: 11 }, padding: 12 } },
      tooltip: { backgroundColor: '#0d1821', borderColor: '#1e3a52', borderWidth: 1, titleColor: '#00e5ff', bodyColor: '#c8dce8', titleFont: { family: 'Share Tech Mono' }, bodyFont: { family: 'Share Tech Mono' } }
    }
  };
  if (type === 'bar') {
    base.scales = {
      x: { ticks: { color: '#5a7a90', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: 'rgba(30,58,82,0.5)' } },
      y: { ticks: { color: '#5a7a90', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: 'rgba(30,58,82,0.5)' } }
    };
  }
  return base;
}

function setChartType(type, btn) {
  chartType = type;
  document.querySelectorAll('#panelDist .chart-toggle').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (chartDist) {
    chartDist.destroy();
    chartDist = null;
  }
}

// ─── Accuracy Chart ────────────────────────────────
function updateAccChart(history) {
  if (!showAccChart) return;
  const labels = history.map(h => new Date(h.time).toLocaleTimeString('en-US', { hour12: false }));
  const values = history.map(h => h.accuracy);

  if (!chartAcc) {
    const ctx = document.getElementById('chartAcc').getContext('2d');
    chartAcc = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Accuracy %', data: values,
          borderColor: '#00e5ff', backgroundColor: 'rgba(0,229,255,0.08)',
          borderWidth: 2, pointRadius: 0, tension: 0.4, fill: true
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0d1821', borderColor: '#1e3a52', borderWidth: 1, titleColor: '#00e5ff', bodyColor: '#c8dce8', titleFont: { family: 'Share Tech Mono' }, bodyFont: { family: 'Share Tech Mono' } } },
        scales: {
          x: { ticks: { color: '#5a7a90', font: { family: 'Share Tech Mono', size: 9 }, maxTicksLimit: 8 }, grid: { color: 'rgba(30,58,82,0.5)' } },
          y: { min: 80, max: 100, ticks: { color: '#5a7a90', font: { family: 'Share Tech Mono', size: 9 } }, grid: { color: 'rgba(30,58,82,0.5)' } }
        }
      }
    });
  } else {
    chartAcc.data.labels = labels;
    chartAcc.data.datasets[0].data = values;
    chartAcc.update('none');
  }
}

function toggleAccGraph(showAcc, btn) {
  showAccChart = showAcc;
  document.getElementById('matrixView').style.display = showAcc ? 'none' : '';
  document.getElementById('accChartView').style.display = showAcc ? '' : 'none';
  document.querySelectorAll('#panelMatrix .chart-toggle').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

// ─── Confusion Matrix ──────────────────────────────
function updateMatrix(cm, accuracy) {
  document.getElementById('valTP').textContent = numberFormat(cm.tp);
  document.getElementById('valFP').textContent = numberFormat(cm.fp);
  document.getElementById('valTN').textContent = numberFormat(cm.tn);
  document.getElementById('valFN').textContent = numberFormat(cm.fn);

  document.getElementById('accVal').textContent = parseFloat(accuracy).toFixed(2);
  document.getElementById('accFill').style.width = accuracy + '%';

  const precision = cm.tp + cm.fp > 0 ? (cm.tp / (cm.tp + cm.fp)).toFixed(3) : '—';
  const recall = cm.tp + cm.fn > 0 ? (cm.tp / (cm.tp + cm.fn)).toFixed(3) : '—';
  const f1 = (precision !== '—' && recall !== '—')
    ? (2 * precision * recall / (parseFloat(precision) + parseFloat(recall))).toFixed(3) : '—';

  document.getElementById('mPrecision').textContent = precision;
  document.getElementById('mRecall').textContent = recall;
  document.getElementById('mF1').textContent = f1;
}

// ─── Alerts ────────────────────────────────────────
let alertCount = 0;
function addAlertFeed(log) {
  if (log.level !== 'ALERT') return;
  alertCount++;
  const list = document.getElementById('alertsList');
  const empty = list.querySelector('.alert-empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = 'alert-item';
  const t = new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false });
  div.innerHTML = `<span class="alert-time">${t}</span><span class="alert-msg">${log.message}</span>`;
  list.insertBefore(div, list.firstChild);
  if (list.children.length > 50) list.removeChild(list.lastChild);
}

function clearAlerts() {
  const list = document.getElementById('alertsList');
  list.innerHTML = '<div class="alert-empty">No alerts — system normal</div>';
  alertCount = 0;
}

// ─── Logs ──────────────────────────────────────────
function renderLogs() {
  const container = document.getElementById('logsContainer');
  const filter = document.getElementById('logLevelFilter')?.value || 'ALL';
  container.innerHTML = '';
  const filtered = filter === 'ALL' ? allLogs : allLogs.filter(l => l.level === filter);
  filtered.slice(0, 300).forEach(log => {
    const div = document.createElement('div');
    div.className = `log-line log-${log.level}`;
    const t = new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false });
    div.innerHTML = `<span class="log-ts">[${t}]</span><span class="log-level">${log.level}</span>${escapeHtml(log.message)}`;
    container.appendChild(div);
  });
}

function filterLogs() { renderLogs(); }

function clearLogs() {
  allLogs = [];
  renderLogs();
  fetch(`${API}/api/logs`, { method: 'DELETE' });
}

function exportLogs() {
  const text = allLogs.map(l => `[${l.timestamp}] [${l.level}] ${l.message}`).join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
  a.download = 'nids_logs_' + Date.now() + '.txt';
  a.click();
}

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ─── Navigation ────────────────────────────────────
function switchView(view, el) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`view-${view}`).classList.add('active');
  el.classList.add('active');
}

// ─── Controls ──────────────────────────────────────
function startMonitoring() {
  fetch(`${API}/api/monitoring/start`, { method: 'POST' });
}

function stopMonitoring() {
  fetch(`${API}/api/monitoring/stop`, { method: 'POST' });
}

function resetSystem() {
  if (!confirm('Reset all data?')) return;
  fetch(`${API}/api/reset`, { method: 'POST' });
}

function setMonitoringUI(active) {
  document.getElementById('btnStart').disabled = active;
  document.getElementById('btnStop').disabled = !active;
}

function selectModel(input) {
  const label = input.closest('.model-opt');
  document.querySelectorAll('.model-opt').forEach(l => l.classList.remove('active'));
  label.classList.add('active');
  fetch(`${API}/api/model/select`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: input.value })
  });
}

function updateModelBadge(model) {
  const names = { random_forest: 'RANDOM FOREST', xgboost: 'XGBOOST', cnn: 'CNN', lstm: 'LSTM', svm: 'SVM' };
  document.getElementById('modelBadge').textContent = 'MODEL: ' + (names[model] || model.toUpperCase());
  // highlight selected
  document.querySelectorAll('.model-opt').forEach(opt => {
    const radio = opt.querySelector('input[type=radio]');
    if (radio && radio.value === model) {
      opt.classList.add('active');
      radio.checked = true;
    } else {
      opt.classList.remove('active');
    }
  });
}

function uploadDataset(input) {
  const file = input.files[0];
  if (!file) return;
  document.getElementById('uploadStatus').textContent = 'Uploading...';
  const fd = new FormData();
  fd.append('dataset', file);
  fetch(`${API}/api/upload`, { method: 'POST', body: fd })
    .then(r => r.json())
    .then(d => {
      document.getElementById('uploadStatus').textContent = `✓ ${d.count} records loaded`;
    })
    .catch(() => {
      document.getElementById('uploadStatus').textContent = '✗ Upload failed';
    });
}

function resetUI() {
  allRows = [];
  allLogs = [];
  document.getElementById('detTable').innerHTML = '';
  document.getElementById('tableCount').textContent = '0 records';
  document.getElementById('alertsList').innerHTML = '<div class="alert-empty">No alerts — system normal</div>';
  renderLogs();
  if (chartDist) { chartDist.destroy(); chartDist = null; }
  if (chartAcc) { chartAcc.destroy(); chartAcc = null; }
  updateStats({ packets: 0, attacks: 0, benign: 0, alerts: 0 });
  updateMatrix({ tp: 0, fp: 0, tn: 0, fn: 0 }, 0);
}

// ─── Initial data fetch ────────────────────────────
function fetchInitialData() {
  fetch(`${API}/api/stats`).then(r => r.json()).then(d => {
    updateMatrix(d.confusionMatrix, d.accuracy);
    updateChartDist(d.attackDistribution);
    if (d.accuracyHistory) updateAccChart(d.accuracyHistory);
  }).catch(() => {});
}

// ─── Upload drag and drop ──────────────────────────
const uploadZone = document.getElementById('uploadZone');
uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.style.borderColor = 'var(--cyan)'; });
uploadZone.addEventListener('dragleave', () => { uploadZone.style.borderColor = ''; });
uploadZone.addEventListener('drop', e => {
  e.preventDefault();
  uploadZone.style.borderColor = '';
  const file = e.dataTransfer.files[0];
  if (file && file.name.endsWith('.csv')) {
    const input = document.getElementById('fileInput');
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
    uploadDataset(input);
  }
});
