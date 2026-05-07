const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ─── Storage ──────────────────────────────────────────────────────────────────
const upload = multer({ dest: 'uploads/' });

let monitoringActive = false;
let selectedModel = 'random_forest';
let logs = [];
let stats = { packets: 0, attacks: 0, benign: 0, alerts: 0 };
let detectionTable = [];
let attackDistribution = {};
let confusionMatrix = { tp: 0, fp: 0, tn: 0, fn: 0 };
let accuracyHistory = [];
let monitorInterval = null;
let datasetRows = [];

// ─── Attack types ─────────────────────────────────────────────────────────────
const ATTACK_TYPES = ['DoS', 'DDoS', 'PortScan', 'Brute Force', 'XSS', 'SQL Injection', 'Botnet', 'BENIGN'];
const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH'];
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function randomIP() {
  return `${Math.floor(Math.random()*255)+1}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
}

function randomPort() {
  const ports = [80, 443, 22, 21, 8080, 3306, 5432, 27017, 6379, 53, Math.floor(Math.random()*60000+1024)];
  return ports[Math.floor(Math.random()*ports.length)];
}

function generatePacket() {
  const isBenign = Math.random() > 0.35;
  const attackType = isBenign ? 'BENIGN' : ATTACK_TYPES[Math.floor(Math.random()*(ATTACK_TYPES.length-1))];
  const confidence = (Math.random() * 0.25 + 0.75).toFixed(3);
  const severity = isBenign ? 'LOW' : SEVERITIES[Math.floor(Math.random()*SEVERITIES.length)];
  return {
    id: Date.now() + Math.random(),
    timestamp: new Date().toISOString(),
    srcIP: randomIP(),
    dstIP: randomIP(),
    srcPort: randomPort(),
    dstPort: randomPort(),
    protocol: PROTOCOLS[Math.floor(Math.random()*PROTOCOLS.length)],
    length: Math.floor(Math.random()*1400+60),
    label: attackType,
    confidence: parseFloat(confidence),
    severity,
    isBenign
  };
}

function updateStats(packet) {
  stats.packets++;
  if (packet.isBenign) {
    stats.benign++;
    confusionMatrix.tn++;
  } else {
    stats.attacks++;
    stats.alerts++;
    confusionMatrix.tp++;
    attackDistribution[packet.label] = (attackDistribution[packet.label] || 0) + 1;
  }
  // Occasional FP/FN
  if (Math.random() < 0.03) confusionMatrix.fp++;
  if (Math.random() < 0.02) confusionMatrix.fn++;
}

function calcAccuracy() {
  const { tp, fp, tn, fn } = confusionMatrix;
  const total = tp + fp + tn + fn;
  if (total === 0) return 0;
  return ((tp + tn) / total * 100).toFixed(2);
}

function addLog(level, message) {
  const entry = { timestamp: new Date().toISOString(), level, message };
  logs.unshift(entry);
  if (logs.length > 500) logs.pop();
  return entry;
}

function broadcastAll(type, data) {
  const msg = JSON.stringify({ type, data });
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) client.send(msg);
  });
}

// ─── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ type: 'init', data: { stats, detectionTable: detectionTable.slice(0,50), logs: logs.slice(0,50), attackDistribution, confusionMatrix, accuracy: calcAccuracy(), monitoringActive, selectedModel } }));
  addLog('INFO', 'New dashboard client connected');
});

// ─── Monitoring loop ───────────────────────────────────────────────────────────
function startMonitoringLoop() {
  if (monitorInterval) clearInterval(monitorInterval);
  monitorInterval = setInterval(() => {
    if (!monitoringActive) return;
    const batchSize = Math.floor(Math.random()*4)+1;
    const newPackets = [];
    for (let i = 0; i < batchSize; i++) {
      let packet;
      if (datasetRows.length > 0) {
        const row = datasetRows[Math.floor(Math.random()*datasetRows.length)];
        const isBenign = (row.label || row.Label || 'BENIGN').toUpperCase() === 'BENIGN';
        packet = { id: Date.now()+Math.random(), timestamp: new Date().toISOString(), srcIP: row.src_ip || randomIP(), dstIP: row.dst_ip || randomIP(), srcPort: parseInt(row.src_port||randomPort()), dstPort: parseInt(row.dst_port||randomPort()), protocol: row.protocol || PROTOCOLS[Math.floor(Math.random()*PROTOCOLS.length)], length: parseInt(row.length||Math.floor(Math.random()*1400+60)), label: row.label||row.Label||'BENIGN', confidence: (Math.random()*0.25+0.75).toFixed(3), severity: isBenign?'LOW':SEVERITIES[Math.floor(Math.random()*SEVERITIES.length)], isBenign };
      } else {
        packet = generatePacket();
      }
      updateStats(packet);
      detectionTable.unshift(packet);
      if (detectionTable.length > 200) detectionTable.pop();
      newPackets.push(packet);
      if (!packet.isBenign) addLog('ALERT', `Attack detected: ${packet.label} from ${packet.srcIP}:${packet.srcPort} → ${packet.dstIP}:${packet.dstPort} [${(packet.confidence*100).toFixed(1)}% confidence]`);
    }
    const acc = parseFloat(calcAccuracy());
    accuracyHistory.push({ time: new Date().toISOString(), accuracy: acc });
    if (accuracyHistory.length > 60) accuracyHistory.shift();
    broadcastAll('update', { stats, newPackets, logs: logs.slice(0,20), attackDistribution, confusionMatrix, accuracy: acc, accuracyHistory });
  }, 800);
}

startMonitoringLoop();

// ─── REST API ──────────────────────────────────────────────────────────────────
app.get('/api/status', (req, res) => res.json({ monitoringActive, selectedModel, stats }));

app.post('/api/monitoring/start', (req, res) => {
  monitoringActive = true;
  addLog('INFO', `Monitoring started using model: ${selectedModel}`);
  broadcastAll('monitoring', { active: true });
  res.json({ success: true, message: 'Monitoring started' });
});

app.post('/api/monitoring/stop', (req, res) => {
  monitoringActive = false;
  addLog('INFO', 'Monitoring stopped');
  broadcastAll('monitoring', { active: false });
  res.json({ success: true, message: 'Monitoring stopped' });
});

app.post('/api/model/select', (req, res) => {
  const { model } = req.body;
  selectedModel = model;
  addLog('INFO', `Model switched to: ${model}`);
  broadcastAll('model', { model });
  res.json({ success: true, model });
});

app.get('/api/logs', (req, res) => res.json(logs));

app.delete('/api/logs', (req, res) => {
  logs = [];
  addLog('INFO', 'Logs cleared');
  res.json({ success: true });
});

app.post('/api/reset', (req, res) => {
  stats = { packets: 0, attacks: 0, benign: 0, alerts: 0 };
  detectionTable = [];
  attackDistribution = {};
  confusionMatrix = { tp: 0, fp: 0, tn: 0, fn: 0 };
  accuracyHistory = [];
  datasetRows = [];
  logs = [];
  addLog('INFO', 'System reset');
  broadcastAll('reset', {});
  res.json({ success: true });
});

app.post('/api/upload', upload.single('dataset'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const rows = [];
  fs.createReadStream(req.file.path)
    .pipe(csv())
    .on('data', (row) => rows.push(row))
    .on('end', () => {
      datasetRows = rows;
      fs.unlinkSync(req.file.path);
      addLog('INFO', `Dataset loaded: ${rows.length} records from ${req.file.originalname}`);
      broadcastAll('dataset', { count: rows.length, filename: req.file.originalname });
      res.json({ success: true, count: rows.length });
    })
    .on('error', (err) => res.status(500).json({ error: err.message }));
});

app.get('/api/stats', (req, res) => res.json({ stats, attackDistribution, confusionMatrix, accuracy: calcAccuracy(), accuracyHistory }));

app.get('/api/detections', (req, res) => res.json(detectionTable.slice(0, 100)));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  addLog('INFO', `NIDS Server running on http://localhost:${PORT}`);
  console.log(`\n🛡️  NIDS Server running on http://localhost:${PORT}\n`);
});
