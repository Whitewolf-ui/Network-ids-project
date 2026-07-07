const POLL_MS = 2500;

const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const statusPill = document.getElementById('status-pill');
const statusText = document.getElementById('status-text');
const ifaceLabel = document.getElementById('iface-label');
const feedEl = document.getElementById('feed');
const feedCount = document.getElementById('feed-count');
const topIpsEl = document.getElementById('top-ips');

let lastAlertCount = 0;
let pulseEvents = [];

async function postJSON(url) {
  const res = await fetch(url, { method: 'POST' });
  return res.json();
}
async function getJSON(url) {
  const res = await fetch(url);
  return res.json();
}

btnStart.addEventListener('click', async () => {
  btnStart.disabled = true;
  const r = await postJSON('/api/monitoring/start');
  btnStart.disabled = false;
  if (!r.ok) alert(r.message);
  refreshStatus();
});

btnStop.addEventListener('click', async () => {
  btnStop.disabled = true;
  const r = await postJSON('/api/monitoring/stop');
  btnStop.disabled = false;
  if (!r.ok) alert(r.message);
  refreshStatus();
});

function setRunningUI(running, iface) {
  if (running) {
    statusPill.classList.add('live');
    statusText.textContent = 'Monitoring live';
    btnStart.style.display = 'none';
    btnStop.style.display = 'inline-block';
  } else {
    statusPill.classList.remove('live');
    statusText.textContent = 'Idle';
    btnStart.style.display = 'inline-block';
    btnStop.style.display = 'none';
  }
  ifaceLabel.textContent = 'iface: ' + (iface || '—');
}

async function refreshStatus() {
  const s = await getJSON('/api/status');
  setRunningUI(s.running, s.iface);
  if (s.error) {
    statusText.textContent = 'Error';
  }
}

function timeAgoLabel(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function renderFeed(alerts) {
  if (!alerts.length) {
    feedEl.innerHTML = '<div class="empty-state">No alerts yet. Start monitoring to begin watching traffic.</div>';
    feedCount.textContent = '0 alerts';
    return;
  }
  feedCount.textContent = alerts.length + (alerts.length === 1 ? ' alert' : ' alerts') + ' shown';
  feedEl.innerHTML = alerts.map(a => {
    const tagLabel = a.alert_type === 'port_scan' ? 'Port scan' : 'Sensitive port';
    const desc = a.alert_type === 'port_scan'
      ? `${a.unique_ports} unique ports probed`
      : (a.details || `Connection to port ${a.dest_port}`);
    return `
      <div class="feed-row">
        <span class="feed-time">${timeAgoLabel(a.timestamp)}</span>
        <div class="feed-detail">
          <span class="ip">${a.source_ip}</span>
          <div class="desc">${desc}</div>
        </div>
        <span class="tag ${a.alert_type}">${tagLabel}</span>
      </div>`;
  }).join('');

  if (alerts.length > lastAlertCount) {
    pulseEvents.push(1.0);
  }
  lastAlertCount = alerts.length;
}

function renderStats(stats) {
  document.getElementById('stat-total').textContent = stats.total_alerts;
  document.getElementById('stat-scans').textContent = stats.port_scans;
  document.getElementById('stat-sensitive').textContent = stats.sensitive_port_hits;
  document.getElementById('stat-ips').textContent = stats.unique_ips;
  document.getElementById('stat-hour').textContent = stats.alerts_last_hour;

  if (!stats.top_ips.length) {
    topIpsEl.innerHTML = '<div class="empty-state">No data yet.</div>';
  } else {
    topIpsEl.innerHTML = stats.top_ips.map(row => `
      <div class="top-ip-row">
        <span class="ip">${row.source_ip}</span>
        <span class="count">${row.c}</span>
      </div>`).join('');
  }
}

async function refreshAlerts() {
  const alerts = await getJSON('/api/alerts?limit=40');
  renderFeed(alerts);

  const watchCounts = {};
  alerts.forEach(a => {
    if (a.alert_type === 'sensitive_port' && a.dest_port) {
      watchCounts[a.dest_port] = (watchCounts[a.dest_port] || 0) + 1;
    }
  });
  document.querySelectorAll('[id^="watch-"]').forEach(el => {
    const port = el.id.replace('watch-', '');
    el.textContent = watchCounts[port] || 0;
  });
}

async function refreshStats() {
  const stats = await getJSON('/api/stats');
  renderStats(stats);
}

/* ---------- trend chart ---------- */
let trendChart;
async function refreshChart() {
  const data = await getJSON('/api/chart-data?minutes=30');
  if (!trendChart) {
    const ctx = document.getElementById('trend-chart').getContext('2d');
    trendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [{
          data: data.values,
          borderColor: '#0EA5A0',
          backgroundColor: 'rgba(14,165,160,0.08)',
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.35,
          fill: true,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: { display: false, beginAtZero: true }
        }
      }
    });
  } else {
    trendChart.data.labels = data.labels;
    trendChart.data.datasets[0].data = data.values;
    trendChart.update('none');
  }
}

/* ---------- pulse strip (signature element) ---------- */
const pulseCanvas = document.getElementById('pulse');
const pctx = pulseCanvas.getContext('2d');
let phase = 0;

function drawPulse() {
  const w = pulseCanvas.width, h = pulseCanvas.height;
  pctx.clearRect(0, 0, w, h);
  pctx.strokeStyle = '#0EA5A0';
  pctx.lineWidth = 1.6;
  pctx.beginPath();

  const midline = h / 2;
  let spike = 0;
  if (pulseEvents.length) {
    spike = pulseEvents.reduce((a, b) => a + b, 0);
    pulseEvents = pulseEvents.map(v => v * 0.85).filter(v => v > 0.03);
  }

  for (let x = 0; x < w; x++) {
    const t = (x + phase) * 0.06;
    const baseline = Math.sin(t) * 2.2;
    const jitter = Math.sin(t * 5.3) * (0.6 + spike * 3);
    const y = midline - baseline - jitter;
    if (x === 0) pctx.moveTo(x, y);
    else pctx.lineTo(x, y);
  }
  pctx.stroke();
  phase += 1.4;
  requestAnimationFrame(drawPulse);
}

/* ---------- init ---------- */
function resizeCanvas() {
  pulseCanvas.width = pulseCanvas.clientWidth;
  pulseCanvas.height = 46;
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();
requestAnimationFrame(drawPulse);

refreshStatus();
refreshAlerts();
refreshStats();
refreshChart();

setInterval(refreshStatus, POLL_MS);
setInterval(refreshAlerts, POLL_MS);
setInterval(refreshStats, POLL_MS);
setInterval(refreshChart, 10000);
