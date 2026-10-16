const themeToggle = document.getElementById('theme-toggle');
const html = document.documentElement;

const saved = localStorage.getItem('theme');
if (saved) {
  html.setAttribute('data-theme', saved);
}

themeToggle.addEventListener('click', () => {
  const current = html.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
});

function badge(state) {
  const s = String(state).toLowerCase();
  if (s === 'running' || s === 'up') return '<span class="badge ok">' + state + '</span>';
  if (s === 'stopped' || s === 'exited' || s === 'not found') return '<span class="badge bad">' + state + '</span>';
  return '<span class="badge">' + state + '</span>';
}

async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    const statusList = document.getElementById('status-list');
    statusList.innerHTML = Object.entries(data.containers).map(([name, state]) =>
      `<div class="status-row"><span>${name}</span>${badge(state)}</div>`
    ).join('');

    const serviceList = document.getElementById('service-list');
    const services = Object.entries(data.services).sort((a, b) => a[0].localeCompare(b[0]));
    serviceList.innerHTML = services.map(([name, state]) =>
      `<div class="status-row"><span>${name}</span>${badge(state)}</div>`
    ).join('');
  } catch (e) {
    document.getElementById('status-list').textContent = 'Error loading status';
    document.getElementById('service-list').textContent = 'Error loading services';
  }
}

function levelColor(level) {
  const l = parseInt(level, 10);
  if (l >= 12) return 'var(--bad)';
  if (l >= 8) return 'var(--warn)';
  if (l >= 4) return 'var(--accent)';
  return 'var(--muted)';
}

async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    const data = await res.json();

    document.getElementById('total-alerts').textContent = data.total;

    const mitreList = document.getElementById('mitre-list');
    mitreList.innerHTML = data.top_mitre.map(([id, count]) =>
      `<li><span>${id}</span><span class="count">${count}</span></li>`
    ).join('') || '<li class="count">No MITRE-tagged alerts</li>';

    const severityList = document.getElementById('severity-list');
    severityList.innerHTML = Object.entries(data.severity).map(([level, count]) =>
      `<li><span>Level ${level}</span><span class="count">${count}</span></li>`
    ).join('') || '<li class="count">No alerts</li>';

    const tbody = document.getElementById('recent-alerts');
    tbody.innerHTML = data.recent.map(a => {
      const mitre = Array.isArray(a.mitre) && a.mitre.length ? a.mitre.join(', ') : '-';
      const time = a.timestamp ? a.timestamp.replace('T', ' ').split('.')[0] : '-';
      return `<tr>
        <td>${time}</td>
        <td class="level" style="color:${levelColor(a.level)}">${a.level}</td>
        <td>${a.rule_id}</td>
        <td>${a.agent}</td>
        <td>${mitre}</td>
        <td>${a.description}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    document.getElementById('recent-alerts').innerHTML = '<tr><td colspan="6">Error loading alerts</td></tr>';
  }
}

function init() {
  loadStatus();
  loadAlerts();
  setInterval(() => {
    loadStatus();
    loadAlerts();
  }, 5000);
}

init();
