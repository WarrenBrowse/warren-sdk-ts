const els = {
  dot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  btn: document.getElementById('connect-btn'),
  btnLabel: document.getElementById('connect-btn-label'),
  errorLine: document.getElementById('error-line'),
  datapathNote: document.getElementById('datapath-note'),
  country: document.getElementById('country-select'),
  exit: document.getElementById('exit-select'),
  endpoints: document.getElementById('endpoints-panel'),
  socks5: document.getElementById('socks5-addr'),
  httpRow: document.getElementById('http-row'),
  http: document.getElementById('http-addr'),
  optHttp: document.getElementById('opt-http'),
  optDaita: document.getElementById('opt-daita'),
  optIpv6: document.getElementById('opt-ipv6'),
  metricsPanel: document.getElementById('metrics-panel'),
  mSent: document.getElementById('m-sent'),
  mRecv: document.getElementById('m-recv'),
  mPackets: document.getElementById('m-packets'),
  mUptime: document.getElementById('m-uptime'),
  address: document.getElementById('account-address'),
};

const STATE_LABEL = {
  disconnected: 'Disconnected',
  connecting: 'Connecting...',
  reconnecting: 'Reconnecting...',
  draining: 'Disconnecting...',
  connected: 'Connected',
  failed: 'Connection failed',
};

const DOT_CLASS = {
  disconnected: 'dot-disconnected',
  connecting: 'dot-connecting',
  reconnecting: 'dot-connecting',
  draining: 'dot-connecting',
  connected: 'dot-connected',
  failed: 'dot-failed',
};

let status = { state: 'disconnected', datapathAvailable: true };
let requestPending = false;
let metricsTimer = null;

const countryName = (() => {
  try {
    const names = new Intl.DisplayNames(['en'], { type: 'region' });
    return (code) => names.of(code.toUpperCase()) ?? code.toUpperCase();
  } catch {
    return (code) => code.toUpperCase();
  }
})();

async function api(path, options) {
  const res = await fetch(path, options);
  let data = null;
  try {
    data = await res.json();
  } catch {
    // non-JSON body; fall through to the generic error below
  }
  if (!res.ok) {
    const err = new Error(data?.error?.message ?? `request failed (${res.status})`);
    err.code = data?.error?.code;
    throw err;
  }
  return data;
}

function showError(message) {
  els.errorLine.textContent = message ?? '';
  els.errorLine.hidden = !message;
}

function truncateAddress(addr) {
  if (!addr || addr.length <= 16) return addr ?? '';
  return `${addr.slice(0, 10)}…${addr.slice(-6)}`;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

function formatUptime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  return h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
}

function render() {
  const state = status.state;
  els.dot.className = `dot ${DOT_CLASS[state] ?? 'dot-disconnected'}`;
  let text = STATE_LABEL[state] ?? state;
  if (state === 'connected' && status.exit) {
    text = `Connected: ${status.exit.city}, ${countryName(status.exit.country)}`;
  }
  els.statusText.textContent = text;

  const connectedish = state === 'connected' || state === 'reconnecting';
  const busy = requestPending || state === 'connecting' || state === 'draining';
  els.btnLabel.textContent = connectedish ? 'Disconnect' : busy ? 'Wait...' : 'Connect';
  els.btn.classList.toggle('is-connected', connectedish);
  els.btn.classList.toggle('is-busy', busy);
  els.btn.disabled = busy || (!connectedish && !status.datapathAvailable);
  els.btn.setAttribute('aria-label', connectedish ? 'Disconnect' : 'Connect');

  els.datapathNote.hidden = status.datapathAvailable !== false;

  const eps = status.endpoints;
  els.endpoints.hidden = !(state === 'connected' && eps);
  if (eps) {
    els.socks5.textContent = eps.socks5 ?? '';
    els.httpRow.hidden = !eps.http;
    els.http.textContent = eps.http ?? '';
  }

  els.address.textContent = truncateAddress(status.address);

  if (state === 'connected' && !metricsTimer) {
    metricsTimer = setInterval(pollMetrics, 2000);
    pollMetrics();
  } else if (state !== 'connected' && metricsTimer) {
    clearInterval(metricsTimer);
    metricsTimer = null;
    els.metricsPanel.hidden = true;
  }
}

async function pollMetrics() {
  try {
    const { metrics } = await api('/api/metrics');
    if (!metrics) {
      els.metricsPanel.hidden = true;
      return;
    }
    els.metricsPanel.hidden = false;
    els.mSent.textContent = formatBytes(metrics.bytesSent);
    els.mRecv.textContent = formatBytes(metrics.bytesRecv);
    els.mPackets.textContent = `${metrics.packetsSent} / ${metrics.packetsRecv}`;
    els.mUptime.textContent = formatUptime(metrics.uptimeSecs);
  } catch {
    els.metricsPanel.hidden = true;
  }
}

async function loadExits() {
  try {
    const data = await api('/api/exits');
    for (const { code } of data.countries) {
      const opt = document.createElement('option');
      opt.value = code;
      opt.textContent = countryName(code);
      els.country.appendChild(opt);
    }
    for (const exit of data.exits) {
      const opt = document.createElement('option');
      opt.value = exit.pubkeyHex;
      opt.textContent = `${exit.city}, ${countryName(exit.country)} (${exit.pubkeyHex.slice(0, 8)}…)`;
      els.exit.appendChild(opt);
    }
  } catch (err) {
    showError(`Could not load exits: ${err.message}`);
  }
}

async function onButtonClick() {
  if (requestPending) return;
  showError(null);
  requestPending = true;
  render();
  try {
    if (status.state === 'connected' || status.state === 'reconnecting') {
      await api('/api/disconnect', { method: 'POST' });
    } else {
      const body = {
        advanced: {
          httpProxy: els.optHttp.checked,
          daita: els.optDaita.checked,
          requestIpv6: els.optIpv6.checked,
        },
      };
      if (els.exit.value) body.exitPubkeyHex = els.exit.value;
      else if (els.country.value) body.country = els.country.value;
      await api('/api/connect', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    }
  } catch (err) {
    showError(err.message);
  } finally {
    requestPending = false;
    render();
  }
}

function subscribeEvents() {
  const source = new EventSource('/api/events');
  source.addEventListener('state', (event) => {
    status = JSON.parse(event.data);
    render();
  });
  // EventSource reconnects on its own; just reflect the gap in the UI.
  source.onerror = () => {
    els.statusText.textContent = 'UI disconnected from local server';
  };
}

for (const btn of document.querySelectorAll('.copy-btn')) {
  btn.addEventListener('click', async () => {
    const value = document.getElementById(btn.dataset.copy)?.textContent ?? '';
    try {
      await navigator.clipboard.writeText(value);
      const previous = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => {
        btn.textContent = previous;
      }, 1200);
    } catch {
      showError('Clipboard unavailable');
    }
  });
}

els.btn.addEventListener('click', onButtonClick);

api('/api/status')
  .then((s) => {
    status = s;
    render();
  })
  .catch(() => showError('Local server unreachable'));
subscribeEvents();
loadExits();
