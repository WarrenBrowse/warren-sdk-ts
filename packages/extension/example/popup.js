const els = {
  unlockView: document.getElementById('unlock-view'),
  onboardView: document.getElementById('onboard-view'),
  vpnView: document.getElementById('vpn-view'),
  password: document.getElementById('password'),
  unlockBtn: document.getElementById('unlock-btn'),
  onboardBtn: document.getElementById('onboard-btn'),
  dot: document.getElementById('dot'),
  state: document.getElementById('state'),
  toggle: document.getElementById('toggle'),
  error: document.getElementById('error'),
  country: document.getElementById('country'),
  splitMode: document.getElementById('split-mode'),
  rulesField: document.getElementById('rules-field'),
  rules: document.getElementById('split-rules'),
  address: document.getElementById('address'),
};

const DOT_CLASS = {
  connected: 'dot-connected',
  connecting: 'dot-connecting',
  reconnecting: 'dot-connecting',
  draining: 'dot-connecting',
  failed: 'dot-failed',
  disconnected: 'dot-disconnected',
};

let connected = false;

function render(state) {
  connected = state === 'connected';
  els.state.textContent = state.charAt(0).toUpperCase() + state.slice(1);
  els.dot.className = `dot ${DOT_CLASS[state] ?? 'dot-disconnected'}`;
  els.toggle.textContent = connected ? 'Disconnect' : 'Connect';
  els.toggle.classList.toggle('is-connected', connected);
}

function showError(message) {
  els.error.textContent = message;
  els.error.hidden = !message;
}

function splitConfig() {
  const mode = els.splitMode.value;
  const rules = els.rules.value
    .split('\n')
    .map((r) => r.trim())
    .filter((r) => r.length > 0);
  return { mode, rules };
}

els.splitMode.addEventListener('change', () => {
  els.rulesField.hidden = els.splitMode.value === 'all';
});

function showView(view) {
  els.unlockView.hidden = view !== 'unlock';
  els.onboardView.hidden = view !== 'onboard';
  els.vpnView.hidden = view !== 'vpn';
}

async function refresh() {
  // Default to onboarding if the background is not answering yet, so the popup
  // is never blank.
  const wallet = await chrome.runtime.sendMessage({ type: 'walletState' }).catch(() => null);
  if (!wallet?.ok || !wallet.hasVault) return void showView('onboard');
  if (!wallet.unlocked) return void showView('unlock');
  showView('vpn');
  const res = await chrome.runtime.sendMessage({ type: 'status' }).catch(() => null);
  render(res?.ok ? res.status.state : 'disconnected');
}

els.onboardBtn.addEventListener('click', () => {
  void chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
});

els.unlockBtn.addEventListener('click', async () => {
  showError('');
  els.unlockBtn.disabled = true;
  const res = await chrome.runtime.sendMessage({ type: 'unlock', password: els.password.value });
  els.unlockBtn.disabled = false;
  if (!res.ok) return void showError('Wrong password.');
  els.password.value = '';
  await refresh();
});

els.toggle.addEventListener('click', async () => {
  showError('');
  els.toggle.disabled = true;
  const message = connected
    ? { type: 'disconnect' }
    : {
        type: 'connect',
        selector: els.country.value ? { country: els.country.value } : undefined,
        split: splitConfig(),
      };
  const res = await chrome.runtime.sendMessage(message);
  if (!res.ok) showError(res.message ?? `error: ${res.code ?? 'unknown'}`);
  if (res.ok && res.endpoints?.socks5) els.address.textContent = res.endpoints.socks5;
  await refresh();
  els.toggle.disabled = false;
});

void refresh();
