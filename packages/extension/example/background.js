// Example MV3 service worker: the wallet + VPN brain. Bundle
// `@warrenbrowse/sdk-extension` into ./sdk-extension.js (see example/README.md).
// The mnemonic lives encrypted in the extension vault and is handed to the
// local native host only at connect time; it never touches a page or the network.
import { WarrenBrowserVpn, WarrenKeyring, chromeStorageArea } from './sdk-extension.js';

const keyring = new WarrenKeyring({
  local: chromeStorageArea(chrome.storage.local),
  session: chromeStorageArea(chrome.storage.session),
});

let vpn;
function getVpn() {
  vpn ??= new WarrenBrowserVpn({
    onState: (state) => void chrome.storage.session.set({ vpnState: state }),
  });
  return vpn;
}

// Open the full-tab onboarding on first install (a popup is too small and
// closes on focus loss, dangerous mid-backup).
chrome.runtime.onInstalled.addListener(async () => {
  if (!(await keyring.hasVault())) {
    await chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
  }
});

async function ensureUnlocked() {
  if (!keyring.isUnlocked()) await keyring.rehydrate();
  return keyring.isUnlocked();
}

const handlers = {
  async walletState() {
    const hasVault = await keyring.hasVault();
    const unlocked = await ensureUnlocked();
    return { ok: true, hasVault, unlocked };
  },
  async createWallet({ password }) {
    const mnemonic = await keyring.create(password);
    return { ok: true, mnemonic, address: await keyring.getAddress() };
  },
  async importWallet({ mnemonic, password }) {
    await keyring.import(mnemonic, password);
    return { ok: true, address: await keyring.getAddress() };
  },
  async unlock({ password }) {
    await keyring.unlock(password);
    return { ok: true, address: await keyring.getAddress() };
  },
  async lock() {
    keyring.lock();
    return { ok: true };
  },
  async status() {
    const unlocked = await ensureUnlocked();
    const status = unlocked
      ? await getVpn()
          .status()
          .catch(() => ({ state: 'disconnected' }))
      : { state: 'disconnected' };
    return { ok: true, unlocked, status };
  },
  async connect(message) {
    if (!(await ensureUnlocked()))
      return { ok: false, code: 'locked', message: 'wallet is locked' };
    const mnemonic = await keyring.getMnemonic();
    const endpoints = await getVpn().connect({
      mnemonic,
      selector: message.selector,
      split: message.split,
    });
    await chrome.storage.session.set({ vpnState: 'connected' });
    return { ok: true, endpoints };
  },
  async disconnect() {
    await getVpn().disconnect();
    await chrome.storage.session.set({ vpnState: 'disconnected' });
    return { ok: true };
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Sender identity is browser-process-authenticated; only our own pages drive it.
  if (sender.id !== chrome.runtime.id) return false;
  const handler = handlers[message?.type];
  if (!handler) return false;
  handler(message)
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, code: error.code, message: error.message }));
  return true;
});
