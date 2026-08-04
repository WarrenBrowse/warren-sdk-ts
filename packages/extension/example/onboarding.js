const steps = {
  choice: document.getElementById('step-choice'),
  password: document.getElementById('step-password'),
  backup: document.getElementById('step-backup'),
  final: document.getElementById('step-final'),
};
const el = (id) => document.getElementById(id);
let mode = 'create';

function show(step) {
  for (const s of Object.values(steps)) s.hidden = true;
  steps[step].hidden = false;
}

function fail(message) {
  const err = el('pw-error');
  err.textContent = message;
  err.hidden = false;
}

el('btn-create').addEventListener('click', () => {
  mode = 'create';
  el('import-field').hidden = true;
  show('password');
});
el('btn-import').addEventListener('click', () => {
  mode = 'import';
  el('import-field').hidden = false;
  show('password');
});

el('btn-password-next').addEventListener('click', async () => {
  const pw1 = el('pw1').value;
  const pw2 = el('pw2').value;
  el('pw-error').hidden = true;
  if (pw1.length < 8) return fail('Use at least 8 characters.');
  if (pw1 !== pw2) return fail('Passwords do not match.');

  if (mode === 'import') {
    const res = await chrome.runtime.sendMessage({
      type: 'importWallet',
      mnemonic: el('import-mnemonic').value.trim().replace(/\s+/g, ' '),
      password: pw1,
    });
    if (!res.ok) return fail('Invalid recovery phrase.');
    el('final-address').textContent = res.address;
    return show('final');
  }

  const res = await chrome.runtime.sendMessage({ type: 'createWallet', password: pw1 });
  if (!res.ok) return fail(res.message ?? 'Could not create wallet.');
  const list = el('seed-words');
  list.textContent = '';
  for (const word of res.mnemonic.split(' ')) {
    const li = document.createElement('li');
    li.textContent = word;
    list.appendChild(li);
  }
  el('final-address').textContent = res.address;
  show('backup');
});

el('ack').addEventListener('change', (e) => {
  el('btn-done').disabled = !e.target.checked;
});
el('btn-done').addEventListener('click', () => show('final'));
