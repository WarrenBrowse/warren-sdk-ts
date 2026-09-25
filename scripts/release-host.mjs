// Drives the helper release (release-host.yml) through the GitHub REST API:
// Node only, because the Windows runner has no gh CLI, and release assets
// only, because the org's Actions artifact quota is exhausted.
//
// The release is created as a draft, every build lane uploads its assets to
// it, and `finalize` checksums what was uploaded, adds SHA256SUMS and
// publishes: nobody can download a half-populated release.
//
//   node scripts/release-host.mjs draft <tag> <title> <prerelease: true|false>   -> prints the release id
//   node scripts/release-host.mjs upload <release id> <file> [asset name]
//   node scripts/release-host.mjs finalize <release id>
//
// Needs GH_TOKEN (or GITHUB_TOKEN) and GITHUB_REPOSITORY.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import process from 'node:process';

const repo = process.env.GITHUB_REPOSITORY;
const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
const [command, ...args] = process.argv.slice(2);
if (!repo || !token || !command) {
  console.error(
    'usage: GH_TOKEN=.. GITHUB_REPOSITORY=owner/repo node release-host.mjs <draft|upload|finalize> ...',
  );
  process.exit(2);
}

const api = `https://api.github.com/repos/${repo}`;
const headers = {
  Authorization: `Bearer ${token}`,
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
};

async function call(method, url, body, contentType) {
  const res = await fetch(url, {
    method,
    headers: contentType ? { ...headers, 'Content-Type': contentType } : headers,
    body,
  });
  if (!res.ok) throw new Error(`${method} ${url} -> ${res.status}: ${await res.text()}`);
  return res.status === 204 ? {} : res.json();
}

async function withRetry(what, fn) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt >= 3) throw error;
      console.warn(`${what} failed (attempt ${attempt}), retrying: ${error.message}`);
      await new Promise((r) => setTimeout(r, 5000 * attempt));
    }
  }
}

/** Drafts are not addressable by tag, so find one by listing. */
async function findRelease(tag) {
  for (let page = 1; page <= 5; page++) {
    const list = await call('GET', `${api}/releases?per_page=100&page=${page}`);
    const hit = list.find((r) => r.tag_name === tag);
    if (hit) return hit;
    if (list.length < 100) return undefined;
  }
  return undefined;
}

async function draft(tag, title, prerelease) {
  // A re-run of the same tag resumes the release it already started.
  const existing = await findRelease(tag);
  if (existing) {
    if (!existing.draft) throw new Error(`${tag} is already published; cut a new version instead`);
    return existing.id;
  }
  const created = await call(
    'POST',
    `${api}/releases`,
    JSON.stringify({
      tag_name: tag,
      name: title,
      draft: true,
      prerelease: prerelease === 'true',
      body: [
        'The Warren browser extension helper: one self-contained binary, installed per user, no administrator rights.',
        '',
        'macOS and Linux:',
        '```',
        `curl -fsSL https://github.com/${repo}/releases/download/${tag}/install.sh | sh`,
        '```',
        'Windows (PowerShell):',
        '```',
        `powershell -ExecutionPolicy Bypass -c "irm https://github.com/${repo}/releases/download/${tag}/install.ps1 | iex"`,
        '```',
        'Or download `Warren-Helper-Setup.exe` (Windows) or `Warren-Helper.pkg` (macOS, unsigned: right click, Open) and open it.',
        '',
        '`SHA256SUMS` covers every asset.',
      ].join('\n'),
    }),
    'application/json',
  );
  return created.id;
}

async function upload(id, file, name = basename(file)) {
  const release = await call('GET', `${api}/releases/${id}`);
  const existing = release.assets.find((a) => a.name === name);
  if (existing) await call('DELETE', `${api}/releases/assets/${existing.id}`);
  const data = readFileSync(file);
  const url = release.upload_url.replace(/\{.*\}$/, `?name=${encodeURIComponent(name)}`);
  await withRetry(`upload ${name}`, () => call('POST', url, data, 'application/octet-stream'));
  console.log(`uploaded ${name} (${data.length} bytes)`);
}

async function download(asset) {
  // The API answers with a redirect to storage; fetch drops the token on the
  // cross-origin hop.
  const res = await fetch(`${api}/releases/assets/${asset.id}`, {
    headers: { ...headers, Accept: 'application/octet-stream' },
  });
  if (!res.ok) throw new Error(`download ${asset.name} -> ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function finalize(id) {
  const release = await call('GET', `${api}/releases/${id}`);
  const assets = release.assets
    .filter((a) => a.name !== 'SHA256SUMS')
    .sort((a, b) => a.name.localeCompare(b.name));
  if (assets.length === 0) throw new Error('the release has no assets');
  let sums = '';
  for (const asset of assets) {
    const data = await withRetry(`download ${asset.name}`, () => download(asset));
    if (data.length !== asset.size)
      throw new Error(`${asset.name}: got ${data.length} bytes, expected ${asset.size}`);
    sums += `${createHash('sha256').update(data).digest('hex')}  ${asset.name}\n`;
  }
  process.stdout.write(sums);
  const existing = release.assets.find((a) => a.name === 'SHA256SUMS');
  if (existing) await call('DELETE', `${api}/releases/assets/${existing.id}`);
  const url = release.upload_url.replace(/\{.*\}$/, '?name=SHA256SUMS');
  await withRetry('upload SHA256SUMS', () => call('POST', url, Buffer.from(sums), 'text/plain'));
  const published = await call(
    'PATCH',
    `${api}/releases/${id}`,
    JSON.stringify({ draft: false }),
    'application/json',
  );
  console.log(`published ${published.html_url}`);
}

switch (command) {
  case 'draft':
    console.log(await draft(...args));
    break;
  case 'upload':
    await upload(...args);
    break;
  case 'finalize':
    await finalize(...args);
    break;
  default:
    console.error(`unknown command ${command}`);
    process.exit(2);
}
