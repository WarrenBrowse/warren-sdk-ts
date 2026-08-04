// Publishes one file as an asset on a rolling GitHub release, replacing any
// asset of the same name. Used by the native-prebuilds workflow instead of
// the gh CLI (absent on the Windows runner) and instead of Actions artifacts
// (org storage quota exhausted, and artifacts expire).
//
//   GH_TOKEN=... GITHUB_REPOSITORY=owner/repo \
//     node scripts/publish-prebuild.mjs <tag> <file>

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const [tag, file] = process.argv.slice(2);
const repo = process.env.GITHUB_REPOSITORY;
const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
if (!tag || !file || !repo || !token) {
  console.error(
    'usage: GH_TOKEN=.. GITHUB_REPOSITORY=owner/repo node publish-prebuild.mjs <tag> <file>',
  );
  process.exit(2);
}

const api = 'https://api.github.com';
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
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${method} ${url} -> ${res.status}: ${await res.text()}`);
  return res.status === 204 ? {} : res.json();
}

let release = await call('GET', `${api}/repos/${repo}/releases/tags/${tag}`);
if (!release) {
  console.log(`release ${tag} missing, creating it`);
  try {
    release = await call(
      'POST',
      `${api}/repos/${repo}/releases`,
      JSON.stringify({
        tag_name: tag,
        name: 'Native datapath prebuilds (rolling)',
        body: 'warren-napi addon binaries, refreshed by the native-prebuilds workflow.',
        prerelease: true,
      }),
      'application/json',
    );
  } catch (err) {
    // Two matrix jobs can race the creation; the loser re-reads the winner's.
    release = await call('GET', `${api}/repos/${repo}/releases/tags/${tag}`);
    if (!release) throw err;
  }
}

const assetName = basename(file);
const existing = (release.assets ?? []).find((a) => a.name === assetName);
if (existing) {
  console.log(`replacing existing asset ${assetName}`);
  await call('DELETE', `${api}/repos/${repo}/releases/assets/${existing.id}`);
}

const data = readFileSync(file);
const uploadUrl = release.upload_url.replace(/\{.*\}$/, `?name=${encodeURIComponent(assetName)}`);
const uploaded = await call('POST', uploadUrl, data, 'application/octet-stream');
console.log(`uploaded ${assetName} (${data.length} bytes) -> ${uploaded.browser_download_url}`);
