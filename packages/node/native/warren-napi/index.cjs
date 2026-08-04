'use strict';

// Loads the Warren native datapath addon. Tries the triple-suffixed name first
// (what `napi build --platform` and the per-OS prebuilds emit), then the plain
// local-build name.
const { existsSync } = require('node:fs');
const { join } = require('node:path');

const candidates = [
  `warren-napi.${process.platform}-${process.arch}.node`,
  'warren-napi.node',
];

let binding;
for (const name of candidates) {
  const path = join(__dirname, name);
  if (existsSync(path)) {
    binding = require(path);
    break;
  }
}

if (!binding) {
  throw new Error(
    `@warrenbrowse/sdk-node: no native datapath binary for ${process.platform}-${process.arch}. ` +
      'Build it with `napi build --release` in packages/node/native/warren-napi, or install a prebuilt.',
  );
}

module.exports = binding;
