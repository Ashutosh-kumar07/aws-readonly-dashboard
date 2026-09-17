/**
 * Post-build step: make the CLI executable and verify the published entry
 * points actually exist before anything is packed.
 */

import { chmod, readFile, access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const required = ['dist/cli.js', 'dist/index.js', 'dist/index.d.ts', 'public/index.html'];

for (const relative of required) {
  const path = join(root, relative);
  try {
    await access(path, constants.F_OK);
  } catch {
    console.error(`Build verification failed: ${relative} is missing.`);
    process.exit(1);
  }
}

const cliPath = join(root, 'dist/cli.js');
const cli = await readFile(cliPath, 'utf8');
if (!cli.startsWith('#!')) {
  console.error('Build verification failed: dist/cli.js has no shebang.');
  process.exit(1);
}

await chmod(cliPath, 0o755);
console.log('Build verified: dist/cli.js is executable and entry points are present.');
