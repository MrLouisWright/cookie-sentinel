#!/usr/bin/env node
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';
import { spawnSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

await esbuild.build({
  entryPoints: [join(root, 'src/index.js')],
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'cjs',
  outfile: join(dist, 'index.cjs'),
  sourcemap: true,
  logLevel: 'info',
  define: { 'import.meta.url': 'import_meta_url' },
  banner: {
    js: "const { pathToFileURL } = require('node:url'); const import_meta_url = pathToFileURL(__filename).href;",
  },
});

const tsc = spawnSync(
  process.platform === 'win32' ? 'npx.cmd' : 'npx',
  ['tsc', '-p', 'tsconfig.json'],
  { cwd: root, stdio: 'inherit' },
);
if (tsc.status !== 0) process.exit(tsc.status ?? 1);

process.stdout.write('Build complete: dist/index.cjs + dist/*.d.ts\n');
