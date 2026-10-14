#!/usr/bin/env node
/**
 * Download the Open Cookie Database and write a compact bundled snapshot (no runtime network).
 * Source: https://github.com/jkwakman/Open-Cookie-Database (MIT)
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE =
  process.env.OCDB_URL ||
  'https://raw.githubusercontent.com/jkwakman/Open-Cookie-Database/master/open-cookie-database.json';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outPath = join(root, 'data', 'ocdb.json');

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`Failed to fetch OCDB (${res.status}): ${SOURCE}`);
const raw = await res.json();

/** @type {Array<{ vendor: string; name: string; category: string; domain: string; wildcard: boolean; retentionPeriod?: string }>} */
const entries = [];
for (const [vendor, list] of Object.entries(raw)) {
  if (!Array.isArray(list)) continue;
  for (const row of list) {
    if (!row?.cookie) continue;
    entries.push({
      vendor,
      name: String(row.cookie),
      category: String(row.category || 'Unknown'),
      domain: String(row.domain || ''),
      wildcard: row.wildcardMatch === '1' || row.wildcardMatch === 1,
      retentionPeriod: row.retentionPeriod ? String(row.retentionPeriod) : undefined,
    });
  }
}

entries.sort((a, b) => a.name.localeCompare(b.name) || a.vendor.localeCompare(b.vendor));

const snapshot = {
  source: 'Open Cookie Database (jkwakman/Open-Cookie-Database)',
  sourceUrl: 'https://github.com/jkwakman/Open-Cookie-Database',
  license: 'MIT',
  fetchedAt: new Date().toISOString(),
  entryCount: entries.length,
  entries,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(snapshot));
process.stdout.write(`Wrote ${entries.length} entries to ${outPath}\n`);
