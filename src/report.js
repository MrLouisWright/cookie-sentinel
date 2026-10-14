import { RULES, SEVERITIES } from './rules.js';

const C = { critical: '\x1b[35;1m', high: '\x1b[31;1m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[2m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m', red: '\x1b[31m', green: '\x1b[32m' };

function summary(counts) {
  const s = SEVERITIES.filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`).join(', ');
  return s || 'no findings';
}

export function formatText(report, { color = false, failOn } = {}) {
  const c = (k, s) => (color ? `${C[k]}${s}${C.reset}` : s);
  const lines = [];
  lines.push(c('bold', `cookie-sentinel — ${report.cookies.length} cookie(s) from ${report.targets.length} target(s)`));
  if (report.classificationSummary) {
    const s = report.classificationSummary;
    lines.push(c('dim', `  classification: ${s.firstParty} first-party, ${s.thirdParty} third-party, ${s.tracking} tracking, ${s.essential} essential (${s.catalogued} in Open Cookie Database)`));
  }
  if (report.crawl) lines.push(c('dim', `  crawl: ${report.crawl.discovered} page(s) discovered (max ${report.crawl.maxPages})`));
  if (report.browser) lines.push(c('dim', `  browser: ${report.browser.engine} captured ${report.browser.cookies} cookie observation(s)`));
  for (const t of report.targets) {
    if (t.error) { lines.push(c('red', `  ✖ ${t.url}: ${t.error}`)); continue; }
    if (t.hops) lines.push(c('dim', `  ${t.hops.map((h) => `${h.status} ${h.url} (${h.cookies} cookie${h.cookies === 1 ? '' : 's'})`).join(' → ')}`));
  }
  lines.push('');
  const groups = new Map();
  for (const f of report.findings) {
    const k = `${f.cookie}  ${c('dim', f.url)}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  for (const [k, list] of groups) {
    lines.push(c('bold', k));
    const f0 = list[0];
    const sample = report.cookies.find((co) => co.name === f0.cookie && co.url === f0.url);
    if (sample?.classification) {
      const cl = sample.classification;
      const bits = [cl.party, cl.purpose !== 'unknown' ? cl.purpose : null, cl.category].filter(Boolean);
      if (bits.length) lines.push(c('dim', `           classification: ${bits.join(' · ')}${cl.vendor ? ` (${cl.vendor})` : ''}`));
    }
    for (const f of list) {
      lines.push(`  ${c(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.message} [${f.rule}]`);
      lines.push(c('dim', `           ↳ fix: ${f.fix}`));
    }
    lines.push('');
  }
  if (report.suppressed.length) lines.push(c('dim', `${report.suppressed.length} finding(s) suppressed by allowlist`));
  lines.push(summary(report.counts));
  if (failOn) {
    const failing = failOn !== 'none' && report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(failOn));
    lines.push(failing ? c('red', `✖ Failing (fail-on: ${failOn}).`) : c('green', `✔ Passing (fail-on: ${failOn}).`));
  }
  return lines.join('\n') + '\n';
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2) + '\n';
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

export function formatSarif(report, { version = '0.0.0' } = {}) {
  const ids = Object.keys(RULES);
  const rules = ids.map((id) => ({
    id, name: id.replace(/(^|-)(\w)/g, (_, __, ch) => ch.toUpperCase()),
    shortDescription: { text: RULES[id].title },
    helpUri: `https://github.com/MrLouisWright/cookie-sentinel#${id}`,
    defaultConfiguration: { level: SARIF_LEVEL[RULES[id].severity] },
    properties: { tags: ['security', 'cookies'], 'security-severity': SCORE[RULES[id].severity] },
  }));
  const results = report.findings.map((f) => ({
    ruleId: f.rule, ruleIndex: ids.indexOf(f.rule), level: SARIF_LEVEL[f.severity],
    message: { text: `${f.message}. Fix: ${f.fix}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: f.url } } }],
    partialFingerprints: { cookieRule: `${f.rule}:${f.cookie}:${f.url}` },
    properties: { cookie: f.cookie, severity: f.severity, 'security-severity': SCORE[f.severity] },
  }));
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{ tool: { driver: { name: 'cookie-sentinel', version, informationUri: 'https://github.com/MrLouisWright/cookie-sentinel', rules } }, results }],
  }, null, 2) + '\n';
}

const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
export function formatMarkdown(report, { failOn } = {}) {
  const l = ['## 🍪 cookie-sentinel', ''];
  l.push(`Audited **${report.cookies.length}** cookie(s) across **${report.targets.length}** target(s): ${summary(report.counts)}.`);
  if (failOn) {
    const failing = failOn !== 'none' && report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(failOn));
    l.push('', failing ? `❌ Failing at \`--fail-on ${failOn}\`.` : `✅ Passing at \`--fail-on ${failOn}\`.`);
  }
  for (const e of report.errors) l.push('', `> ⚠️ ${esc(e.url)}: ${esc(e.error)}`);
  if (report.findings.length) {
    l.push('', '| Severity | Cookie | Rule | Finding | Fix |', '|---|---|---|---|---|');
    for (const f of report.findings) l.push(`| ${f.severity} | \`${esc(f.cookie)}\` | \`${f.rule}\` | ${esc(f.message)} (${esc(f.url)}) | ${esc(f.fix)} |`);
  }
  if (report.suppressed.length) l.push('', `_${report.suppressed.length} finding(s) suppressed by allowlist._`);
  return l.join('\n') + '\n';
}
