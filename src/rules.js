import { lifetimeSeconds, isDeletion } from './parse.js';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const rank = (s) => { const i = SEVERITIES.indexOf(s); return i === -1 ? 99 : i; };

export const DEFAULT_SESSION_PATTERNS = [
  'sess', '^sid$', '[._-]sid$', '^sid[._-]', 'auth', 'token', 'jwt', 'login', 'remember', 'identity', 'credential',
  'access', 'refresh', '^connect\\.sid$', '^phpsessid$', '^jsessionid$', '^asp\\.net_sessionid$', '^\\.aspnetcore\\.', 'user_?id$', '^_?session',
];
export const DEFAULT_NOT_SESSION_PATTERNS = ['csrf', 'xsrf'];

export const RULES = {
  'missing-secure': { severity: 'high', title: 'Cookie without Secure on an HTTPS site' },
  'cookie-over-http': { severity: 'medium', title: 'Cookie set over plain HTTP' },
  'missing-httponly': { severity: 'high', title: 'Session-like cookie readable by JavaScript (no HttpOnly)' },
  'samesite-missing': { severity: 'low', title: 'No SameSite attribute' },
  'samesite-none': { severity: 'low', title: 'SameSite=None sends the cookie on cross-site requests' },
  'samesite-none-insecure': { severity: 'high', title: 'SameSite=None without Secure (rejected by browsers)' },
  'samesite-invalid': { severity: 'medium', title: 'Invalid SameSite value' },
  'host-prefix': { severity: 'high', title: '__Host- prefix rules violated' },
  'secure-prefix': { severity: 'high', title: '__Secure- prefix rules violated' },
  'broad-domain': { severity: 'medium', title: 'Domain attribute widens cookie scope' },
  'domain-mismatch': { severity: 'low', title: 'Domain does not match the setting host (cookie rejected)' },
  'broad-path': { severity: 'info', title: 'Sensitive cookie scoped to Path=/' },
  'long-expiry': { severity: 'medium', title: 'Excessive Expires/Max-Age' },
  'large-cookie': { severity: 'low', title: 'Very large cookie' },
  'sensitive-jwt': { severity: 'medium', title: 'JWT stored in cookie value' },
  'jwt-alg-none': { severity: 'critical', title: 'Unsigned JWT (alg: none) in cookie' },
  'sensitive-email': { severity: 'medium', title: 'Email address in cookie value' },
  'duplicate-cookie': { severity: 'low', title: 'Duplicate cookie' },
  'partitioned-insecure': { severity: 'high', title: 'Partitioned without Secure (rejected by browsers)' },
  'partitioned-misuse': { severity: 'low', title: 'Partitioned attribute misuse' },
};

export function compilePatterns(list) {
  return (list || []).map((p) => (p instanceof RegExp ? p : new RegExp(p, 'i')));
}

export function isSessionLike(name, opts) {
  const not = opts.notSessionRe.some((r) => r.test(name));
  return !not && opts.sessionRe.some((r) => r.test(name));
}

function safeDecode(v) { try { return decodeURIComponent(v); } catch { return v; } }
function b64urlJson(s) {
  try { return JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch { return null; }
}
const JWT_RE = /(eyJ[A-Za-z0-9_-]{4,})\.(eyJ[A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]*)/;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;

const days = (s) => Math.round(s / 86400);

/**
 * Audit a list of observations: { cookie, url, status?, hop? }.
 * Returns raw findings (before severity overrides / allowlist).
 */
export function runRules(observations, opts) {
  const findings = [];
  const now = opts.now ?? Date.now();
  for (const obs of observations) {
    const { cookie: c, url } = obs;
    const a = c.attrs;
    let u; try { u = new URL(url); } catch { u = null; }
    const https = u ? u.protocol === 'https:' : true;
    const host = u ? u.hostname.toLowerCase() : '';
    const session = isSessionLike(c.name, opts);
    const add = (rule, message, fix, extra = {}) => findings.push({ rule, severity: extra.severity || RULES[rule].severity, cookie: c.name, url, message, fix, sessionLike: session, setCookie: c.raw, ...(obs.hop !== undefined ? { hop: obs.hop } : {}) });
    if (isDeletion(c, now)) continue; // clearing a cookie is never a risk
    const ss = a.sameSite === undefined ? undefined : a.sameSite.toLowerCase();

    if (u && u.protocol === 'http:') {
      add('cookie-over-http', `"${c.name}" is set by an http:// response, so it travels in cleartext and can be read or injected by a network attacker`,
        'Serve the site only over HTTPS (redirect http→https before setting cookies, enable HSTS) and add Secure.',
        { severity: session ? 'high' : undefined });
    }
    if (https && !a.secure) {
      add('missing-secure', `"${c.name}" has no Secure attribute; it will be sent over plain HTTP if the user ever hits an http:// URL`,
        `Add Secure: \`Set-Cookie: ${c.name}=…; Secure\`.`, { severity: session ? 'high' : 'medium' });
    }
    if (session && !a.httpOnly) {
      add('missing-httponly', `"${c.name}" looks like a session/auth cookie but lacks HttpOnly, so any XSS can steal it via document.cookie`,
        'Add HttpOnly. If front-end code genuinely needs this value, allowlist it in the config (allow: [{ rule: "missing-httponly", cookie: "' + c.name + '" }]).');
    }
    if (ss === undefined) {
      add('samesite-missing', `"${c.name}" has no SameSite attribute; behaviour depends on the browser default (Lax in Chromium, None in some others)`,
        `Set it explicitly: \`SameSite=Lax\` (or \`Strict\` for ${session ? 'this session cookie' : 'cookies never needed cross-site'}).`,
        { severity: session ? 'medium' : undefined });
    } else if (!['strict', 'lax', 'none'].includes(ss)) {
      add('samesite-invalid', `"${c.name}" has SameSite=${a.sameSite}, which browsers ignore`, 'Use SameSite=Strict, Lax or None.');
    } else if (ss === 'none') {
      if (!a.secure) add('samesite-none-insecure', `"${c.name}" uses SameSite=None without Secure; modern browsers reject the cookie outright`, 'Add Secure (SameSite=None requires it), or use SameSite=Lax.');
      else add('samesite-none', `"${c.name}" is SameSite=None, so it is sent on cross-site requests (CSRF exposure${session ? ' for a session cookie' : ''})`,
        'Use SameSite=Lax unless the cookie is genuinely needed in third-party/iframe contexts; if so, consider Partitioned (CHIPS).',
        { severity: session ? 'medium' : undefined });
    }
    if (c.name.startsWith('__Host-')) {
      const why = [];
      if (!a.secure) why.push('missing Secure');
      if (a.domain !== undefined) why.push(`has Domain=${a.domain}`);
      if (a.path !== '/') why.push(a.path === undefined ? 'missing Path=/' : `Path=${a.path} (must be /)`);
      if (!https) why.push('set from a non-HTTPS origin');
      if (why.length) add('host-prefix', `"${c.name}" violates the __Host- prefix rules (${why.join(', ')}); browsers will reject it`, 'A __Host- cookie must have Secure, Path=/, no Domain and be set over HTTPS.');
    } else if (c.name.startsWith('__Secure-')) {
      const why = [];
      if (!a.secure) why.push('missing Secure');
      if (!https) why.push('set from a non-HTTPS origin');
      if (why.length) add('secure-prefix', `"${c.name}" violates the __Secure- prefix rules (${why.join(', ')}); browsers will reject it`, 'A __Secure- cookie must have Secure and be set over HTTPS.');
    } else if (/^__(host|secure)-/i.test(c.name)) {
      add('host-prefix', `"${c.name}" uses a mis-cased cookie prefix; browsers treat prefixes case-insensitively and will enforce (and likely reject) it`, 'Use the exact prefix `__Host-` or `__Secure-` and follow its rules.', { severity: 'medium' });
    }
    if (a.domain !== undefined && a.domain !== '') {
      const d = a.domain.replace(/^\./, '').toLowerCase();
      if (host && !(host === d || host.endsWith('.' + d))) {
        add('domain-mismatch', `"${c.name}" has Domain=${a.domain}, which does not domain-match ${host}; browsers reject it`, `Remove Domain or set it to ${host}.`);
      } else if (!d.includes('.')) {
        add('broad-domain', `"${c.name}" has Domain=${a.domain} (a top-level domain); browsers reject it, and if accepted it would be sent to every site`, 'Remove the Domain attribute.', { severity: 'high' });
      } else if (host && host !== d) {
        add('broad-domain', `"${c.name}" has Domain=${a.domain}, a parent of ${host}, so every subdomain of ${d} receives${session ? ' (and can overwrite)' : ''} it`,
          `Remove Domain to make it host-only${session ? ' (ideally rename to __Host-' + c.name + ')' : ''}, or scope it to the narrowest host that needs it.`,
          { severity: session ? 'medium' : 'low' });
      } else if (session) {
        add('broad-domain', `"${c.name}" sets Domain=${a.domain}; unlike a host-only cookie it is also sent to all subdomains of ${d}`,
          `Omit the Domain attribute so the cookie stays host-only (consider __Host-${c.name}).`, { severity: 'low' });
      }
    }
    if (session && (a.path === '/' || a.path === undefined) && opts.flagBroadPath !== false) {
      if (a.path === '/') add('broad-path', `"${c.name}" is a sensitive cookie sent to every path on ${host || 'the site'} (Path=/)`,
        'If only part of the site needs it (e.g. /api or /admin), set a narrower Path. Note Path is not a security boundary against same-origin scripts.');
    }
    const life = lifetimeSeconds(c, now);
    if (life !== null) {
      const limit = (session ? opts.sessionMaxAgeDays : opts.maxAgeDays) * 86400;
      if (life > limit) {
        add('long-expiry', `"${c.name}" lives for ${days(life)} days (limit ${session ? opts.sessionMaxAgeDays : opts.maxAgeDays} for ${session ? 'session-like' : 'other'} cookies)`,
          session ? 'Shorten the lifetime (hours to days for sessions) and rotate on use; prefer short-lived sessions with server-side refresh.' : 'Lower Max-Age; browsers cap cookie lifetimes at 400 days anyway.',
          { severity: session ? 'medium' : 'low' });
      }
    }
    const size = Buffer.byteLength(c.name + c.value);
    if (size > opts.largeBytes) {
      add('large-cookie', `"${c.name}" is ${size} bytes (limit ${opts.largeBytes}); browsers drop cookies over 4096 bytes and big cookies bloat every request`,
        'Store the data server-side and keep only an opaque identifier in the cookie.', { severity: size > 4096 ? 'medium' : undefined });
    }
    const decoded = safeDecode(c.value);
    const jwt = decoded.match(JWT_RE);
    if (jwt) {
      const header = b64urlJson(jwt[1]);
      const payload = b64urlJson(jwt[2]);
      if (header && String(header.alg).toLowerCase() === 'none') {
        add('jwt-alg-none', `"${c.name}" holds an unsigned JWT (alg: none); anyone can forge it`, 'Never accept alg "none": sign tokens (RS256/ES256/HS256) and verify the algorithm server-side.');
      }
      const claims = payload ? Object.keys(payload).slice(0, 8).join(', ') : 'unreadable';
      add('sensitive-jwt', `"${c.name}" contains a JWT whose payload is readable by anyone holding the cookie (claims: ${claims})`,
        `JWT payloads are only base64-encoded, not encrypted. Keep PII out of the claims or use an opaque session id${a.httpOnly ? '' : ', and add HttpOnly'}.`,
        { severity: (!a.httpOnly) ? 'high' : undefined });
      if (payload && EMAIL_RE.test(JSON.stringify(payload))) {
        add('sensitive-email', `"${c.name}" JWT payload contains an email address`, 'Remove personal data from token claims; use an opaque user id.');
      }
    } else if (EMAIL_RE.test(decoded) || EMAIL_RE.test(tryBase64(decoded))) {
      add('sensitive-email', `"${c.name}" value contains an email address`, 'Do not store personal data in cookies; keep it server-side and reference it with an opaque id.');
    }
    if (a.partitioned) {
      if (!a.secure) add('partitioned-insecure', `"${c.name}" is Partitioned without Secure; browsers reject it`, 'Add Secure (CHIPS requires it).');
      if (ss !== 'none') add('partitioned-misuse', `"${c.name}" is Partitioned but SameSite=${a.sameSite ?? '(unset)'}; partitioning only matters for cookies sent in cross-site contexts`,
        'Use Partitioned together with SameSite=None; Secure for embedded/third-party cookies, or drop Partitioned for first-party cookies.');
      if (session && ss === 'none' && !opts.thirdParty) add('partitioned-misuse', `"${c.name}" is a session-like cookie marked Partitioned; it will not be shared between top-level sites, which can silently break SSO`,
        'Confirm the cookie is only needed inside a single embedding site; otherwise remove Partitioned.', { severity: 'info' });
    }
  }
  findings.push(...duplicates(observations, now));
  return findings;
}

function tryBase64(v) {
  if (!/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(v)) return '';
  try { return Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'); } catch { return ''; }
}

function duplicates(observations, now) {
  const out = [];
  const byResp = new Map();
  const byName = new Map();
  for (const o of observations) {
    if (isDeletion(o.cookie, now)) continue;
    let host = ''; try { host = new URL(o.url).hostname; } catch {}
    const scope = `${(o.cookie.attrs.domain || host).replace(/^\./, '').toLowerCase()}|${o.cookie.attrs.path || '/'}`;
    const rk = `${o.url}#${o.hop ?? 0}#${o.response ?? ''}|${o.cookie.name}|${scope}`;
    byResp.set(rk, (byResp.get(rk) || []).concat(o));
    const nk = o.cookie.name;
    if (!byName.has(nk)) byName.set(nk, new Map());
    const m = byName.get(nk);
    m.set(scope, (m.get(scope) || []).concat(o));
  }
  for (const [, list] of byResp) {
    if (list.length > 1) {
      const o = list[0];
      out.push({ rule: 'duplicate-cookie', severity: 'low', cookie: o.cookie.name, url: o.url, message: `"${o.cookie.name}" is set ${list.length} times in the same response; only the last one wins`, fix: 'Emit each cookie once per response (check middleware/framework layers that both set it).', setCookie: list.map((x) => x.cookie.raw).join('\n') });
    }
  }
  for (const [name, scopes] of byName) {
    if (scopes.size > 1) {
      const all = [...scopes.values()].map((l) => l[0]);
      out.push({ rule: 'duplicate-cookie', severity: 'medium', cookie: name, url: all[0].url, message: `"${name}" is set with ${scopes.size} different Domain/Path scopes (${[...scopes.keys()].map((k) => k.replace('|', ' path ')).join('; ')}); the browser keeps both and sends both, enabling cookie-tossing/shadowing`, fix: 'Use one consistent Domain and Path for each cookie name (prefer host-only, Path=/, and a __Host- prefix).', setCookie: all.map((x) => x.cookie.raw).join('\n') });
    }
  }
  return out;
}
