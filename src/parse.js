// Set-Cookie parsing (RFC 6265bis, lenient like browsers).

/** Parse one Set-Cookie header value. Returns null for unparseable input. */
export function parseSetCookie(header) {
  if (typeof header !== 'string') return null;
  const raw = header.replace(/^\s*set-cookie\s*:\s*/i, '').trim();
  if (!raw) return null;
  const parts = raw.split(';');
  const pair = parts.shift();
  const eq = pair.indexOf('=');
  if (eq === -1) return null; // nameless cookies are ignored here
  const name = pair.slice(0, eq).trim();
  let value = pair.slice(eq + 1).trim();
  if (!name) return null;
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
  const attrs = { secure: false, httpOnly: false, partitioned: false, sameSite: undefined, domain: undefined, path: undefined, expires: undefined, maxAge: undefined, unknown: [] };
  const seen = {};
  for (const p of parts) {
    const i = p.indexOf('=');
    const key = (i === -1 ? p : p.slice(0, i)).trim().toLowerCase();
    const val = i === -1 ? '' : p.slice(i + 1).trim();
    if (!key) continue;
    seen[key] = true;
    switch (key) {
      case 'secure': attrs.secure = true; break;
      case 'httponly': attrs.httpOnly = true; break;
      case 'partitioned': attrs.partitioned = true; break;
      case 'samesite': attrs.sameSite = val; break;
      case 'domain': attrs.domain = val; break;
      case 'path': attrs.path = val; break;
      case 'expires': { const d = Date.parse(val); attrs.expires = Number.isNaN(d) ? undefined : new Date(d); attrs.expiresRaw = val; break; }
      case 'max-age': { if (/^-?\d+$/.test(val)) attrs.maxAge = Number(val); break; }
      default: attrs.unknown.push(key);
    }
  }
  return { name, value, attrs, raw };
}

/** Lifetime in seconds (Max-Age wins over Expires), null for session cookies. */
export function lifetimeSeconds(cookie, now = Date.now()) {
  const { maxAge, expires } = cookie.attrs;
  if (maxAge !== undefined) return maxAge;
  if (expires) return Math.round((expires.getTime() - now) / 1000);
  return null;
}

export function isDeletion(cookie, now = Date.now()) {
  const l = lifetimeSeconds(cookie, now);
  return l !== null && l <= 0;
}

/** Split a folded "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT, b=2" header into cookies. */
export function splitCookiesString(str) {
  if (Array.isArray(str)) return str.flatMap(splitCookiesString);
  if (typeof str !== 'string' || !str.trim()) return [];
  const out = [];
  let start = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] !== ',') continue;
    // A comma starts a new cookie if what follows looks like "name=" before any ';'
    const rest = str.slice(i + 1);
    if (/^\s*[^=;,\s]+=/.test(rest) && !/^\s*\d{2}[ -]/.test(rest)) {
      out.push(str.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(str.slice(start).trim());
  return out.filter(Boolean);
}
