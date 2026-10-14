const { pathToFileURL } = require('node:url'); const import_meta_url = pathToFileURL(__filename).href;
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.js
var index_exports = {};
__export(index_exports, {
  DEFAULTS: () => DEFAULTS,
  RULES: () => RULES,
  SEVERITIES: () => SEVERITIES,
  applyConfig: () => applyConfig,
  auditObservations: () => auditObservations,
  auditSetCookies: () => auditSetCookies,
  auditUrls: () => auditUrls,
  classifyCookie: () => classifyCookie,
  collect: () => collect,
  collectBrowser: () => collectBrowser,
  databaseMeta: () => databaseMeta,
  discoverPages: () => discoverPages,
  exceeds: () => exceeds,
  expandTargets: () => expandTargets,
  formatJson: () => formatJson,
  formatMarkdown: () => formatMarkdown,
  formatSarif: () => formatSarif,
  formatText: () => formatText,
  isSessionLike: () => isSessionLike,
  lifetimeSeconds: () => lifetimeSeconds,
  loadCookiesFile: () => loadCookiesFile,
  loadHeadersFile: () => loadHeadersFile,
  lookupOpenCookieDatabase: () => lookupOpenCookieDatabase,
  mergeCookieHeader: () => mergeCookieHeader,
  mergeCrawlTargets: () => mergeCrawlTargets,
  parseSetCookie: () => parseSetCookie,
  resolveOptions: () => resolveOptions,
  runLogin: () => runLogin,
  splitCookiesString: () => splitCookiesString
});
module.exports = __toCommonJS(index_exports);

// src/parse.js
function parseSetCookie(header) {
  if (typeof header !== "string") return null;
  const raw = header.replace(/^\s*set-cookie\s*:\s*/i, "").trim();
  if (!raw) return null;
  const parts = raw.split(";");
  const pair = parts.shift();
  const eq = pair.indexOf("=");
  if (eq === -1) return null;
  const name = pair.slice(0, eq).trim();
  let value = pair.slice(eq + 1).trim();
  if (!name) return null;
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
  const attrs = { secure: false, httpOnly: false, partitioned: false, sameSite: void 0, domain: void 0, path: void 0, expires: void 0, maxAge: void 0, unknown: [] };
  const seen = {};
  for (const p of parts) {
    const i = p.indexOf("=");
    const key = (i === -1 ? p : p.slice(0, i)).trim().toLowerCase();
    const val = i === -1 ? "" : p.slice(i + 1).trim();
    if (!key) continue;
    seen[key] = true;
    switch (key) {
      case "secure":
        attrs.secure = true;
        break;
      case "httponly":
        attrs.httpOnly = true;
        break;
      case "partitioned":
        attrs.partitioned = true;
        break;
      case "samesite":
        attrs.sameSite = val;
        break;
      case "domain":
        attrs.domain = val;
        break;
      case "path":
        attrs.path = val;
        break;
      case "expires": {
        const d = Date.parse(val);
        attrs.expires = Number.isNaN(d) ? void 0 : new Date(d);
        attrs.expiresRaw = val;
        break;
      }
      case "max-age": {
        if (/^-?\d+$/.test(val)) attrs.maxAge = Number(val);
        break;
      }
      default:
        attrs.unknown.push(key);
    }
  }
  return { name, value, attrs, raw };
}
function lifetimeSeconds(cookie, now = Date.now()) {
  const { maxAge, expires } = cookie.attrs;
  if (maxAge !== void 0) return maxAge;
  if (expires) return Math.round((expires.getTime() - now) / 1e3);
  return null;
}
function isDeletion(cookie, now = Date.now()) {
  const l = lifetimeSeconds(cookie, now);
  return l !== null && l <= 0;
}
function splitCookiesString(str) {
  if (Array.isArray(str)) return str.flatMap(splitCookiesString);
  if (typeof str !== "string" || !str.trim()) return [];
  const out = [];
  let start = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] !== ",") continue;
    const rest = str.slice(i + 1);
    if (/^\s*[^=;,\s]+=/.test(rest) && !/^\s*\d{2}[ -]/.test(rest)) {
      out.push(str.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(str.slice(start).trim());
  return out.filter(Boolean);
}

// src/rules.js
var SEVERITIES = ["critical", "high", "medium", "low", "info"];
var rank = (s) => {
  const i = SEVERITIES.indexOf(s);
  return i === -1 ? 99 : i;
};
var DEFAULT_SESSION_PATTERNS = [
  "sess",
  "^sid$",
  "[._-]sid$",
  "^sid[._-]",
  "auth",
  "token",
  "jwt",
  "login",
  "remember",
  "identity",
  "credential",
  "access",
  "refresh",
  "^connect\\.sid$",
  "^phpsessid$",
  "^jsessionid$",
  "^asp\\.net_sessionid$",
  "^\\.aspnetcore\\.",
  "user_?id$",
  "^_?session"
];
var DEFAULT_NOT_SESSION_PATTERNS = ["csrf", "xsrf"];
var RULES = {
  "missing-secure": { severity: "high", title: "Cookie without Secure on an HTTPS site" },
  "cookie-over-http": { severity: "medium", title: "Cookie set over plain HTTP" },
  "missing-httponly": { severity: "high", title: "Session-like cookie readable by JavaScript (no HttpOnly)" },
  "samesite-missing": { severity: "low", title: "No SameSite attribute" },
  "samesite-none": { severity: "low", title: "SameSite=None sends the cookie on cross-site requests" },
  "samesite-none-insecure": { severity: "high", title: "SameSite=None without Secure (rejected by browsers)" },
  "samesite-invalid": { severity: "medium", title: "Invalid SameSite value" },
  "host-prefix": { severity: "high", title: "__Host- prefix rules violated" },
  "secure-prefix": { severity: "high", title: "__Secure- prefix rules violated" },
  "broad-domain": { severity: "medium", title: "Domain attribute widens cookie scope" },
  "domain-mismatch": { severity: "low", title: "Domain does not match the setting host (cookie rejected)" },
  "broad-path": { severity: "info", title: "Sensitive cookie scoped to Path=/" },
  "long-expiry": { severity: "medium", title: "Excessive Expires/Max-Age" },
  "large-cookie": { severity: "low", title: "Very large cookie" },
  "sensitive-jwt": { severity: "medium", title: "JWT stored in cookie value" },
  "jwt-alg-none": { severity: "critical", title: "Unsigned JWT (alg: none) in cookie" },
  "sensitive-email": { severity: "medium", title: "Email address in cookie value" },
  "duplicate-cookie": { severity: "low", title: "Duplicate cookie" },
  "partitioned-insecure": { severity: "high", title: "Partitioned without Secure (rejected by browsers)" },
  "partitioned-misuse": { severity: "low", title: "Partitioned attribute misuse" }
};
function compilePatterns(list) {
  return (list || []).map((p) => p instanceof RegExp ? p : new RegExp(p, "i"));
}
function isSessionLike(name, opts) {
  const not = opts.notSessionRe.some((r) => r.test(name));
  return !not && opts.sessionRe.some((r) => r.test(name));
}
function safeDecode(v) {
  try {
    return decodeURIComponent(v);
  } catch {
    return v;
  }
}
function b64urlJson(s) {
  try {
    return JSON.parse(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return null;
  }
}
var JWT_RE = /(eyJ[A-Za-z0-9_-]{4,})\.(eyJ[A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]*)/;
var EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;
var days = (s) => Math.round(s / 86400);
function runRules(observations, opts) {
  const findings = [];
  const now = opts.now ?? Date.now();
  for (const obs of observations) {
    const { cookie: c, url } = obs;
    const a = c.attrs;
    let u;
    try {
      u = new URL(url);
    } catch {
      u = null;
    }
    const https2 = u ? u.protocol === "https:" : true;
    const host = u ? u.hostname.toLowerCase() : "";
    const session = isSessionLike(c.name, opts);
    const add = (rule, message, fix, extra = {}) => findings.push({ rule, severity: extra.severity || RULES[rule].severity, cookie: c.name, url, message, fix, sessionLike: session, setCookie: c.raw, ...obs.hop !== void 0 ? { hop: obs.hop } : {} });
    if (isDeletion(c, now)) continue;
    const ss = a.sameSite === void 0 ? void 0 : a.sameSite.toLowerCase();
    if (u && u.protocol === "http:") {
      add(
        "cookie-over-http",
        `"${c.name}" is set by an http:// response, so it travels in cleartext and can be read or injected by a network attacker`,
        "Serve the site only over HTTPS (redirect http\u2192https before setting cookies, enable HSTS) and add Secure.",
        { severity: session ? "high" : void 0 }
      );
    }
    if (https2 && !a.secure) {
      add(
        "missing-secure",
        `"${c.name}" has no Secure attribute; it will be sent over plain HTTP if the user ever hits an http:// URL`,
        `Add Secure: \`Set-Cookie: ${c.name}=\u2026; Secure\`.`,
        { severity: session ? "high" : "medium" }
      );
    }
    if (session && !a.httpOnly) {
      add(
        "missing-httponly",
        `"${c.name}" looks like a session/auth cookie but lacks HttpOnly, so any XSS can steal it via document.cookie`,
        'Add HttpOnly. If front-end code genuinely needs this value, allowlist it in the config (allow: [{ rule: "missing-httponly", cookie: "' + c.name + '" }]).'
      );
    }
    if (ss === void 0) {
      add(
        "samesite-missing",
        `"${c.name}" has no SameSite attribute; behaviour depends on the browser default (Lax in Chromium, None in some others)`,
        `Set it explicitly: \`SameSite=Lax\` (or \`Strict\` for ${session ? "this session cookie" : "cookies never needed cross-site"}).`,
        { severity: session ? "medium" : void 0 }
      );
    } else if (!["strict", "lax", "none"].includes(ss)) {
      add("samesite-invalid", `"${c.name}" has SameSite=${a.sameSite}, which browsers ignore`, "Use SameSite=Strict, Lax or None.");
    } else if (ss === "none") {
      if (!a.secure) add("samesite-none-insecure", `"${c.name}" uses SameSite=None without Secure; modern browsers reject the cookie outright`, "Add Secure (SameSite=None requires it), or use SameSite=Lax.");
      else add(
        "samesite-none",
        `"${c.name}" is SameSite=None, so it is sent on cross-site requests (CSRF exposure${session ? " for a session cookie" : ""})`,
        "Use SameSite=Lax unless the cookie is genuinely needed in third-party/iframe contexts; if so, consider Partitioned (CHIPS).",
        { severity: session ? "medium" : void 0 }
      );
    }
    if (c.name.startsWith("__Host-")) {
      const why = [];
      if (!a.secure) why.push("missing Secure");
      if (a.domain !== void 0) why.push(`has Domain=${a.domain}`);
      if (a.path !== "/") why.push(a.path === void 0 ? "missing Path=/" : `Path=${a.path} (must be /)`);
      if (!https2) why.push("set from a non-HTTPS origin");
      if (why.length) add("host-prefix", `"${c.name}" violates the __Host- prefix rules (${why.join(", ")}); browsers will reject it`, "A __Host- cookie must have Secure, Path=/, no Domain and be set over HTTPS.");
    } else if (c.name.startsWith("__Secure-")) {
      const why = [];
      if (!a.secure) why.push("missing Secure");
      if (!https2) why.push("set from a non-HTTPS origin");
      if (why.length) add("secure-prefix", `"${c.name}" violates the __Secure- prefix rules (${why.join(", ")}); browsers will reject it`, "A __Secure- cookie must have Secure and be set over HTTPS.");
    } else if (/^__(host|secure)-/i.test(c.name)) {
      add("host-prefix", `"${c.name}" uses a mis-cased cookie prefix; browsers treat prefixes case-insensitively and will enforce (and likely reject) it`, "Use the exact prefix `__Host-` or `__Secure-` and follow its rules.", { severity: "medium" });
    }
    if (a.domain !== void 0 && a.domain !== "") {
      const d = a.domain.replace(/^\./, "").toLowerCase();
      if (host && !(host === d || host.endsWith("." + d))) {
        add("domain-mismatch", `"${c.name}" has Domain=${a.domain}, which does not domain-match ${host}; browsers reject it`, `Remove Domain or set it to ${host}.`);
      } else if (!d.includes(".")) {
        add("broad-domain", `"${c.name}" has Domain=${a.domain} (a top-level domain); browsers reject it, and if accepted it would be sent to every site`, "Remove the Domain attribute.", { severity: "high" });
      } else if (host && host !== d) {
        add(
          "broad-domain",
          `"${c.name}" has Domain=${a.domain}, a parent of ${host}, so every subdomain of ${d} receives${session ? " (and can overwrite)" : ""} it`,
          `Remove Domain to make it host-only${session ? " (ideally rename to __Host-" + c.name + ")" : ""}, or scope it to the narrowest host that needs it.`,
          { severity: session ? "medium" : "low" }
        );
      } else if (session) {
        add(
          "broad-domain",
          `"${c.name}" sets Domain=${a.domain}; unlike a host-only cookie it is also sent to all subdomains of ${d}`,
          `Omit the Domain attribute so the cookie stays host-only (consider __Host-${c.name}).`,
          { severity: "low" }
        );
      }
    }
    if (session && (a.path === "/" || a.path === void 0) && opts.flagBroadPath !== false) {
      if (a.path === "/") add(
        "broad-path",
        `"${c.name}" is a sensitive cookie sent to every path on ${host || "the site"} (Path=/)`,
        "If only part of the site needs it (e.g. /api or /admin), set a narrower Path. Note Path is not a security boundary against same-origin scripts."
      );
    }
    const life = lifetimeSeconds(c, now);
    if (life !== null) {
      const limit = (session ? opts.sessionMaxAgeDays : opts.maxAgeDays) * 86400;
      if (life > limit) {
        add(
          "long-expiry",
          `"${c.name}" lives for ${days(life)} days (limit ${session ? opts.sessionMaxAgeDays : opts.maxAgeDays} for ${session ? "session-like" : "other"} cookies)`,
          session ? "Shorten the lifetime (hours to days for sessions) and rotate on use; prefer short-lived sessions with server-side refresh." : "Lower Max-Age; browsers cap cookie lifetimes at 400 days anyway.",
          { severity: session ? "medium" : "low" }
        );
      }
    }
    const size = Buffer.byteLength(c.name + c.value);
    if (size > opts.largeBytes) {
      add(
        "large-cookie",
        `"${c.name}" is ${size} bytes (limit ${opts.largeBytes}); browsers drop cookies over 4096 bytes and big cookies bloat every request`,
        "Store the data server-side and keep only an opaque identifier in the cookie.",
        { severity: size > 4096 ? "medium" : void 0 }
      );
    }
    const decoded = safeDecode(c.value);
    const jwt = decoded.match(JWT_RE);
    if (jwt) {
      const header = b64urlJson(jwt[1]);
      const payload = b64urlJson(jwt[2]);
      if (header && String(header.alg).toLowerCase() === "none") {
        add("jwt-alg-none", `"${c.name}" holds an unsigned JWT (alg: none); anyone can forge it`, 'Never accept alg "none": sign tokens (RS256/ES256/HS256) and verify the algorithm server-side.');
      }
      const claims = payload ? Object.keys(payload).slice(0, 8).join(", ") : "unreadable";
      add(
        "sensitive-jwt",
        `"${c.name}" contains a JWT whose payload is readable by anyone holding the cookie (claims: ${claims})`,
        `JWT payloads are only base64-encoded, not encrypted. Keep PII out of the claims or use an opaque session id${a.httpOnly ? "" : ", and add HttpOnly"}.`,
        { severity: !a.httpOnly ? "high" : void 0 }
      );
      if (payload && EMAIL_RE.test(JSON.stringify(payload))) {
        add("sensitive-email", `"${c.name}" JWT payload contains an email address`, "Remove personal data from token claims; use an opaque user id.");
      }
    } else if (EMAIL_RE.test(decoded) || EMAIL_RE.test(tryBase64(decoded))) {
      add("sensitive-email", `"${c.name}" value contains an email address`, "Do not store personal data in cookies; keep it server-side and reference it with an opaque id.");
    }
    if (a.partitioned) {
      if (!a.secure) add("partitioned-insecure", `"${c.name}" is Partitioned without Secure; browsers reject it`, "Add Secure (CHIPS requires it).");
      if (ss !== "none") add(
        "partitioned-misuse",
        `"${c.name}" is Partitioned but SameSite=${a.sameSite ?? "(unset)"}; partitioning only matters for cookies sent in cross-site contexts`,
        "Use Partitioned together with SameSite=None; Secure for embedded/third-party cookies, or drop Partitioned for first-party cookies."
      );
      if (session && ss === "none" && !opts.thirdParty) add(
        "partitioned-misuse",
        `"${c.name}" is a session-like cookie marked Partitioned; it will not be shared between top-level sites, which can silently break SSO`,
        "Confirm the cookie is only needed inside a single embedding site; otherwise remove Partitioned.",
        { severity: "info" }
      );
    }
  }
  findings.push(...duplicates(observations, now));
  return findings;
}
function tryBase64(v) {
  if (!/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(v)) return "";
  try {
    return Buffer.from(v.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  } catch {
    return "";
  }
}
function duplicates(observations, now) {
  const out = [];
  const byResp = /* @__PURE__ */ new Map();
  const byName = /* @__PURE__ */ new Map();
  for (const o of observations) {
    if (isDeletion(o.cookie, now)) continue;
    let host = "";
    try {
      host = new URL(o.url).hostname;
    } catch {
    }
    const scope = `${(o.cookie.attrs.domain || host).replace(/^\./, "").toLowerCase()}|${o.cookie.attrs.path || "/"}`;
    const rk = `${o.url}#${o.hop ?? 0}#${o.response ?? ""}|${o.cookie.name}|${scope}`;
    byResp.set(rk, (byResp.get(rk) || []).concat(o));
    const nk = o.cookie.name;
    if (!byName.has(nk)) byName.set(nk, /* @__PURE__ */ new Map());
    const m = byName.get(nk);
    m.set(scope, (m.get(scope) || []).concat(o));
  }
  for (const [, list] of byResp) {
    if (list.length > 1) {
      const o = list[0];
      out.push({ rule: "duplicate-cookie", severity: "low", cookie: o.cookie.name, url: o.url, message: `"${o.cookie.name}" is set ${list.length} times in the same response; only the last one wins`, fix: "Emit each cookie once per response (check middleware/framework layers that both set it).", setCookie: list.map((x) => x.cookie.raw).join("\n") });
    }
  }
  for (const [name, scopes] of byName) {
    if (scopes.size > 1) {
      const all = [...scopes.values()].map((l) => l[0]);
      out.push({ rule: "duplicate-cookie", severity: "medium", cookie: name, url: all[0].url, message: `"${name}" is set with ${scopes.size} different Domain/Path scopes (${[...scopes.keys()].map((k) => k.replace("|", " path ")).join("; ")}); the browser keeps both and sends both, enabling cookie-tossing/shadowing`, fix: "Use one consistent Domain and Path for each cookie name (prefer host-only, Path=/, and a __Host- prefix).", setCookie: all.map((x) => x.cookie.raw).join("\n") });
    }
  }
  return out;
}

// src/fetch.js
var import_node_http = __toESM(require("node:http"), 1);
var import_node_https = __toESM(require("node:https"), 1);
var UA = "cookie-sentinel (+https://github.com/MrLouisWright/cookie-sentinel)";
function request(url, { headers = {}, timeout = 15e3, insecure = false, method = "GET", body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === "https:" ? import_node_https.default : u.protocol === "http:" ? import_node_http.default : null;
    if (!mod) return reject(new Error(`Unsupported protocol: ${u.protocol}`));
    const h = { "user-agent": UA, accept: "*/*", ...headers };
    if (body != null && !h["content-length"]) h["content-length"] = Buffer.byteLength(String(body));
    const req = mod.request(u, { method, headers: h, rejectUnauthorized: !insecure }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        res._body = Buffer.concat(chunks);
        resolve(res);
      });
      res.on("error", reject);
    });
    req.setTimeout(timeout, () => req.destroy(new Error(`Timed out after ${timeout} ms: ${url}`)));
    req.on("error", reject);
    if (body != null) req.write(String(body));
    req.end();
  });
}
async function collect(url, { headers = {}, maxRedirects = 10, timeout, insecure, jar = true, method, body, readBody = false } = {}) {
  const hops = [];
  const observations = [];
  const store = /* @__PURE__ */ new Map();
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    const host = new URL(current).host;
    const h = { ...headers };
    if (jar && store.has(host) && store.get(host).size) {
      const ours = [...store.get(host)].map(([k, v]) => `${k}=${v}`).join("; ");
      const userCookie = Object.keys(h).find((k) => k.toLowerCase() === "cookie");
      if (userCookie) h[userCookie] = `${h[userCookie]}; ${ours}`;
      else h.cookie = ours;
    }
    const res = await request(current, { headers: h, timeout, insecure, method: i === 0 ? method : "GET", body: i === 0 ? body : void 0 });
    const setCookie = splitCookiesString(res.headers["set-cookie"] || []);
    const location = res.headers.location ? new URL(res.headers.location, current).href : void 0;
    hops.push({ url: current, status: res.statusCode, location, setCookie, body: readBody ? res._body?.toString("utf8") : void 0 });
    for (const sc of setCookie) {
      const cookie = parseSetCookie(sc);
      if (!cookie) continue;
      observations.push({ cookie, url: current, status: res.statusCode, hop: i, source: url });
      if (!store.has(host)) store.set(host, /* @__PURE__ */ new Map());
      store.get(host).set(cookie.name, cookie.value);
    }
    if (res.statusCode >= 300 && res.statusCode < 400 && location) {
      current = location;
      continue;
    }
    return { url, finalUrl: current, hops, observations, html: readBody ? hops.at(-1)?.body : void 0 };
  }
  throw new Error(`Too many redirects (>${maxRedirects}) starting at ${url}`);
}
function expandTargets(urls, paths = []) {
  const out = [];
  for (const u of urls) {
    const base = new URL(/^https?:\/\//i.test(u) ? u : `https://${u}`);
    out.push(base.href);
    for (const p of paths) out.push(new URL(p, base).href);
  }
  return [...new Set(out)];
}

// src/crawl.js
var HREF_RE = /\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi;
function extractLinks(html, baseUrl, { sameOrigin = true } = {}) {
  const base = new URL(baseUrl);
  const out = /* @__PURE__ */ new Set();
  let m;
  HREF_RE.lastIndex = 0;
  while (m = HREF_RE.exec(html)) {
    const raw = m[2] || m[3] || m[4];
    if (!raw || raw.startsWith("#") || /^javascript:/i.test(raw) || /^mailto:/i.test(raw) || /^tel:/i.test(raw)) continue;
    try {
      const u = new URL(raw, base);
      if (u.protocol !== "http:" && u.protocol !== "https:") continue;
      if (sameOrigin && u.origin !== base.origin) continue;
      u.hash = "";
      out.add(u.href);
    } catch {
    }
  }
  return [...out];
}
async function discoverPages(seeds, {
  maxPages = 25,
  maxDepth = 2,
  sameOrigin = true,
  headers = {},
  timeout,
  insecure,
  maxRedirects,
  jar = true,
  concurrency = 4,
  allowPath,
  denyPath
} = {}) {
  const allowRe = allowPath ? new RegExp(allowPath) : null;
  const denyRe = denyPath ? new RegExp(denyPath) : null;
  const seen = /* @__PURE__ */ new Set();
  const queue = [...new Set(seeds)].map((url) => ({ url, depth: 0 }));
  const pages = [];
  const errors = [];
  const allowed = (url) => {
    try {
      const p = new URL(url).pathname;
      if (denyRe?.test(p)) return false;
      if (allowRe && !allowRe.test(p)) return false;
      return true;
    } catch {
      return false;
    }
  };
  while (queue.length && pages.length < maxPages) {
    const batch = [];
    while (queue.length && batch.length < concurrency && pages.length + batch.length < maxPages) {
      const item = queue.shift();
      if (!item || seen.has(item.url)) continue;
      seen.add(item.url);
      if (!allowed(item.url)) continue;
      batch.push(item);
    }
    if (!batch.length) break;
    await Promise.all(batch.map(async ({ url, depth }) => {
      try {
        const res = await collect(url, { headers, timeout, insecure, maxRedirects, jar, readBody: true });
        const html = res.html || "";
        const links = extractLinks(html, res.finalUrl || url, { sameOrigin });
        pages.push({ url: res.finalUrl || url, links });
        if (depth < maxDepth) {
          for (const link of links) {
            if (!seen.has(link)) queue.push({ url: link, depth: depth + 1 });
          }
        }
      } catch (e) {
        errors.push({ url, error: e.message });
      }
    }));
  }
  return { urls: pages.map((p) => p.url), pages, errors };
}
function mergeCrawlTargets(seeds, discoveredUrls, paths = []) {
  return expandTargets([.../* @__PURE__ */ new Set([...seeds, ...discoveredUrls])], paths);
}

// src/auth.js
var import_node_fs = require("node:fs");
function loadHeadersFile(path) {
  const raw = JSON.parse((0, import_node_fs.readFileSync)(path, "utf8"));
  if (raw && typeof raw === "object" && raw.headers && typeof raw.headers === "object") return { ...raw.headers };
  if (raw && typeof raw === "object" && !Array.isArray(raw)) return { ...raw };
  throw new Error("Headers file must be a JSON object of header names to values");
}
function loadCookiesFile(path) {
  const text = (0, import_node_fs.readFileSync)(path, "utf8").trim();
  if (!text) return "";
  if (text.startsWith("{") || text.startsWith("[")) {
    const parsed = JSON.parse(text);
    const pairs = [];
    if (Array.isArray(parsed)) {
      for (const c of parsed) {
        if (typeof c === "string") pairs.push(c);
        else if (c && c.name) pairs.push(`${c.name}=${c.value ?? ""}`);
      }
    } else if (parsed && typeof parsed === "object") {
      for (const [k, v] of Object.entries(parsed)) pairs.push(`${k}=${v}`);
    }
    return pairs.join("; ");
  }
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  const netscape = lines.some((l) => l.includes("	"));
  if (netscape) {
    const pairs = [];
    for (const line of lines) {
      if (line.startsWith("#")) continue;
      const cols = line.split("	");
      if (cols.length >= 7 && !/^TRUE$/i.test(cols[3])) continue;
      if (cols.length >= 7) pairs.push(`${cols[5]}=${cols[6]}`);
    }
    return pairs.join("; ");
  }
  return lines.map((l) => l.replace(/^cookie:\s*/i, "")).join("; ");
}
function mergeCookieHeader(headers, cookieHeader) {
  if (!cookieHeader) return headers;
  const out = { ...headers };
  const existing = Object.keys(out).find((k) => k.toLowerCase() === "cookie");
  if (existing) out[existing] = `${out[existing]}; ${cookieHeader}`;
  else out.Cookie = cookieHeader;
  return out;
}
async function runLogin(login, fetchOpts = {}) {
  if (!login?.url) throw new Error("login.url is required");
  const headers = { ...login.headers || {} };
  const result = await collect(login.url, {
    ...fetchOpts,
    headers,
    method: login.method || "POST",
    body: login.body
  });
  const expect = login.expectStatus ?? [200, 201, 204, 302, 303, 307, 308];
  const ok = Array.isArray(expect) ? expect.includes(result.hops.at(-1)?.status) : result.hops.at(-1)?.status === expect;
  if (!ok) {
    throw new Error(`Login to ${login.url} returned ${result.hops.at(-1)?.status}, expected ${JSON.stringify(expect)}`);
  }
  const jar = /* @__PURE__ */ new Map();
  for (const hop of result.hops) {
    for (const sc of hop.setCookie || []) {
      const m = sc.match(/^([^=]+)=([^;]*)/);
      if (m) jar.set(m[1].trim(), m[2]);
    }
  }
  const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  return { headers: mergeCookieHeader(fetchOpts.headers || {}, cookie), result };
}

// src/classify.js
var import_node_fs2 = require("node:fs");
var import_node_url = require("node:url");
var import_node_path = require("node:path");
var TRACKING = /* @__PURE__ */ new Set(["Analytics", "Marketing", "Targeting", "Advertising", "Social Media", "Personalization"]);
var ESSENTIAL = /* @__PURE__ */ new Set(["Functional", "Necessary", "Strictly Necessary", "Security", "Preferences", "Unknown"]);
var _index;
function loadIndex() {
  if (_index) return _index;
  const baseDir = typeof __dirname !== "undefined" ? __dirname : (0, import_node_path.dirname)((0, import_node_url.fileURLToPath)(import_meta_url));
  const path = (0, import_node_path.join)(baseDir, "../data/ocdb.json");
  const snapshot = JSON.parse((0, import_node_fs2.readFileSync)(path, "utf8"));
  const exact = /* @__PURE__ */ new Map();
  const wildcards = [];
  for (const e of snapshot.entries) {
    const row = { ...e };
    if (e.wildcard) wildcards.push(row);
    else {
      const key = e.name.toLowerCase();
      if (!exact.has(key)) exact.set(key, []);
      exact.get(key).push(row);
    }
  }
  _index = { exact, wildcards, meta: { fetchedAt: snapshot.fetchedAt, entryCount: snapshot.entryCount } };
  return _index;
}
function matchWildcard(pattern, name) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(name);
}
function lookupOpenCookieDatabase(name) {
  const { exact, wildcards } = loadIndex();
  const hit = exact.get(String(name).toLowerCase());
  if (hit?.length) return hit[0];
  for (const row of wildcards) {
    if (matchWildcard(row.name, name)) return row;
  }
  return null;
}
function registrableDomain(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (!h || h === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  const multi = /* @__PURE__ */ new Set(["co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br"]);
  const tail2 = parts.slice(-2).join(".");
  if (multi.has(tail2) && parts.length >= 3) return parts.slice(-3).join(".");
  return tail2;
}
function cookieParty(pageUrl, cookieDomainAttr, ocdb) {
  if (ocdb?.domain?.includes("3rd party")) return "third-party";
  let pageHost;
  try {
    pageHost = new URL(pageUrl).hostname;
  } catch {
    return "unknown";
  }
  const pageReg = registrableDomain(pageHost);
  const cookieHost = (cookieDomainAttr || pageHost).toLowerCase().replace(/^\./, "");
  const cookieReg = registrableDomain(cookieHost);
  if (!cookieReg || !pageReg) return "unknown";
  if (cookieReg === pageReg) return "first-party";
  if (pageHost.endsWith(cookieHost) || cookieHost.endsWith(pageReg)) return "first-party";
  return "third-party";
}
function purposeFromCategory(category) {
  if (!category) return "unknown";
  if (TRACKING.has(category)) return "tracking";
  if (ESSENTIAL.has(category)) return "essential";
  if (/analytic/i.test(category) || /market/i.test(category)) return "tracking";
  if (/function/i.test(category) || /necess/i.test(category)) return "essential";
  return "unknown";
}
function classifyCookie(cookie, pageUrl) {
  const ocdb = lookupOpenCookieDatabase(cookie.name);
  const party = cookieParty(pageUrl, cookie.attrs?.domain, ocdb);
  const purpose = purposeFromCategory(ocdb?.category);
  return {
    party,
    purpose,
    category: ocdb?.category || null,
    vendor: ocdb?.vendor || null,
    retentionPeriod: ocdb?.retentionPeriod || null,
    openCookieDatabase: ocdb ? { name: ocdb.name, vendor: ocdb.vendor, category: ocdb.category } : null
  };
}
function databaseMeta() {
  return loadIndex().meta;
}

// src/browser.js
async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch (e) {
    throw new Error("Playwright is not installed. Add it as a dev/peer dependency: npm i -D playwright");
  }
}
async function loadPuppeteer() {
  try {
    return await import("puppeteer");
  } catch (e) {
    throw new Error("Puppeteer is not installed. Add it as a dev/peer dependency: npm i -D puppeteer");
  }
}
function playwrightToObservation(c, pageUrl) {
  const parts = [`${c.name}=${c.value}`];
  if (c.domain) parts.push(`Domain=${c.domain}`);
  if (c.path) parts.push(`Path=${c.path}`);
  if (c.expires && c.expires > 0) parts.push(`Expires=${new Date(c.expires * 1e3).toUTCString()}`);
  if (c.httpOnly) parts.push("HttpOnly");
  if (c.secure) parts.push("Secure");
  if (c.sameSite) parts.push(`SameSite=${c.sameSite}`);
  const raw = parts.join("; ");
  const cookie = parseSetCookie(raw);
  if (!cookie) return null;
  return { cookie, url: pageUrl, source: "browser", via: "playwright" };
}
function puppeteerToObservation(c, pageUrl) {
  const parts = [`${c.name}=${c.value}`];
  if (c.domain) parts.push(`Domain=${c.domain}`);
  if (c.path) parts.push(`Path=${c.path}`);
  if (c.expires && c.expires > 0) parts.push(`Expires=${new Date(c.expires * 1e3).toUTCString()}`);
  if (c.httpOnly) parts.push("HttpOnly");
  if (c.secure) parts.push("Secure");
  if (c.sameSite && c.sameSite !== "None") parts.push(`SameSite=${c.sameSite}`);
  else if (c.sameSite === "None") parts.push("SameSite=None");
  const raw = parts.join("; ");
  const cookie = parseSetCookie(raw);
  if (!cookie) return null;
  return { cookie, url: pageUrl, source: "browser", via: "puppeteer" };
}
async function collectBrowser(urls, { engine = "playwright", headers = {}, timeout = 3e4, waitUntil } = {}) {
  const observations = [];
  const targets = [];
  if (engine === "puppeteer") {
    const puppeteer = await loadPuppeteer();
    const browser2 = await puppeteer.default.launch({ headless: true });
    try {
      const page = await browser2.newPage();
      if (Object.keys(headers).length) await page.setExtraHTTPHeaders(headers);
      page.setDefaultNavigationTimeout(timeout);
      for (const url of urls) {
        const nav = await page.goto(url, { waitUntil: waitUntil || "networkidle2" });
        const finalUrl = nav?.url() || url;
        const js = await page.evaluate(() => document.cookie).catch(() => "");
        for (const part of js.split(";").map((s) => s.trim()).filter(Boolean)) {
          const obs = parseSetCookie(part);
          if (obs) observations.push({ cookie: obs, url: finalUrl, source: "browser-js", via: "puppeteer" });
        }
        const cookies = await page.cookies(finalUrl);
        for (const c of cookies) {
          const o = puppeteerToObservation(c, finalUrl);
          if (o) observations.push(o);
        }
        targets.push({ url, finalUrl, engine: "puppeteer" });
      }
    } finally {
      await browser2.close();
    }
    return { observations: dedupeObservations(observations), targets };
  }
  const { chromium } = await loadPlaywright();
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ extraHTTPHeaders: headers });
    context.setDefaultNavigationTimeout(timeout);
    const page = await context.newPage();
    for (const url of urls) {
      await page.goto(url, { waitUntil: waitUntil || "networkidle" });
      const finalUrl = page.url();
      const js = await page.evaluate(() => document.cookie).catch(() => "");
      for (const part of js.split(";").map((s) => s.trim()).filter(Boolean)) {
        const obs = parseSetCookie(part);
        if (obs) observations.push({ cookie: obs, url: finalUrl, source: "browser-js", via: "playwright" });
      }
      const cookies = await context.cookies(finalUrl);
      for (const c of cookies) {
        const o = playwrightToObservation(c, finalUrl);
        if (o) observations.push(o);
      }
      targets.push({ url, finalUrl, engine: "playwright" });
    }
  } finally {
    await browser.close();
  }
  return { observations: dedupeObservations(observations), targets };
}
function dedupeObservations(list) {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const o of list) {
    const k = `${o.url}\0${o.cookie.name}\0${o.cookie.raw}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(o);
  }
  return out;
}

// src/report.js
var C = { critical: "\x1B[35;1m", high: "\x1B[31;1m", medium: "\x1B[33m", low: "\x1B[36m", info: "\x1B[2m", dim: "\x1B[2m", bold: "\x1B[1m", reset: "\x1B[0m", red: "\x1B[31m", green: "\x1B[32m" };
function summary(counts) {
  const s = SEVERITIES.filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`).join(", ");
  return s || "no findings";
}
function formatText(report, { color = false, failOn } = {}) {
  const c = (k, s) => color ? `${C[k]}${s}${C.reset}` : s;
  const lines = [];
  lines.push(c("bold", `cookie-sentinel \u2014 ${report.cookies.length} cookie(s) from ${report.targets.length} target(s)`));
  if (report.classificationSummary) {
    const s = report.classificationSummary;
    lines.push(c("dim", `  classification: ${s.firstParty} first-party, ${s.thirdParty} third-party, ${s.tracking} tracking, ${s.essential} essential (${s.catalogued} in Open Cookie Database)`));
  }
  if (report.crawl) lines.push(c("dim", `  crawl: ${report.crawl.discovered} page(s) discovered (max ${report.crawl.maxPages})`));
  if (report.browser) lines.push(c("dim", `  browser: ${report.browser.engine} captured ${report.browser.cookies} cookie observation(s)`));
  for (const t of report.targets) {
    if (t.error) {
      lines.push(c("red", `  \u2716 ${t.url}: ${t.error}`));
      continue;
    }
    if (t.hops) lines.push(c("dim", `  ${t.hops.map((h) => `${h.status} ${h.url} (${h.cookies} cookie${h.cookies === 1 ? "" : "s"})`).join(" \u2192 ")}`));
  }
  lines.push("");
  const groups = /* @__PURE__ */ new Map();
  for (const f of report.findings) {
    const k = `${f.cookie}  ${c("dim", f.url)}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  for (const [k, list] of groups) {
    lines.push(c("bold", k));
    const f0 = list[0];
    const sample = report.cookies.find((co) => co.name === f0.cookie && co.url === f0.url);
    if (sample?.classification) {
      const cl = sample.classification;
      const bits = [cl.party, cl.purpose !== "unknown" ? cl.purpose : null, cl.category].filter(Boolean);
      if (bits.length) lines.push(c("dim", `           classification: ${bits.join(" \xB7 ")}${cl.vendor ? ` (${cl.vendor})` : ""}`));
    }
    for (const f of list) {
      lines.push(`  ${c(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.message} [${f.rule}]`);
      lines.push(c("dim", `           \u21B3 fix: ${f.fix}`));
    }
    lines.push("");
  }
  if (report.suppressed.length) lines.push(c("dim", `${report.suppressed.length} finding(s) suppressed by allowlist`));
  lines.push(summary(report.counts));
  if (failOn) {
    const failing = failOn !== "none" && report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(failOn));
    lines.push(failing ? c("red", `\u2716 Failing (fail-on: ${failOn}).`) : c("green", `\u2714 Passing (fail-on: ${failOn}).`));
  }
  return lines.join("\n") + "\n";
}
function formatJson(report) {
  return JSON.stringify(report, null, 2) + "\n";
}
var SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
var SCORE = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
function formatSarif(report, { version = "0.0.0" } = {}) {
  const ids = Object.keys(RULES);
  const rules = ids.map((id) => ({
    id,
    name: id.replace(/(^|-)(\w)/g, (_, __, ch) => ch.toUpperCase()),
    shortDescription: { text: RULES[id].title },
    helpUri: `https://github.com/MrLouisWright/cookie-sentinel#${id}`,
    defaultConfiguration: { level: SARIF_LEVEL[RULES[id].severity] },
    properties: { tags: ["security", "cookies"], "security-severity": SCORE[RULES[id].severity] }
  }));
  const results = report.findings.map((f) => ({
    ruleId: f.rule,
    ruleIndex: ids.indexOf(f.rule),
    level: SARIF_LEVEL[f.severity],
    message: { text: `${f.message}. Fix: ${f.fix}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: f.url } } }],
    partialFingerprints: { cookieRule: `${f.rule}:${f.cookie}:${f.url}` },
    properties: { cookie: f.cookie, severity: f.severity, "security-severity": SCORE[f.severity] }
  }));
  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "cookie-sentinel", version, informationUri: "https://github.com/MrLouisWright/cookie-sentinel", rules } }, results }]
  }, null, 2) + "\n";
}
var esc = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
function formatMarkdown(report, { failOn } = {}) {
  const l = ["## \u{1F36A} cookie-sentinel", ""];
  l.push(`Audited **${report.cookies.length}** cookie(s) across **${report.targets.length}** target(s): ${summary(report.counts)}.`);
  if (failOn) {
    const failing = failOn !== "none" && report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(failOn));
    l.push("", failing ? `\u274C Failing at \`--fail-on ${failOn}\`.` : `\u2705 Passing at \`--fail-on ${failOn}\`.`);
  }
  for (const e of report.errors) l.push("", `> \u26A0\uFE0F ${esc(e.url)}: ${esc(e.error)}`);
  if (report.findings.length) {
    l.push("", "| Severity | Cookie | Rule | Finding | Fix |", "|---|---|---|---|---|");
    for (const f of report.findings) l.push(`| ${f.severity} | \`${esc(f.cookie)}\` | \`${f.rule}\` | ${esc(f.message)} (${esc(f.url)}) | ${esc(f.fix)} |`);
  }
  if (report.suppressed.length) l.push("", `_${report.suppressed.length} finding(s) suppressed by allowlist._`);
  return l.join("\n") + "\n";
}

// src/index.js
var DEFAULTS = { maxAgeDays: 400, sessionMaxAgeDays: 30, largeBytes: 3072, flagBroadPath: true, thirdParty: false };
function resolveOptions(config = {}) {
  const sessionPatterns = [...config.replaceSessionPatterns ? [] : DEFAULT_SESSION_PATTERNS, ...config.sessionPatterns || []];
  return {
    ...DEFAULTS,
    ...config,
    sessionRe: compilePatterns(sessionPatterns),
    notSessionRe: compilePatterns([...DEFAULT_NOT_SESSION_PATTERNS, ...config.notSessionPatterns || []])
  };
}
function glob(pattern, value) {
  if (pattern === void 0) return true;
  const re = new RegExp("^" + String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");
  return re.test(value ?? "");
}
function applyConfig(findings, config = {}) {
  const sev = config.severity || config.rules || {};
  const allow = config.allow || config.allowlist || [];
  const out = [];
  const suppressed = [];
  for (const f of findings) {
    const o = sev[f.rule];
    if (o === "off" || o === false) continue;
    const g = { ...f, severity: SEVERITIES.includes(o) ? o : f.severity };
    const hit = allow.find((a) => typeof a === "string" ? glob(a, g.cookie) : glob(a.rule, g.rule) && glob(a.cookie, g.cookie) && glob(a.url, g.url));
    if (hit) {
      suppressed.push({ ...g, allowedBy: hit.reason || hit });
      continue;
    }
    out.push(g);
  }
  out.sort((a, b) => rank(a.severity) - rank(b.severity) || a.url.localeCompare(b.url) || a.cookie.localeCompare(b.cookie));
  return { findings: out, suppressed };
}
function enrichObservations(observations, config) {
  if (config.classify === false) return observations;
  return observations.map((o) => ({
    ...o,
    classification: classifyCookie(o.cookie, o.url)
  }));
}
function auditObservations(observations, config = {}, meta = {}) {
  const opts = resolveOptions(config);
  const enriched = enrichObservations(observations, config);
  const raw = runRules(enriched, opts);
  const { findings, suppressed } = applyConfig(raw, config);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  const cookies = enriched.map((o) => ({
    name: o.cookie.name,
    url: o.url,
    hop: o.hop,
    sessionLike: isSessionLike(o.cookie.name, opts),
    setCookie: o.cookie.raw,
    source: o.source,
    classification: o.classification
  }));
  const classificationSummary = summarizeClassification(cookies);
  return {
    tool: "cookie-sentinel",
    generatedAt: new Date(config.now ?? Date.now()).toISOString(),
    targets: meta.targets || [],
    crawl: meta.crawl,
    browser: meta.browser,
    openCookieDatabase: databaseMeta(),
    cookies,
    classificationSummary,
    findings,
    suppressed,
    counts,
    errors: meta.errors || []
  };
}
function summarizeClassification(cookies) {
  const summary2 = { firstParty: 0, thirdParty: 0, unknownParty: 0, essential: 0, tracking: 0, unknownPurpose: 0, catalogued: 0 };
  for (const c of cookies) {
    const cl = c.classification;
    if (!cl) continue;
    if (cl.party === "first-party") summary2.firstParty++;
    else if (cl.party === "third-party") summary2.thirdParty++;
    else summary2.unknownParty++;
    if (cl.purpose === "essential") summary2.essential++;
    else if (cl.purpose === "tracking") summary2.tracking++;
    else summary2.unknownPurpose++;
    if (cl.openCookieDatabase) summary2.catalogued++;
  }
  return summary2;
}
function auditSetCookies(input, { origin = "https://example.com/", config = {} } = {}) {
  const lines = Array.isArray(input) ? input : String(input).split(/\r?\n/);
  const observations = [];
  let url = origin;
  let response = 0;
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = t.match(/^@\s*(\S+)/);
    if (m) {
      url = new URL(m[1], url).href;
      response++;
      continue;
    }
    if (/^---+$/.test(t)) {
      response++;
      continue;
    }
    for (const sc of splitCookiesString(t.replace(/^set-cookie\s*:\s*/i, ""))) {
      const cookie = parseSetCookie(sc);
      if (cookie) observations.push({ cookie, url, response });
    }
  }
  return auditObservations(observations, config, { targets: [{ url: origin, offline: true }] });
}
async function resolveRequestHeaders(config = {}, cliHeaders = {}) {
  let headers = { ...config.headers || {}, ...cliHeaders };
  if (config.headersFile) headers = { ...loadHeadersFile(config.headersFile), ...headers };
  if (config.cookiesFile) headers = mergeCookieHeader(headers, loadCookiesFile(config.cookiesFile));
  if (config.login) {
    const { headers: afterLogin } = await runLogin(config.login, { headers, ...config.loginFetch });
    headers = afterLogin;
  }
  return headers;
}
async function auditUrls(urls, {
  paths = [],
  headers: headerOverrides = {},
  config = {},
  maxRedirects,
  timeout,
  insecure,
  jar,
  concurrency = 4,
  crawl,
  browser
} = {}) {
  const headers = await resolveRequestHeaders(config, headerOverrides);
  let seeds = expandTargets(urls, paths);
  let crawlMeta;
  const crawlOpts = crawl ?? config.crawl;
  if (crawlOpts && crawlOpts.enabled !== false) {
    const discovered = await discoverPages(seeds, {
      maxPages: crawlOpts.maxPages ?? 25,
      maxDepth: crawlOpts.maxDepth ?? 2,
      sameOrigin: crawlOpts.sameOrigin !== false,
      headers,
      timeout: crawlOpts.timeout ?? timeout,
      insecure: crawlOpts.insecure ?? insecure,
      maxRedirects: crawlOpts.maxRedirects ?? maxRedirects,
      jar: crawlOpts.jar ?? jar,
      concurrency: crawlOpts.concurrency ?? concurrency,
      allowPath: crawlOpts.allowPath,
      denyPath: crawlOpts.denyPath
    });
    seeds = mergeCrawlTargets(urls, discovered.urls, paths);
    crawlMeta = { seeds: urls.length, discovered: discovered.urls.length, maxPages: crawlOpts.maxPages ?? 25, errors: discovered.errors };
  }
  const browserOpts = browser ?? config.browser;
  let browserMeta;
  let browserObservations = [];
  if (browserOpts && browserOpts.engine) {
    const { observations: observations2, targets: targets2 } = await collectBrowser(seeds, {
      engine: browserOpts.engine,
      headers,
      timeout: browserOpts.timeout ?? timeout,
      waitUntil: browserOpts.waitUntil
    });
    browserObservations = observations2;
    browserMeta = { engine: browserOpts.engine, pages: targets2.length, cookies: observations2.length };
  }
  const targets = seeds;
  const results = new Array(targets.length);
  let next = 0;
  const worker = async () => {
    while (next < targets.length) {
      const i = next++;
      try {
        results[i] = await collect(targets[i], { headers, maxRedirects, timeout, insecure, jar });
      } catch (e) {
        results[i] = { url: targets[i], error: e.message };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));
  const observations = [...results.flatMap((r) => r.observations || []), ...browserObservations];
  const errors = [
    ...crawlMeta?.errors || [],
    ...results.filter((r) => r.error).map((r) => ({ url: r.url, error: r.error }))
  ];
  const tmeta = results.map((r) => r.error ? { url: r.url, error: r.error } : { url: r.url, finalUrl: r.finalUrl, hops: r.hops.map((h) => ({ url: h.url, status: h.status, location: h.location, cookies: h.setCookie.length })) });
  return auditObservations(observations, config, { targets: tmeta, errors, crawl: crawlMeta, browser: browserMeta });
}
function exceeds(report, failOn = "high") {
  if (failOn === "none") return false;
  return report.findings.some((f) => rank(f.severity) <= rank(failOn));
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  DEFAULTS,
  RULES,
  SEVERITIES,
  applyConfig,
  auditObservations,
  auditSetCookies,
  auditUrls,
  classifyCookie,
  collect,
  collectBrowser,
  databaseMeta,
  discoverPages,
  exceeds,
  expandTargets,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  isSessionLike,
  lifetimeSeconds,
  loadCookiesFile,
  loadHeadersFile,
  lookupOpenCookieDatabase,
  mergeCookieHeader,
  mergeCrawlTargets,
  parseSetCookie,
  resolveOptions,
  runLogin,
  splitCookiesString
});
//# sourceMappingURL=index.cjs.map
