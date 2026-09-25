// ClashDashboard gateway - serve zashboard behind TOTP, and reverse-proxy the Clash controller.
//
// Why a gateway instead of pointing the browser straight at the controller:
//   1. the controller secret must not reach the browser;
//   2. Clash Verge's controller CORS only allows its own origins (tauri://localhost), so a page on
//      http://<lan-ip>:3000 calling http://<ip>:15120 directly is blocked -> proxy it same-origin;
//   3. both traps we hit on the VPS are handled here: the SPA needs ?protocol=&hostname=&port= or it
//      silently talks to http://<host>:9090 and issues zero API calls, and the API probes trigger an
//      OPTIONS preflight that must be answered 204 + ACAO or the browser reports a bogus CORS error.
//
// Auth: RFC 6238 TOTP (6 digits / 30 s / +/-1 window), replay-guarded, per-IP lockout after N wrong
// codes, 30-day SameSite=Lax cookie. Unauthenticated API paths return a bare 404 (no hint that an
// API exists); the UI redirects to /login. /healthz stays public for monitoring.
//
// Zero dependencies.
import http from 'node:http';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, 'public');
const LOGDIR = path.join(ROOT, 'logs');
const STATEDIR = path.join(ROOT, 'state');
const CFG_FILE = path.join(ROOT, 'config.json');

// ------------------------------------------------------------------ config
const DEFAULTS = {
  host: '0.0.0.0',
  port: 3000,
  uiPath: '/panel',
  token: '',                 // optional second factor in front of everything (pre-TOTP gate)
  controller: '',            // empty = discover from the Clash Verge runtime config
  clashConfig: '',           // absolute path of clash-verge.yaml (recorded at install time)
  totpSecret: '',            // base32, RFC 4648; empty = no TOTP gate (wide open)
  sessionDays: 30,
  lockFails: 5,              // wrong codes before the source IP is locked
  lockMinutes: 120,
};
let cfg = { ...DEFAULTS };
const readCfg = () => {
  const text = fs.readFileSync(CFG_FILE, 'utf8').replace(/^\uFEFF/, '');   // PS 5.1 writes a BOM
  return JSON.parse(text);
};
try {
  if (fs.existsSync(CFG_FILE)) cfg = { ...cfg, ...readCfg() };
} catch (e) { console.error('[cfg] config.json unreadable: ' + e.message); }
if (process.env.DASH_PORT) cfg.port = Number(process.env.DASH_PORT);
if (process.env.DASH_HOST) cfg.host = process.env.DASH_HOST;
if (process.env.DASH_TOKEN !== undefined) cfg.token = process.env.DASH_TOKEN;

function log(...a) {
  const line = `[${new Date().toISOString()}] ${a.join(' ')}`;
  console.log(line);
  try {
    fs.mkdirSync(LOGDIR, { recursive: true });
    const f = path.join(LOGDIR, 'server.log');
    if (fs.existsSync(f) && fs.statSync(f).size > 2 * 1024 * 1024) fs.renameSync(f, f + '.1');
    fs.appendFileSync(f, line + '\n');
  } catch { }
}
function saveCfg() {
  try { fs.writeFileSync(CFG_FILE, JSON.stringify(cfg, null, 2), 'utf8'); }
  catch (e) { log('[cfg] cannot persist config.json: ' + e.message); }
}
// one session-signing key per installation
if (!cfg.sessionSecret) {
  cfg.sessionSecret = crypto.randomBytes(32).toString('base64url');
  saveCfg();
  log('[auth] generated a new session secret into config.json');
}
if (!cfg.totpSecret) log('[auth] WARNING: no totpSecret configured - the panel is UNPROTECTED');

// ------------------------------------------------------------------ controller discovery
// Verge regenerates its runtime config on every core start, so the secret can change: re-read with
// an mtime cache instead of caching the value forever.
const candidateConfigs = () => {
  const list = [
    cfg.clashConfig,
    path.join(process.env.APPDATA || '', 'io.github.clash-verge-rev.clash-verge-rev', 'clash-verge.yaml'),
    path.join(process.env.APPDATA || '', 'clash-verge', 'clash-verge.yaml'),
    path.join(ROOT, 'clash-verge.yaml'),
  ];
  // running as SYSTEM, APPDATA is not the user's: scan the profiles so the gateway works even
  // without a recorded clashConfig (defence in depth for the boot-time service account)
  try {
    for (const u of fs.readdirSync('C:\\Users')) {
      list.push(path.join('C:\\Users', u, 'AppData\\Roaming\\io.github.clash-verge-rev.clash-verge-rev\\clash-verge.yaml'));
      list.push(path.join('C:\\Users', u, 'AppData\\Roaming\\clash-verge\\clash-verge.yaml'));
    }
  } catch { }
  return list.filter(Boolean);
};

let cache = { file: '', mtime: 0, controller: '', secret: '' };
function clashRuntime() {
  for (const f of candidateConfigs()) {
    let st;
    try { st = fs.statSync(f); } catch { continue; }
    if (cache.file === f && cache.mtime === st.mtimeMs) return cache;
    let text;
    try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
    const ctl = /^\s*external-controller:\s*['"]?([^\s'"]+)/m.exec(text);
    const sec = /^\s*secret:\s*['"]?([^\s'"]+)/m.exec(text);
    let controller = ctl ? ctl[1] : '';
    // 0.0.0.0:PORT is not dialable; fall back to loopback
    if (/^0\.0\.0\.0:/.test(controller)) controller = controller.replace('0.0.0.0', '127.0.0.1');
    if (!controller) controller = '127.0.0.1:15120';
    cache = { file: f, mtime: st.mtimeMs, controller, secret: sec ? sec[1] : '' };
    return cache;
  }
  return { file: '(not found)', mtime: 0, controller: '127.0.0.1:15120', secret: '' };
}
function target() {
  const rt = clashRuntime();
  const ctl = cfg.controller || rt.controller;
  return { host: ctl.split(':')[0], port: Number(ctl.split(':')[1] || 15120), secret: rt.secret, from: rt.file };
}

// ------------------------------------------------------------------ TOTP (RFC 6238)
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s) {
  const clean = String(s).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totpAt(key, counter) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter % 2 ** 32, 4);
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 0x0f;
  const code = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6;
  return String(code).padStart(6, '0');
}
// state: recent counters (replay guard) + per-IP failures (lockout). Disk-backed, best effort.
const locks = new Map();      // ip -> { fails, until }
const used = new Map();       // counter -> timestamp
function loadState() {
  try {
    const f = path.join(STATEDIR, 'auth.json');
    if (!fs.existsSync(f)) return;
    const s = JSON.parse(fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, ''));
    for (const [ip, v] of Object.entries(s.locks || {})) locks.set(ip, v);
    for (const [c, t] of Object.entries(s.used || {})) used.set(Number(c), t);
    log(`[auth] state loaded: ${locks.size} lock(s), ${used.size} used code(s)`);
  } catch { }
}
function saveState() {
  try {
    fs.mkdirSync(STATEDIR, { recursive: true });
    const now = Date.now();
    const out = { locks: {}, used: {} };
    for (const [ip, v] of locks) if (!v.until || v.until > now) out.locks[ip] = v;
    // keep the replay guard bounded: 30 minutes of counters is plenty for a +/-1 window
    for (const [c, t] of used) if (now - t < 30 * 60 * 1000) out.used[c] = t;
    fs.writeFileSync(path.join(STATEDIR, 'auth.json'), JSON.stringify(out), 'utf8');
  } catch { }
}
loadState();
setInterval(saveState, 60 * 1000).unref?.();

function verifyTotp(code, ip) {
  const now = Date.now();
  const lock = locks.get(ip);
  if (lock && lock.until > now) return { ok: false, locked: true, until: lock.until };
  if (!/^\d{6}$/.test(String(code || ''))) return { ok: false, reason: 'format' };
  const key = b32decode(cfg.totpSecret);
  const step = Math.floor(now / 1000 / 30);
  for (const drift of [0, -1, 1]) {                 // +/-1 window
    const counter = step + drift;
    if (totpAt(key, counter) !== code) continue;
    if (used.has(counter)) return { ok: false, reason: 'replay' };
    used.set(counter, now);
    locks.delete(ip);
    saveState();
    return { ok: true, counter };
  }
  const fails = (lock && lock.fails ? lock.fails : 0) + 1;
  if (fails >= cfg.lockFails) {
    locks.set(ip, { fails, until: now + cfg.lockMinutes * 60 * 1000 });
    log(`[auth] LOCKED ${ip} for ${cfg.lockMinutes} min after ${fails} wrong codes`);
  } else {
    locks.set(ip, { fails, until: 0 });
  }
  saveState();
  return { ok: false, reason: 'wrong', fails };
}

// ------------------------------------------------------------------ session cookie
function sign(v) { return crypto.createHmac('sha256', cfg.sessionSecret).update(v).digest('base64url'); }
function makeCookie() {
  const exp = Date.now() + cfg.sessionDays * 24 * 3600 * 1000;
  const payload = `v1.${exp}`;
  return `dash_session=${payload}.${sign(payload)}; Path=/; Max-Age=${cfg.sessionDays * 24 * 3600}; SameSite=Lax; HttpOnly`;
}
function sessionValid(req) {
  const raw = req.headers.cookie || '';
  const m = /(?:^|;\s*)dash_session=([^;]+)/.exec(raw);
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 3) return false;
  const payload = `${parts[0]}.${parts[1]}`;
  const exp = Number(parts[1]);
  if (!exp || exp < Date.now()) return false;
  const expect = sign(payload);
  return parts[2].length === expect.length &&
    crypto.timingSafeEqual(Buffer.from(parts[2]), Buffer.from(expect));
}
const clientIp = (req) => (req.socket.remoteAddress || '').replace(/^::ffff:/, '');

// ------------------------------------------------------------------ CORS (origin unrestricted)
// Reflect the caller's Origin (instead of a literal "*") so that credentialed cross-origin calls
// ALSO work: "*" is incompatible with Access-Control-Allow-Credentials. SameSite=Lax on the session
// cookie is what stops a random web page from riding an existing session.
function corsHeaders(req, extra = {}) {
  const origin = req.headers.origin;
  const base = {
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || '*',
    'Access-Control-Expose-Headers': '*',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin, Access-Control-Request-Headers',
  };
  if (origin) {
    base['Access-Control-Allow-Origin'] = origin;
    base['Access-Control-Allow-Credentials'] = 'true';
  } else {
    base['Access-Control-Allow-Origin'] = '*';
  }
  return { ...base, ...extra };
}
function tokenOK(req, res) {
  if (!cfg.token) return true;
  const u = new URL(req.url, 'http://x');
  if (u.searchParams.get('token') === cfg.token) {
    res.setHeader('Set-Cookie', `dash_token=${cfg.token}; Path=/; Max-Age=2592000; SameSite=Lax`);
    return true;
  }
  const hdr = req.headers['x-dash-token'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (hdr === cfg.token) return true;
  if ((req.headers.cookie || '').includes(`dash_token=${cfg.token}`)) return true;
  return false;
}

// ------------------------------------------------------------------ login page
const LOGIN_HTML = (msg) => `<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>ClashDashboard</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ctext y='26' font-size='26'%3E%F0%9F%94%90%3C/text%3E%3C/svg%3E">
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100dvh;display:flex;align-items:center;justify-content:center;
     background:#0b0f14;color:#e6edf3;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans SC",sans-serif}
.card{width:100%;max-width:360px;padding:28px 24px;background:#131a22;border:1px solid #223040;border-radius:14px;
      box-shadow:0 12px 40px rgba(0,0,0,.45)}
h1{margin:0 0 4px;font-size:19px;letter-spacing:.2px}
p.sub{margin:0 0 20px;color:#8b98a5;font-size:13px}
input{width:100%;padding:14px 12px;font-size:22px;letter-spacing:7px;text-align:center;font-variant-numeric:tabular-nums;
      background:#0b0f14;color:#e6edf3;border:1px solid #2b3b4d;border-radius:10px;outline:none}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.18)}
button{width:100%;margin-top:14px;padding:12px;font-size:15px;font-weight:600;color:#fff;background:#2563eb;
       border:0;border-radius:10px;cursor:pointer}
button:hover{background:#1d4ed8}
.msg{margin:0 0 14px;padding:10px 12px;border-radius:9px;font-size:13px;background:#3a1d1d;color:#ffb4b4;border:1px solid #5b2b2b}
.hint{margin-top:16px;color:#6e7c8a;font-size:12px;line-height:1.6}
</style></head><body>
<form class="card" method="post" action="/login">
  <h1>ClashDashboard</h1>
  <p class="sub">输入身份验证器中的 6 位动态码</p>
  ${msg ? `<p class="msg">${msg}</p>` : ''}
  <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" maxlength="6" autofocus placeholder="000000">
  <input type="hidden" name="next" value="/panel/">
  <button type="submit">验证并进入</button>
  <p class="hint">动态码 30 秒一轮，用过一次即失效；连续输错会被锁定该来源 IP。</p>
</form></body></html>`;

// ------------------------------------------------------------------ static files
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.ico': 'image/x-icon', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.map': 'application/json',
  '.webmanifest': 'application/manifest+json', '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
};
function serveStatic(req, res, rel) {
  const clean = path.normalize(rel).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(PUBLIC, clean);
  if (!file.startsWith(PUBLIC)) { res.writeHead(403, corsHeaders(req)); res.end('forbidden'); return true; }
  let st;
  try { st = fs.statSync(file); } catch { return false; }
  if (!st.isFile()) return false;
  const ext = path.extname(file).toLowerCase();
  const headers = corsHeaders(req, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': st.size,
    'Cache-Control': /index\.html$/.test(file) ? 'no-store' : 'public, max-age=86400',
  });
  res.writeHead(200, headers);
  fs.createReadStream(file).pipe(res);
  return true;
}

// ------------------------------------------------------------------ SPA shell with backend seed
// zashboard reads ?hostname=&port=&protocol= (and a hash form) to build the API base URL. Without
// protocol it defaults to http on port 9090 and silently issues zero API calls.
function sendIndex(req, res) {
  let html;
  try { html = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8'); }
  catch { res.writeHead(500, corsHeaders(req)); res.end('index.html missing'); return; }
  const proto = (req.headers['x-forwarded-proto'] || 'http').toString().split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || `127.0.0.1:${cfg.port}`).toString();
  const hostname = host.split(':')[0];
  const port = host.includes(':') ? host.split(':')[1] : (proto === 'https' ? '443' : '80');
  const seed = `<script id="dash-backend-seed">
;(function () {
  try {
    var p = new URLSearchParams(location.search);
    var proto = p.get('protocol') || ${JSON.stringify(proto)};
    var hn = p.get('hostname') || ${JSON.stringify(hostname)};
    var pt = p.get('port') || ${JSON.stringify(port)};
    var tid = p.get('token');
    if (!p.get('protocol') || !p.get('hostname') || !p.get('port')) {
      var q = new URLSearchParams(location.search);
      q.set('protocol', proto); q.set('hostname', hn); q.set('port', pt);
      if (tid) q.set('token', tid);
      history.replaceState(null, '', location.pathname + '?' + q.toString() + location.hash);
    }
  } catch (e) {}
})();
</script>`;
  html = html.includes('</head>') ? html.replace('</head>', seed + '</head>') : seed + html;
  const buf = Buffer.from(html, 'utf8');
  res.writeHead(200, corsHeaders(req, { 'Content-Type': MIME['.html'], 'Content-Length': buf.length, 'Cache-Control': 'no-store' }));
  res.end(buf);
}

// ------------------------------------------------------------------ local status (no OS calls)
function localStatus(req, res) {
  const t = target();
  const probe = (p) => new Promise((resolve) => {
    const r = http.request({ host: t.host, port: t.port, path: p, method: 'GET', timeout: 4000, headers: t.secret ? { Authorization: `Bearer ${t.secret}` } : {} }, (rr) => {
      let b = ''; rr.on('data', (d) => (b += d)); rr.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve(null); } });
    });
    r.on('error', () => resolve(null));
    r.on('timeout', () => { r.destroy(); resolve(null); });
    r.end();
  });
  Promise.all([probe('/version'), probe('/configs')]).then(([v, c]) => {
    const body = JSON.stringify({
      gateway: { host: cfg.host, port: cfg.port, token: !!cfg.token, totp: !!cfg.totpSecret },
      controller: { address: `${t.host}:${t.port}`, secretLoaded: !!t.secret, configFile: t.from },
      clash: v ? { version: v.version, meta: !!v.meta } : null,
      config: c ? { mode: c.mode, tunEnable: c.tun && c.tun.enable, tunStack: c.tun && c.tun.stack, mixedPort: c['mixed-port'], logLevel: c['log-level'] } : null,
      ok: !!v,
      time: new Date().toISOString(),
    }, null, 2);
    res.writeHead(200, corsHeaders(req, { 'Content-Type': MIME['.json'] }));
    res.end(body);
  });
}

// ------------------------------------------------------------------ controller proxy
function proxy(req, res) {
  const t = target();
  const headers = { ...req.headers, host: `${t.host}:${t.port}` };
  delete headers.origin;
  delete headers.referer;
  if (t.secret) headers.authorization = `Bearer ${t.secret}`; else delete headers.authorization;
  const pr = http.request({ host: t.host, port: t.port, path: req.url, method: req.method, headers }, (pres) => {
    const out = corsHeaders(req, {});
    for (const [k, v] of Object.entries(pres.headers)) {
      if (['access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers', 'access-control-expose-headers'].includes(k.toLowerCase())) continue;
      out[k] = v;
    }
    res.writeHead(pres.statusCode || 502, out);
    pres.pipe(res);
  });
  pr.on('error', (e) => {
    log('proxy error', e.code || e.message, req.method, req.url);
    res.writeHead(502, corsHeaders(req, { 'Content-Type': MIME['.json'] }));
    res.end(JSON.stringify({ error: 'controller unreachable', detail: e.code || e.message, controller: `${t.host}:${t.port}` }));
  });
  req.pipe(pr);
}

// ------------------------------------------------------------------ request router
const jsonOut = (req, res, status, obj) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, corsHeaders(req, { 'Content-Type': MIME['.json'], 'Content-Length': b.length }));
  res.end(b);
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = decodeURIComponent(u.pathname);

  if (req.method === 'OPTIONS') {           // preflight: 204 + CORS headers, never 404
    res.writeHead(204, corsHeaders(req, { 'Content-Length': '0' }));
    res.end();
    return;
  }
  if (p === '/healthz') return jsonOut(req, res, 200, { ok: true });

  // ---- login / logout (public)
  if (p === '/login' && req.method === 'GET') {
    const msg = u.searchParams.get('e') === '1' ? '动态码不正确或已过期，请重试。'
      : u.searchParams.get('e') === '2' ? '该来源已被锁定，请稍后再试。'
        : '';
    const b = Buffer.from(LOGIN_HTML(msg).replace('value="/panel/"', `value="${(u.searchParams.get('next') || '/panel/').replace(/"/g, '')}"`), 'utf8');
    res.writeHead(200, corsHeaders(req, { 'Content-Type': MIME['.html'], 'Content-Length': b.length, 'Cache-Control': 'no-store' }));
    res.end(b);
    return;
  }
  if (p === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > 4096) req.destroy(); });
    req.on('end', () => {
      const form = new URLSearchParams(body);
      const code = (form.get('code') || '').trim();
      const next = form.get('next') || '/panel/';
      const ip = clientIp(req);
      if (!cfg.totpSecret) {           // no secret configured -> no gate (documented)
        res.writeHead(302, corsHeaders(req, { Location: next, 'Set-Cookie': makeCookie() }));
        res.end(); return;
      }
      const r = verifyTotp(code, ip);
      if (r.ok) {
        log(`[auth] login ok from ${ip}`);
        res.writeHead(302, corsHeaders(req, { Location: next, 'Set-Cookie': makeCookie() }));
        res.end();
      } else {
        log(`[auth] login FAILED from ${ip} (${r.reason || (r.locked ? 'locked' : 'wrong')})`);
        res.writeHead(302, corsHeaders(req, { Location: `/login?e=${r.locked ? 2 : 1}&next=${encodeURIComponent(next)}` }));
        res.end();
      }
    });
    return;
  }
  if (p === '/logout') {
    res.writeHead(302, corsHeaders(req, { Location: '/login', 'Set-Cookie': 'dash_session=; Path=/; Max-Age=0; SameSite=Lax' }));
    res.end();
    return;
  }

  // ---- gate everything else
  if (!tokenOK(req, res)) return jsonOut(req, res, 401, { error: 'token required' });
  if (cfg.totpSecret && !sessionValid(req)) {
    const isUi = p === '/' || p === cfg.uiPath || p.startsWith(cfg.uiPath + '/');
    // API paths answer a bare 404 so the panel is invisible to unauthenticated scanners
    if (!isUi) { res.writeHead(404, corsHeaders(req, { 'Content-Type': 'text/plain', 'Content-Length': '9' })); res.end('Not Found'); return; }
    res.writeHead(302, corsHeaders(req, { Location: `/login?next=${encodeURIComponent(p)}` }));
    res.end();
    return;
  }

  if (p === '/local/status') return localStatus(req, res);

  // SPA lives under cfg.uiPath so it cannot collide with the controller's API paths
  if (p === '/' || p === cfg.uiPath) {
    res.writeHead(302, corsHeaders(req, { Location: `${cfg.uiPath}/` + (u.search || '') }));
    res.end();
    return;
  }
  if (p.startsWith(cfg.uiPath + '/')) {
    const rel = p.slice(cfg.uiPath.length + 1);
    if (rel === '' || rel === 'index.html') return sendIndex(req, res);
    if (serveStatic(req, res, rel)) return;
    return sendIndex(req, res);   // SPA client-side route
  }
  // bare static assets at the root (favicon, manifest, service worker)
  if (serveStatic(req, res, p.slice(1))) return;

  proxy(req, res);
});

// websocket upgrade (connections / logs streams) -> pipe straight to the controller
server.on('upgrade', (req, socket, head) => {
  if (cfg.totpSecret && !sessionValid(req)) { socket.destroy(); return; }
  const t = target();
  const up = net.connect(t.port, t.host, () => {
    const lines = [`GET ${req.url} HTTP/1.1`];
    const h = { ...req.headers, host: `${t.host}:${t.port}` };
    delete h.origin;
    if (t.secret) h.authorization = `Bearer ${t.secret}`;
    for (const [k, v] of Object.entries(h)) lines.push(`${k}: ${v}`);
    up.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length) up.write(head);
    up.pipe(socket);
    socket.pipe(up);
  });
  up.on('error', () => socket.destroy());
  socket.on('error', () => up.destroy());
});

server.on('error', (e) => {
  log('FATAL listen error', e.code, e.message);
  if (e.code === 'EACCES') log('port is inside a Windows excluded/reserved range - run install.ps1 to reserve it');
  process.exit(1);
});

server.listen(cfg.port, cfg.host, () => {
  const t = target();
  log(`listening on http://${cfg.host}:${cfg.port}${cfg.uiPath}/  -> controller ${t.host}:${t.port} (secret ${t.secret ? 'loaded' : 'none'}, from ${t.from})`);
  log(`auth: totp ${cfg.totpSecret ? 'ENABLED' : 'disabled'} | token ${cfg.token ? 'ENABLED' : 'disabled'} | origin unrestricted (reflect)`);
});
