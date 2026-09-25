// /opt/hyexit/panel/server.mjs
// Hidden TOTP-gated control gateway for the hyexit (tailscale exit node + mihomo) stack.
//
//   /clashConfiguePage            -> login page (no session) | control console (session)
//   /clashConfiguePage/login      -> POST { code } -> session cookie
//   /clashConfiguePage/logout     -> clear session
//   /clashConfiguePage/panel      -> 302 -> /            (full zashboard UI)
//   /clashConfiguePage/api/...    -> control API (status / power / subs / logs)
//   /<mihomo api paths>           -> reverse proxy to the mihomo controller, secret injected
//   /<anything else>              -> static zashboard files, ONLY with a valid session
//
// Unauthenticated requests get 404 everywhere except the login page, so the port shows no
// fingerprint to a scanner. Sessions are per-IP locked after too many bad TOTP attempts.
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const HY = '/opt/hyexit';
const STATE = path.join(HY, 'state');
const PUBLIC = path.join(DIR, 'public');
const LISTEN = { host: '127.0.0.1', port: 19121 };
const CONTROLLER = 'http://127.0.0.1:19120';
const MIXED_PORT = 17897;
const NODE_BIN = 'node';

const SECRET = fs.readFileSync(path.join(STATE, 'controller.secret'), 'utf8').trim();
const TOTP_SECRET = fs.readFileSync(path.join(STATE, 'totp.secret'), 'utf8').trim();
const LOCK_FILE = path.join(STATE, 'panel-locks.json');
const SESS_FILE = path.join(STATE, 'panel-sessions.json');

const MAX_FAILS = 5;
const LOCK_MS = 2 * 60 * 60 * 1000;   // 2 hours, same policy as the DSH panel
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const TOTP_STEP = 30;
const TOTP_DIGITS = 6;

// ---------------------------------------------------------------- state files
function loadJson(f, dflt) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return dflt; } }
function saveJson(f, v) { try { fs.writeFileSync(f, JSON.stringify(v), { mode: 0o600 }); } catch (e) { log('save ' + f + ' failed: ' + e.message); } }
let locks = loadJson(LOCK_FILE, {});
let sessions = loadJson(SESS_FILE, {});

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  process.stdout.write(line);   // systemd captures stdout into panel.log (no double write)
}
// TOTP replay guard: a 30s-step code may only be used once per IP (same rule as the DSH panel).
const OTP_FILE = path.join(STATE, 'panel-otp.json');
let otpUsed = loadJson(OTP_FILE, {});
function otpSeen(ip, counter) {
  const e = otpUsed[ip] || { counters: [] };
  if (e.counters.includes(counter)) return true;
  e.counters = [...e.counters.slice(-4), counter];
  otpUsed[ip] = e; saveJson(OTP_FILE, otpUsed);
  return false;
}

// ---------------------------------------------------------------- totp
function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = String(s).replace(/[=\s-]/g, '').toUpperCase();
  let bits = 0, val = 0; const out = [];
  for (const c of s) {
    const i = A.indexOf(c); if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totpAt(key, counter) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 0x0f;
  const code = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** TOTP_DIGITS;
  return String(code).padStart(TOTP_DIGITS, '0');
}
function verifyTotp(code) {
  const key = base32Decode(TOTP_SECRET);
  const now = Math.floor(Date.now() / 1000 / TOTP_STEP);
  const c = String(code || '').replace(/\D/g, '');
  if (c.length !== TOTP_DIGITS) return null;
  for (const d of [-1, 0, 1]) {
    const expect = Buffer.from(totpAt(key, now + d));
    const got = Buffer.from(c);
    if (expect.length === got.length && crypto.timingSafeEqual(expect, got)) return now + d;
  }
  return null;
}

// ---------------------------------------------------------------- locks/sessions
function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.socket.remoteAddress || 'unknown';
}
function lockInfo(ip) {
  const l = locks[ip];
  if (!l) return null;
  if (l.until && l.until > Date.now()) return l;
  return null;
}
function noteFail(ip) {
  const l = locks[ip] || { fails: 0, until: 0 };
  l.fails = (l.fails || 0) + 1;
  l.last = Date.now();
  if (l.fails >= MAX_FAILS) { l.until = Date.now() + LOCK_MS; l.fails = 0; log(`LOCK ip=${ip} for 2h (too many bad codes)`); }
  locks[ip] = l; saveJson(LOCK_FILE, locks);
}
function clearFails(ip) { if (locks[ip]) { delete locks[ip]; saveJson(LOCK_FILE, locks); } }
function newSession(ip) {
  const t = crypto.randomBytes(32).toString('base64url');
  sessions[t] = { exp: Date.now() + SESSION_MS, ip, created: Date.now() };
  // prune
  for (const [k, v] of Object.entries(sessions)) if (v.exp < Date.now()) delete sessions[k];
  saveJson(SESS_FILE, sessions);
  return t;
}
function sessionOf(req) {
  const raw = String(req.headers.cookie || '');
  const m = raw.match(/hyexit_s=([A-Za-z0-9_-]+)/);
  if (!m) return null;
  const s = sessions[m[1]];
  if (!s || s.exp < Date.now()) return null;
  return { token: m[1], ...s };
}

// ---------------------------------------------------------------- helpers
const run = (cmd, args, timeout = 15000) => new Promise((resolve) => {
  execFile(cmd, args, { timeout, maxBuffer: 4 << 20 }, (err, stdout, stderr) => {
    resolve({ ok: !err, code: err ? (err.code ?? 1) : 0, out: String(stdout || ''), err: String(stderr || '') });
  });
});

async function mihomoGet(p) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(CONTROLLER + p, { headers: { Authorization: `Bearer ${SECRET}` }, signal: ctl.signal });
    return await r.json();
  } catch { return null; } finally { clearTimeout(t); }
}

function readFile(p, n = 4000) { try { return fs.readFileSync(p, 'utf8').slice(-n); } catch { return ''; } }

async function collectStatus() {
  const [active, tun, rules, tsJson, providerJson, versionJson, sysinfo] = await Promise.all([
    run('systemctl', ['is-active', 'hyexit-mihomo.service']),
    run('ip', ['link', 'show', 'hyexit0']),
    run('ip', ['rule', 'show']),
    run('tailscale', ['status', '--json']),
    mihomoGet('/providers/proxies'),
    mihomoGet('/version'),
    run('bash', ['-c', 'uptime -p; free -m | sed -n 2p; df -h / | tail -1']),
  ]);

  let self = {}, peers = [];
  try {
    const d = JSON.parse(tsJson.out);
    self = d.Self || {};
    peers = Object.values(d.Peer || {}).map((p) => ({ name: p.HostName, ip: (p.TailscaleIPs || [])[0], online: !!p.Online, exit: !!p.ExitNodeOption }));
  } catch {}

  const providers = [];
  if (providerJson && providerJson.providers) {
    for (const [name, v] of Object.entries(providerJson.providers)) {
      const ui = v.subscriptionInfo || {};
      providers.push({
        name, nodes: (v.proxies || []).length,
        updated: v.updatedAt || null,
        used: ui.Upload != null ? ui.Upload + ui.Download : null,
        total: ui.Total ?? null,
        expire: ui.Expire ?? null,
      });
    }
  }
  const mode = (await mihomoGet('/configs'))?.mode || null;

  // egress checks
  const proxied = await run('curl', ['-s', '-m', '20', '-x', `http://127.0.0.1:${MIXED_PORT}`, 'https://api.ipify.org']);
  const direct = await run('curl', ['-s', '-m', '12', 'https://api.ipify.org']);
  const resolver = await run('bash', ['-c', "grep -E '^nameserver' /run/systemd/resolve/resolv.conf | tr '\\n' ' '"]);
  const hostDnsClean = !/198\.18\.|fdfe:dcba/.test(resolver.out);

  return {
    at: new Date().toISOString(),
    clash: {
      active: active.out.trim() === 'active',
      tunUp: tun.ok,
      version: versionJson?.version || null,
      mode,
      providers,
      rules: rules.out.split('\n').filter((l) => /5190|5200/.test(l)).map((l) => l.trim()),
    },
    exitNode: {
      hostname: self.HostName || null,
      ip: (self.TailscaleIPs || [])[0] || null,
      advertised: !!self.ExitNodeOption,          // set once the route is approved in the admin console
      online: !!self.Online,
      peers,
    },
    egress: {
      proxiedIp: proxied.ok ? proxied.out.trim() : null,
      directIp: direct.ok ? direct.out.trim() : null,
    },
    safety: {
      hostDnsClean,
      resolvers: resolver.out.trim(),
      ipRules: rules.out.split('\n').filter((l) => /5190|5200/.test(l)).length,
    },
    server: { info: sysinfo.out.trim().split('\n') },
  };
}

// ---------------------------------------------------------------- pages
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function loginPage(msg = '') {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>·</title><style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0d10;color:#e6e8eb;font:15px/1.5 -apple-system,Segoe UI,Roboto,"Noto Sans SC",sans-serif}
.card{width:min(92vw,380px);padding:28px;border:1px solid #1e2430;border-radius:16px;background:#11151b;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{font-size:15px;font-weight:600;margin:0 0 4px;letter-spacing:.02em}
p.sub{margin:0 0 20px;color:#7c8798;font-size:12.5px}
input{width:100%;padding:14px 16px;font:600 22px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.42em;text-align:center;background:#0b0e13;border:1px solid #222a36;border-radius:10px;color:#e6e8eb;outline:none}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15)}
button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:10px;background:#2563eb;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#1d4ed8}
.msg{margin:14px 0 0;font-size:12.5px;color:#f87171;word-break:break-all}
.foot{margin-top:18px;font-size:11.5px;color:#5b6473}
</style></head><body><form class="card" method="POST" action="/clashConfiguePage/login">
<h1>需要验证</h1><p class="sub">输入认证器中的 6 位动态码</p>
<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" maxlength="6" autofocus placeholder="······">
<button type="submit">进入</button>
${msg ? `<div class="msg">${esc(msg)}</div>` : ''}
<div class="foot">连续 ${MAX_FAILS} 次错误将锁定该 IP 2 小时。</div>
</form>
<script>const i=document.querySelector('input');i.addEventListener('input',()=>{if(i.value.replace(/\\D/g,'').length===6)document.querySelector('form').submit()});</script>
</body></html>`;
}

function consolePage() {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>hyexit</title><style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0d10;color:#e6e8eb;font:14px/1.6 -apple-system,Segoe UI,Roboto,"Noto Sans SC",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:24px 18px 60px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:17px;margin:0;font-weight:650}
.spacer{flex:1}
a.btn,button.btn{display:inline-block;padding:9px 14px;border-radius:9px;border:1px solid #263041;background:#141a23;color:#cfd6e2;text-decoration:none;font-size:13px;cursor:pointer}
button.btn.primary{background:#2563eb;border-color:#2563eb;color:#fff}
button.btn.danger{background:#7f1d1d;border-color:#991b1b;color:#fff}
button.btn:disabled{opacity:.45;cursor:not-allowed}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.card{border:1px solid #1c232e;border-radius:14px;background:#0f131a;padding:16px}
.card h2{margin:0 0 10px;font-size:13px;font-weight:600;color:#8b97a8;letter-spacing:.04em;text-transform:uppercase}
.kv{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px dashed #1a212b;font-size:13px}
.kv:last-child{border-bottom:0}
.kv b{font-weight:600;color:#e6e8eb;text-align:right;word-break:break-all}
.ok{color:#34d399}.bad{color:#f87171}.warn{color:#fbbf24}.dim{color:#6b7280}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 4px;border-bottom:1px solid #1a212b}
th{color:#7c8798;font-weight:500}
pre{background:#080a0e;border:1px solid #1a212b;border-radius:9px;padding:10px;max-height:260px;overflow:auto;font-size:11.5px;color:#9aa6b6;white-space:pre-wrap;word-break:break-all}
.pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11.5px;border:1px solid #263041}
</style></head><body><div class="wrap">
<header>
  <h1>hyexit · 出口节点控制台</h1>
  <span class="spacer"></span>
  <a class="btn" href="/clashConfiguePage/panel" target="_blank">完整面板 (zashboard) ↗</a>
  <a class="btn" href="/clashConfiguePage/logout">退出</a>
</header>
<div class="grid">
  <div class="card"><h2>Clash 出口代理</h2><div id="clash">载入中…</div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn primary" id="btnOn">开启 Clash（走代理）</button>
      <button class="btn danger" id="btnOff">关闭 Clash（直出香港）</button>
      <button class="btn" id="btnSubs">更新订阅</button>
      <button class="btn" id="btnRefresh">刷新状态</button>
    </div>
    <div id="opmsg" class="dim" style="margin-top:10px;font-size:12.5px"></div>
  </div>
  <div class="card"><h2>出口测试</h2><div id="egress">…</div></div>
  <div class="card"><h2>Tailscale 出口节点</h2><div id="ts">…</div></div>
  <div class="card"><h2>安全断言</h2><div id="safety">…</div></div>
  <div class="card" style="grid-column:1/-1"><h2>订阅 / 节点</h2><div id="prov"></div></div>
  <div class="card" style="grid-column:1/-1"><h2>服务器</h2><div id="srv"></div></div>
  <div class="card" style="grid-column:1/-1"><h2>日志（尾部）</h2><pre id="logs">…</pre></div>
</div>
</div>
<script>
const $ = (id) => document.getElementById(id);
const gb = (n) => n == null ? '—' : (n / 1073741824).toFixed(1) + ' GB';
const ts = (s) => s ? new Date(s).toLocaleString('zh-CN') : '—';
const kv = (k, v, cls) => '<div class="kv"><span class="dim">' + k + '</span><b class="' + (cls || '') + '">' + v + '</b></div>';

async function load(statusOnly) {
  try {
    const r = await fetch('/clashConfiguePage/api/status', { cache: 'no-store' });
    if (r.status === 401) { location.href = '/clashConfiguePage'; return; }
    const s = await r.json();
    $('clash').innerHTML =
      kv('运行状态', s.clash.active ? '<span class="ok">运行中</span>' : '<span class="bad">已停止</span>') +
      kv('TUN 设备', s.clash.tunUp ? '<span class="ok">hyexit0 正常</span>' : '<span class="bad">缺失</span>') +
      kv('分流模式', s.clash.mode || '—') +
      kv('内核', s.clash.version || '—');
    $('egress').innerHTML =
      kv('经代理出口', s.egress.proxiedIp || '<span class="bad">不可用</span>') +
      kv('直连出口（本机）', s.egress.directIp || '—');
    $('ts').innerHTML =
      kv('节点名', s.exitNode.hostname || '—') +
      kv('tailnet IP', s.exitNode.ip || '—') +
      kv('已声明出口节点', s.exitNode.advertised ? '<span class="ok">是（已批准）</span>' : '<span class="warn">否（未声明或管理台未批准）</span>') +
      kv('在线', s.exitNode.online ? '是' : '否');
    $('safety').innerHTML =
      kv('宿主 DNS 未被污染', s.safety.hostDnsClean ? '<span class="ok">通过</span>' : '<span class="bad">异常：解析被劫持</span>') +
      kv('策略路由规则', s.safety.ipRules + ' 条' + (s.safety.ipRules >= 2 ? ' <span class="ok">✓</span>' : ' <span class="bad">✗</span>')) +
      kv('上游 DNS', s.safety.resolvers || '—');
    let ph = '<table><tr><th>订阅</th><th>节点</th><th>已用</th><th>总量</th><th>更新</th></tr>';
    for (const p of s.clash.providers) ph += '<tr><td>' + p.name + '</td><td>' + p.nodes + '</td><td>' + gb(p.used) + '</td><td>' + gb(p.total) + '</td><td>' + ts(p.updated) + '</td></tr>';
    $('prov').innerHTML = ph + '</table>';
    $('srv').innerHTML = s.server.info.map((l) => '<div class="kv"><span>' + l + '</span></div>').join('');
  } catch (e) { $('opmsg').textContent = '状态载入失败: ' + e.message; }
}
async function act(path, body, label) {
  $('opmsg').textContent = label + ' …';
  try {
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    const j = await r.json().catch(() => ({}));
    $('opmsg').textContent = (r.ok ? '✅ ' : '❌ ') + (j.message || r.status);
  } catch (e) { $('opmsg').textContent = '❌ ' + e.message; }
  setTimeout(() => load(true), 1200);
}
$('btnOn').onclick = () => act('/clashConfiguePage/api/power', { on: true }, '正在启动 Clash');
$('btnOff').onclick = () => act('/clashConfiguePage/api/power', { on: false }, '正在停止 Clash');
$('btnSubs').onclick = () => act('/clashConfiguePage/api/subs', {}, '正在更新订阅与规则');
$('btnRefresh').onclick = () => load(true);
async function logs() { try { const r = await fetch('/clashConfiguePage/api/logs', { cache: 'no-store' }); $('logs').textContent = await r.text(); } catch {} }
load(true); logs(); setInterval(logs, 15000);
</script></body></html>`;
}

// ---------------------------------------------------------------- static
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.mjs': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8', '.map': 'application/json' };
// zashboard discovers its backend from URL params read off location.search / the hash:
//   hostname, port, protocol, secret, type
// It builds the base URL as `${protocol}://${host}:${port}`. With nothing set it defaults to
// http://<host>:9090; on an HTTPS page that is (a) mixed content and (b) a different origin,
// so the browser fires a CORS preflight, the gateway 404s it, and zashboard shows
// "后端能连上，但浏览器按同源策略拦下了响应" and never calls the API.
// So ALWAYS seed protocol+hostname+port for this very origin. The controller secret stays
// server-side: the gateway injects it, so zashboard needs no password.
const SEED = `<script id="hyexit-backend-seed">(function(){try{
var q=(location.hash&&location.hash.indexOf('?')>=0)?location.hash.slice(location.hash.indexOf('?')):location.search;
var p=new URLSearchParams(q||'');
if(!p.has('hostname')||!p.has('protocol')){
  var u=new URL(location.href);
  u.searchParams.set('hostname',location.hostname);
  u.searchParams.set('port',location.port||(location.protocol==='https:'?'443':'80'));
  u.searchParams.set('protocol',location.protocol.replace(':',''));
  history.replaceState(null,'',u.pathname+'?'+u.searchParams.toString()+u.hash);
}
}catch(e){}})();</script>`;

function sendHtml(res, file) {
  let html;
  try { html = fs.readFileSync(file, 'utf8'); } catch { res.writeHead(500).end('read error'); return; }
  if (!html.includes('hyexit-backend-seed')) html = html.replace(/<head>/i, '<head>\n' + SEED);
  res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-store' });
  res.end(html);
}

function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath.split('?')[0]);
  if (rel === '/' || rel === '') rel = '/index.html';
  const full = path.join(PUBLIC, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
  if (!full.startsWith(PUBLIC)) { res.writeHead(404).end('Not Found'); return; }
  fs.stat(full, (err, st) => {
    if (err || !st.isFile()) {
      // SPA fallback
      const idx = path.join(PUBLIC, 'index.html');
      if (fs.existsSync(idx)) sendHtml(res, idx);
      else res.writeHead(404).end('Not Found');
      return;
    }
    if (path.extname(full).toLowerCase() === '.html') { sendHtml(res, full); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    fs.createReadStream(full).pipe(res);
  });
}

// ---------------------------------------------------------------- mihomo api proxy
const API_PREFIXES = ['/version', '/configs', '/proxies', '/providers', '/rules', '/connections', '/logs', '/traffic', '/memory', '/dns', '/group', '/script', '/profile', '/restart', '/upgrade', '/cache', '/delay', '/healthcheck', '/debug'];
const isApi = (p) => API_PREFIXES.some((x) => p === x || p.startsWith(x + '/') || p.startsWith(x + '?'));

function proxyApi(req, res) {
  const u = new URL(CONTROLLER + req.url);
  const headers = { ...req.headers, host: u.host, authorization: `Bearer ${SECRET}` };
  delete headers.cookie;
  const origin = String(req.headers.origin || '');
  const preq = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: req.method, headers }, (pres) => {
    const out = { ...pres.headers };
    if (origin) { out['access-control-allow-origin'] = origin; out['access-control-allow-credentials'] = 'true'; out['vary'] = 'Origin'; }
    res.writeHead(pres.statusCode, out);
    pres.pipe(res);
  });
  preq.on('error', (e) => { res.writeHead(502, { 'Content-Type': 'text/plain' }).end('controller error: ' + e.message); });
  req.pipe(preq);
}

// ---------------------------------------------------------------- control api
async function apiStatus(res) {
  const s = await collectStatus();
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }).end(JSON.stringify(s));
}

async function apiPower(req, res, ip) {
  const body = await readBody(req);
  const on = !!(body && body.on);
  log(`power ${on ? 'ON' : 'OFF'} by ${ip}`);
  const r = on
    ? await run('systemctl', ['start', 'hyexit-mihomo.service'], 30000)
    : await run('systemctl', ['stop', 'hyexit-mihomo.service'], 30000);
  // when ON, wait (briefly) for the start post-script to install the TPROXY capture.
  // Keep this in sync with route-up.sh: an earlier version waited on a rule name that no
  // longer existed and always burned the full 30s -> browsers aborted (nginx 499).
  if (on) await run('bash', ['-c', 'for i in $(seq 1 12); do ip rule show | grep -q "fwmark 0x1 lookup 100" && ss -tln | grep -q ":17899" && break; sleep 1; done']);
  else await run('bash', ['-c', 'sleep 2']);
  const st = await run('systemctl', ['is-active', 'hyexit-mihomo.service']);
  const ok = on ? st.out.trim() === 'active' : st.out.trim() !== 'active';
  res.writeHead(ok ? 200 : 500, { 'Content-Type': 'application/json' }).end(JSON.stringify({
    ok,
    message: on
      ? (ok ? 'Clash 已开启，出口流量走代理' : '启动失败：' + (r.err || r.out).slice(0, 200))
      : (ok ? 'Clash 已关闭，出口流量直出香港（不会失联）' : '停止失败：' + (r.err || r.out).slice(0, 200)),
  }));
}

async function apiSubs(res, ip) {
  log(`subs update by ${ip}`);
  const r = await run(NODE_BIN, [path.join(HY, 'bin', 'gen-config.mjs')], 600000);
  const tail = (r.out + r.err).split('\n').filter(Boolean).slice(-6).join(' | ');
  if (!r.ok) { res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: false, message: '生成失败：' + tail })); return; }
  const rr = await run('systemctl', ['restart', 'hyexit-mihomo.service'], 40000);
  res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true, message: '订阅与规则已更新并重载：' + tail.slice(0, 300) + (rr.ok ? '' : ' (重载异常)') }));
}

function apiLogs(res) {
  const a = readFile(path.join(HY, 'logs', 'mihomo.log'), 6000);
  const b = readFile(path.join(HY, 'logs', 'panel.log'), 2000);
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }).end('=== mihomo ===\n' + a + '\n\n=== panel ===\n' + b);
}

function readBody(req) {
  return new Promise((resolve) => {
    const c = []; req.on('data', (d) => { c.push(d); if (Buffer.concat(c).length > 65536) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(c).toString('utf8') || '{}')); } catch { resolve(null); } });
  });
}

// ---------------------------------------------------------------- server
const server = http.createServer(async (req, res) => {
  const ip = clientIp(req);
  const p = req.url.split('?')[0];
  const sess = sessionOf(req);

  // login flow
  if (p === '/clashConfiguePage/login' && req.method === 'POST') {
    const l = lockInfo(ip);
    if (l) {
      const mins = Math.ceil((l.until - Date.now()) / 60000);
      res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' }).end(loginPage(`该 IP 已被锁定，请 ${mins} 分钟后再试。`));
      return;
    }
    const form = await new Promise((resolve) => { let b = ''; req.on('data', (d) => { b += d; if (b.length > 4096) req.destroy(); }); req.on('end', () => resolve(b)); });
    const code = new URLSearchParams(form).get('code') || '';
    const ctr = verifyTotp(code);
    if (ctr !== null) {
      if (otpSeen(ip, ctr)) {
        log(`login REPLAY rejected ip=${ip} counter=${ctr}`);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' }).end(loginPage('该动态码已被使用过，请等待下一个 30 秒窗口。'));
        return;
      }
      clearFails(ip);
      const t = newSession(ip);
      log(`login OK ip=${ip}`);
      res.writeHead(302, { 'Set-Cookie': `hyexit_s=${t}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`, Location: '/clashConfiguePage' }).end();
    } else {
      noteFail(ip);
      const left = MAX_FAILS - ((locks[ip]?.fails) || 0);
      log(`login FAIL ip=${ip}`);
      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' }).end(loginPage(`动态码不正确。${left > 0 ? `还可尝试 ${left} 次。` : ''}`));
    }
    return;
  }
  if (p === '/clashConfiguePage/logout') {
    if (sess) { delete sessions[sess.token]; saveJson(SESS_FILE, sessions); }
    res.writeHead(302, { 'Set-Cookie': 'hyexit_s=; Path=/; Max-Age=0', Location: '/clashConfiguePage' }).end();
    return;
  }

  // CORS preflight. zashboard probes `/version` with an Authorization header, which makes the
  // browser send OPTIONS first; without a proper preflight answer the probe fails and the UI
  // reports "backend blocked by CORS" even though the API itself is fine. Answer it for every
  // path (preflights carry no credentials, so no auth required here).
  if (req.method === 'OPTIONS') {
    const o = String(req.headers.origin || '');
    res.writeHead(204, {
      'Access-Control-Allow-Origin': o || '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': String(req.headers['access-control-request-headers'] || 'Authorization,Content-Type'),
      'Access-Control-Max-Age': '86400',
      'Access-Control-Allow-Credentials': 'true',
      'Vary': 'Origin',
    }).end();
    return;
  }

  const authed = !!sess;

  if (p === '/clashConfiguePage' || p === '/clashConfiguePage/') {
    if (!authed) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }).end(loginPage()); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }).end(consolePage());
    return;
  }
  if (p === '/clashConfiguePage/panel') {
    if (!authed) { res.writeHead(404).end('Not Found'); return; }
    // hand zashboard its backend explicitly; protocol matters (http would be cross-origin
    // and trigger a preflight). The gateway injects the controller secret, so no password.
    const hostHeader = String(req.headers.host || '');
    const host = hostHeader.replace(/:\d+$/, '');
    const port = hostHeader.split(':')[1] || '443';
    const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
    res.writeHead(302, { Location: `/?hostname=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}&protocol=${encodeURIComponent(proto)}` }).end();
    return;
  }

  // control api
  if (p.startsWith('/clashConfiguePage/api/')) {
    if (!authed) { res.writeHead(404).end('Not Found'); return; }   // same 404 as everything else: no fingerprint
    if (p === '/clashConfiguePage/api/status' && req.method === 'GET') return apiStatus(res);
    if (p === '/clashConfiguePage/api/power' && req.method === 'POST') return apiPower(req, res, ip);
    if (p === '/clashConfiguePage/api/subs' && req.method === 'POST') return apiSubs(res, ip);
    if (p === '/clashConfiguePage/api/logs' && req.method === 'GET') return apiLogs(res);
    res.writeHead(404).end('Not Found');
    return;
  }

  // mihomo controller api (secret injected server-side)
  if (isApi(p)) {
    if (!authed) { res.writeHead(404).end('Not Found'); return; }
    return proxyApi(req, res);
  }

  // everything else: static SPA, only when authenticated (no fingerprint otherwise)
  if (!authed) { res.writeHead(404).end('Not Found'); return; }
  serveStatic(req, res, req.url);
});

// websocket upgrade passthrough for /traffic /logs /connections /memory
server.on('upgrade', (req, socket, head) => {
  const sess = sessionOf(req);
  const p = req.url.split('?')[0];
  if (!sess || !isApi(p)) { socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy(); return; }
  const u = new URL(CONTROLLER + req.url);
  const preq = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, headers: { ...req.headers, host: u.host, authorization: `Bearer ${SECRET}` } });
  preq.on('upgrade', (pres, psocket, phead) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\n' + Object.entries(pres.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n');
    if (phead && phead.length) socket.write(phead);
    psocket.pipe(socket); socket.pipe(psocket);
    psocket.on('error', () => socket.destroy()); socket.on('error', () => psocket.destroy());
  });
  preq.on('error', () => socket.destroy());
  preq.end();
});

server.listen(LISTEN.port, LISTEN.host, () => log(`panel gateway listening on http://${LISTEN.host}:${LISTEN.port} (auth: TOTP, ${MAX_FAILS} fails -> 2h ip lock)`));
