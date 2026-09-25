// verify-gateway.mjs - end-to-end check of the ClashDashboard gateway (TOTP-gated).
//   node verify-gateway.mjs [port] [lock]
//     port  defaults to 3000
//     lock  also exercise the per-IP lockout (run it against a NON-primary address, see below)
//
// The lockout test locks the SOURCE IP it is called from, so call it with the tailnet address:
//     node verify-gateway.mjs 3000 lock http://<tailnet-ip>
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[2] || 3000);
const DO_LOCK = process.argv.includes('lock');
const HOST = (process.argv.find((a) => a.startsWith('http://')) || 'http://127.0.0.1').replace('http://', '');

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}${extra ? '  ' + extra : ''}`); }
  else { fail++; console.log(`  FAIL  ${name}${extra ? '  ' + extra : ''}`); }
};

// ---- TOTP (same implementation as the gateway, used to mint a valid code for the test)
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s) {
  const clean = String(s).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const i = B32.indexOf(ch); if (i === -1) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp(secret, counter) {
  const b = Buffer.alloc(8);
  b.writeUInt32BE(Math.floor(counter / 2 ** 32), 0); b.writeUInt32BE(counter % 2 ** 32, 4);
  const h = crypto.createHmac('sha1', b32decode(secret)).update(b).digest();
  const o = h[19] & 0x0f;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6).padStart(6, '0');
}

let secret = '', cfg = {};
try {
  cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'config.json'), 'utf8').replace(/^\uFEFF/, ''));
  secret = cfg.totpSecret || '';
} catch (e) { console.log('  WARN  cannot read config.json: ' + e.message); }

function req(method, p, headers = {}, body = null) {
  return new Promise((resolve) => {
    const r = http.request({ host: HOST, port: PORT, path: p, method, headers, timeout: 15000 }, (res) => {
      let b = '';
      res.on('data', (d) => (b += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    r.on('error', (e) => resolve({ status: 0, headers: {}, body: e.code || e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, headers: {}, body: 'timeout' }); });
    if (body) r.write(body);
    r.end();
  });
}
const cookieOf = (res) => (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
function wsUpgrade(cookie) {
  return new Promise((resolve) => {
    const s = net.connect(PORT, HOST, () => {
      s.write(`GET /connections HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n` +
        (cookie ? `Cookie: ${cookie}\r\n` : '') + '\r\n');
    });
    let buf = '';
    s.on('data', (d) => { buf += d.toString('latin1'); if (buf.includes('\r\n')) { s.destroy(); resolve(buf.split('\r\n')[0]); } });
    s.on('error', () => resolve('ERR'));
    setTimeout(() => { try { s.destroy(); } catch { } resolve(buf ? buf.split('\r\n')[0] : 'NO-REPLY'); }, 4000);
  });
}
const login = (code, next = '/panel/') =>
  req('POST', '/login', { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(`code=${code}&next=${next}`) }, `code=${code}&next=${next}`);

console.log(`== gateway checks on ${HOST}:${PORT} (totp ${secret ? 'configured' : 'NOT configured'}) ==`);

// --- public surface
const hz = await req('GET', '/healthz');
ok('/healthz stays public', hz.status === 200, `-> ${hz.status}`);
const loginPage = await req('GET', '/login');
ok('/login serves the TOTP form', loginPage.status === 200 && /name="code"/.test(loginPage.body), `-> ${loginPage.status}`);

// --- unauthenticated must NOT leak the API
const un1 = await req('GET', '/proxies');
ok('unauth API -> 404 (stealth, no hint an API exists)', un1.status === 404, `-> ${un1.status}`);
const un2 = await req('GET', '/local/status');
ok('unauth /local/status -> 404', un2.status === 404, `-> ${un2.status}`);
const un3 = await req('GET', '/');
ok('unauth UI -> redirect to /login', un3.status === 302 && /\/login/.test(un3.headers.location || ''), `-> ${un3.status} ${un3.headers.location || ''}`);
const un4 = await req('GET', '/panel/');
ok('unauth /panel/ -> redirect to /login', un4.status === 302 && /\/login/.test(un4.headers.location || ''), `-> ${un4.status}`);

// --- preflight must still answer 204 for ANY origin (the CORS trap)
const pre = await req('OPTIONS', '/proxies', {
  Origin: 'https://random-origin.example', 'Access-Control-Request-Method': 'GET',
  'Access-Control-Request-Headers': 'authorization,x-test',
});
ok('CORS preflight -> 204 (never 404)', pre.status === 204, `-> ${pre.status}`);
ok('CORS preflight reflects the origin + allows credentials',
  pre.headers['access-control-allow-origin'] === 'https://random-origin.example' &&
  pre.headers['access-control-allow-credentials'] === 'true',
  `ACAO=${pre.headers['access-control-allow-origin']} ACAC=${pre.headers['access-control-allow-credentials']}`);
ok('CORS preflight echoes requested headers', (pre.headers['access-control-allow-headers'] || '').includes('authorization'));

// --- wrong code must be rejected
if (secret) {
  const wrong = await login('000000');
  ok('wrong TOTP code is rejected', wrong.status === 302 && /e=1|e=2/.test(wrong.headers.location || ''), `-> ${wrong.status} ${wrong.headers.location || ''}`);
}

// --- correct code logs in
let cookie = '';
if (secret) {
  const counter = Math.floor(Date.now() / 1000 / 30);
  // use the current window, and fall back to the NEXT window (+1) if this one was already consumed:
  // the gateway accepts a +/-1 window, and re-running the verifier inside the same 30 s would
  // otherwise trip the replay guard (correctly) and make the test look broken.
  let good = await login(totp(secret, counter));
  if (!/dash_session=/.test(cookieOf(good))) good = await login(totp(secret, counter + 1));
  const code = totp(secret, counter);
  cookie = cookieOf(good);
  ok('valid TOTP code -> redirect + session cookie', good.status === 302 && /dash_session=/.test(cookie), `-> ${good.status}`);
  ok('session cookie is HttpOnly + SameSite=Lax', /HttpOnly/i.test((good.headers['set-cookie'] || [''])[0]) && /SameSite=Lax/i.test((good.headers['set-cookie'] || [''])[0]));

  // --- replay a code that was definitely used: try the currently valid windows until one is burned
  let replayed = false;
  for (const d of [0, 1, -1]) {
    const c = totp(secret, counter + d);
    const first = await login(c);
    if (/dash_session=/.test(cookieOf(first))) {           // this one was fresh -> use it for the replay test
      const again = await login(c);
      replayed = !/dash_session=/.test(cookieOf(again));
      break;
    }
  }
  ok('replaying an already-used code is refused', replayed);

  // --- authenticated surface
  const ver = await req('GET', '/version', { Cookie: cookie, Origin: 'https://random-origin.example' });
  let vj = null; try { vj = JSON.parse(ver.body); } catch { }
  ok('authed GET /version proxied', ver.status === 200 && vj && !!vj.version, `-> ${ver.status} version=${vj && vj.version}`);
  ok('CORS: authed cross-origin response reflects origin', ver.headers['access-control-allow-origin'] === 'https://random-origin.example' && ver.headers['access-control-allow-credentials'] === 'true');
  const prox = await req('GET', '/proxies', { Cookie: cookie });
  let pj = null; try { pj = JSON.parse(prox.body); } catch { }
  ok('authed GET /proxies proxied (secret injected server-side)', prox.status === 200 && pj && pj.proxies && Object.keys(pj.proxies).length > 0, `groups=${pj && pj.proxies ? Object.keys(pj.proxies).length : 0}`);
  // the controller secret must never appear in a proxied response: discover it from the Clash runtime
  // config and assert it is absent, rather than hardcoding it in the test
  let ctrlSecret = '';
  for (const cand of [cfg.clashConfig,
    path.join(process.env.APPDATA || '', 'io.github.clash-verge-rev.clash-verge-rev', 'clash-verge.yaml')].filter(Boolean)) {
    try {
      const m = /^\s*secret:\s*['"]?([^\s'"]+)/m.exec(fs.readFileSync(cand, 'utf8'));
      if (m) { ctrlSecret = m[1]; break; }
    } catch { }
  }
  ok('controller secret never reaches the client', !ctrlSecret || !prox.body.includes(ctrlSecret), ctrlSecret ? '' : '(no secret found; skipped)');
  const st = await req('GET', '/local/status', { Cookie: cookie });
  let sj = null; try { sj = JSON.parse(st.body); } catch { }
  ok('authed /local/status', st.status === 200 && sj && sj.ok === true, `tun=${sj && sj.config && sj.config.tunEnable} totp=${sj && sj.gateway && sj.gateway.totp}`);
  const idx = await req('GET', '/panel/', { Cookie: cookie });
  ok('authed /panel/ serves the SPA shell + backend seed', idx.status === 200 && idx.body.includes('dash-backend-seed') && idx.body.includes("q.set('protocol'"));
  const asset = idx.body.match(/src="\.\/(assets\/[^"]+)"/);
  if (asset) {
    const a = await req('GET', '/panel/' + asset[1], { Cookie: cookie });
    ok('authed SPA asset served', a.status === 200 && /javascript/.test(a.headers['content-type'] || ''), `-> ${asset[1]}`);
  }
  const ws = await wsUpgrade(cookie);
  ok('websocket proxied with a session cookie (101)', /101/.test(ws), ws);
  const wsNo = await wsUpgrade('');
  ok('websocket without a cookie is refused', !/101/.test(wsNo), wsNo);
} else {
  console.log('  SKIP  TOTP checks (no totpSecret in config.json)');
}

// --- optional lockout test (locks the caller IP, so use the tailnet address)
if (DO_LOCK && secret) {
  console.log(`  -- lockout test from ${HOST} --`);
  let last = null;
  for (let i = 0; i < 5; i++) last = await login('111111');
  const nowLocked = /e=2/.test(last.headers.location || '');
  ok('5 wrong codes lock the source IP', nowLocked, `-> ${last.headers.location || ''}`);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const after = await login(totp(secret, counter + 1));   // correct code while locked
  ok('lockout blocks even a correct code', after.status === 302 && /e=2/.test(after.headers.location || ''), `-> ${after.headers.location || ''}`);
}

console.log(`\n== ${pass} passed, ${fail} failed ==`);
process.exit(fail ? 1 : 0);
