// panel-cli.mjs - operate the hyexit control panel from the command line.
//   node panel-cli.mjs status | on | off | subs | login
// Zero deps. TOTP is computed locally from the shared secret.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// deployment-specific values (NOT committed) come from /opt/hyexit/config/gen.env
try {
  for (const line of fs.readFileSync('/opt/hyexit/config/gen.env', 'utf8').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = /^([A-Za-z0-9_]+)=(.*)$/.exec(t);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']/, '').replace(/["']$/, '');
  }
} catch { /* no gen.env: fall back to env vars / defaults */ }
const HOST = process.env.HYEXIT_HOST || process.env.PANEL_HOST || 'panel.example.com';
const PORT = Number(process.env.HYEXIT_PORT || process.env.PANEL_PORT || 10443);
const BASE = `https://${HOST}:${PORT}`;
// TOTP secret: pass it inline (HYEXIT_TOTP) or point at the file the gateway generated.
const SECRET_FILE = process.env.HYEXIT_SECRET_FILE || '/opt/hyexit/state/totp.secret';
const SECRET = process.env.HYEXIT_TOTP || fs.readFileSync(SECRET_FILE, 'utf8').trim();
const COOKIE_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '.panel-session');

function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = String(s).replace(/[=\s-]/g, '').toUpperCase();
  let bits = 0, val = 0; const out = [];
  for (const c of s) { const i = A.indexOf(c); if (i < 0) continue; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; } }
  return Buffer.from(out);
}
function totp(step = 30, digits = 6) {
  const key = base32Decode(SECRET);
  let counter = Math.floor(Date.now() / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0); buf.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 0x0f;
  return String((((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** digits).padStart(digits, '0');
}

let cookie = '';
try { cookie = fs.readFileSync(COOKIE_FILE, 'utf8').trim(); } catch {}

async function req(path, opts = {}) {
  const r = await fetch(BASE + path, {
    ...opts,
    headers: { ...(opts.headers || {}), ...(cookie ? { cookie } : {}) },
    redirect: 'manual',
  });
  const setC = r.headers.getSetCookie ? r.headers.getSetCookie() : [r.headers.get('set-cookie')].filter(Boolean);
  for (const c of setC) { const m = c.match(/hyexit_s=[A-Za-z0-9_-]+/); if (m) { cookie = m[0]; fs.writeFileSync(COOKIE_FILE, cookie); } }
  return r;
}

async function ensureLogin() {
  const t = await req('/clashConfiguePage');
  if (t.status === 200) {
    const html = await t.text();
    if (!html.includes('clashConfiguePage/login')) return true;   // already authed (console page)
  }
  const body = new URLSearchParams({ code: totp() });
  const r = await req('/clashConfiguePage/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  if (r.status === 302 || r.status === 200) { const h = await r.text().catch(() => ''); if (r.status === 302 || !h.includes('login')) return true; }
  console.error(`login failed: HTTP ${r.status} ${(await r.text().catch(() => '')).slice(0, 200)}`);
  return false;
}

const cmd = (process.argv[2] || 'status').toLowerCase();
if (!(await ensureLogin())) process.exit(2);

if (cmd === 'login') { console.log('login ok'); process.exit(0); }

if (cmd === 'status') {
  const r = await req('/clashConfiguePage/api/status');
  const s = await r.json();
  console.log(`clash        : ${s.clash.active ? 'ON ' : 'OFF'}  tun=${s.clash.tunUp} mode=${s.clash.mode} ${s.clash.version || ''}`);
  console.log(`egress       : proxied=${s.egress.proxiedIp || '-'}  direct=${s.egress.directIp || '-'}`);
  console.log(`exit node    : ${s.exitNode.hostname} ${s.exitNode.ip} advertised=${s.exitNode.advertised}`);
  console.log(`safety       : hostDnsClean=${s.safety.hostDnsClean} ipRules=${s.safety.ipRules} resolvers="${s.safety.resolvers}"`);
  console.log(`providers    : ${s.clash.providers.map((p) => `${p.name}=${p.nodes}`).join(' ')}`);
  process.exit(0);
}
if (cmd === 'on' || cmd === 'off') {
  const r = await req('/clashConfiguePage/api/power', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ on: cmd === 'on' }) });
  const j = await r.json();
  console.log(`HTTP ${r.status} ${j.message || JSON.stringify(j)}`);
  process.exit(r.ok ? 0 : 1);
}
if (cmd === 'subs') {
  const r = await req('/clashConfiguePage/api/subs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  const j = await r.json();
  console.log(`HTTP ${r.status} ${j.message || JSON.stringify(j)}`);
  process.exit(r.ok ? 0 : 1);
}
if (cmd === 'logs') {
  const r = await req('/clashConfiguePage/api/logs');
  console.log((await r.text()).slice(-3000));
  process.exit(0);
}
console.error('usage: status | on | off | subs | logs | login');
process.exit(2);
