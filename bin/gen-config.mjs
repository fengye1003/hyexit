// gen-config.mjs - generate /opt/hyexit/config/config.yaml
// Layered routing: self-protection -> ACL4SSR local/ads -> merged airport rules -> dynamic CN sets -> MATCH
// Run on the server:  node /opt/hyexit/bin/gen-config.mjs [--dry]
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const HY = '/opt/hyexit';
const CFG = path.join(HY, 'config');
const DRY = process.argv.includes('--dry');
const TS = new Date().toISOString().replace(/[:.]/g, '-');

// ---------- subs.env ----------
const envText = fs.readFileSync(path.join(CFG, 'subs.env'), 'utf8');
const SUBS = {};
for (const m of envText.matchAll(/^([a-zA-Z0-9_]+)="?([^"\n]+)"?$/gm)) SUBS[m[1]] = m[2];
const SOURCES = [
  { key: 'provider1', label: 'provider1', prio: 1 },
  { key: 'provider3', label: 'provider3', prio: 2 },
  { key: 'provider2', label: 'provider2', prio: 3 },
].filter((s) => SUBS[s.key]);
if (!SOURCES.length) { console.error('FATAL: no subscriptions in subs.env'); process.exit(2); }
console.log('subscriptions:', SOURCES.map((s) => s.label).join(', '));

// Domains that must never be proxied (your own sites / panel / upload point ...).
// Override with HYEXIT_OWN_DOMAINS="a.example.com,b.example.com" (comma separated), or keep the
// deployment-specific values in config/gen.env (NOT committed, see conf/gen.env.example):
//     HYEXIT_OWN_DOMAINS="a.example.com,b.example.com"
const genEnvPath = path.join(CFG, 'gen.env');
if (fs.existsSync(genEnvPath)) {
  let n = 0;
  for (const line of fs.readFileSync(genEnvPath, 'utf8').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = /^([A-Za-z0-9_]+)=(.*)$/.exec(t);
    if (!m) continue;
    if (process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].replace(/^["']/, '').replace(/["']$/, '');
      n++;
    }
  }
  console.log(`gen.env loaded (${n} keys)`);
}
const OWN_DOMAINS = (process.env.HYEXIT_OWN_DOMAINS || 'example.com').split(',').map((s) => s.trim()).filter(Boolean);
// Domains that must be proxied even when a merged upstream rule says DIRECT (empty by default).
const FORCE_PROXY_DOMAINS = (process.env.HYEXIT_FORCE_PROXY_DOMAINS || '').split(',').map((s) => s.trim()).filter(Boolean);

// ---------- helpers ----------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function get(url, ua = 'clash-verge/v2.3.0') {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 40000);
  try {
    const r = await fetch(url, { headers: { 'User-Agent': ua, Accept: '*/*' }, signal: ctl.signal, redirect: 'follow' });
    const body = await r.text();
    return { status: r.status, body };
  } finally { clearTimeout(t); }
}

async function fetchWithRetry(url, { tries = 4, minBytes = 3000 } = {}) {
  let last = '';
  for (let i = 0; i < tries; i++) {
    try {
      const r = await get(url);
      if (r.status === 200 && r.body.length >= minBytes && !/^error code/.test(r.body.slice(0, 20))) return r.body;
      last = `status=${r.status} len=${r.body.length} head=${r.body.slice(0, 40).replace(/\s+/g, ' ')}`;
    } catch (e) { last = e.message; }
    console.log(`   retry ${i + 1}/${tries}: ${last}`);
    await sleep(15000 + i * 20000); // Cloudflare 1015 rate-limit backoff
  }
  throw new Error(`fetch failed: ${url.slice(0, 40)}... last=${last}`);
}

function block(text, key) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp('^' + key + ':').test(l));
  if (start < 0) return null;
  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^[A-Za-z0-9_-]+:/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join('\n');
}

// ---------- rule merge ----------
// Upstream templates usually route through their OWN proxy-group names (e.g. "🚀 节点选择" or a
// provider-specific group). Every rule that targets a group we do not recognise is dropped, so a
// missing alias silently costs you hundreds of rules. Add the exact group names your subscriptions
// use via config/gen.env:  HYEXIT_PROXY_ALIASES="name a,name b"
const PROXY_TARGETS = new Set(['PROXY', '机场', '代理', '自动选择', '故障转移', '♻️ 自动选择', '🚀 节点选择', '选择节点',
  ...(process.env.HYEXIT_PROXY_ALIASES || '').split(',').map((s) => s.trim()).filter(Boolean)]);
console.log(`proxy-group aliases recognised: ${PROXY_TARGETS.size}`);
const DROP_TYPES = new Set(['RULE-SET', 'AND', 'OR', 'NOT', 'SUB-RULE', 'PROCESS-NAME', 'PROCESS-PATH', 'PROCESS-PATH-REGEX', 'SRC-PROCESS-NAME', 'IN-TYPE', 'IN-USER', 'IN-NAME', 'NETWORK', 'DST-PORT', 'SRC-PORT', 'UID', 'MATCH']);
const DROP_VALUE = new Set(['api.ip.sb', 'ipapi.co', 'api.ipapi.is', 'ipwho.is']); // airport IP-echo REJECTs: keep exit-IP checks working

const unknownTargets = new Map(); // target name -> count, so a missing alias is visible instead of silent
function normalize(rule) {
  // Airports emit rules single-quoted:  - 'IP-CIDR,1.1.1.1/32,provider1,no-resolve'
  // Strip the wrapping quotes BEFORE splitting, otherwise the leading quote lands on the
  // type field and the emitted line starts an unclosed YAML scalar (yaml: did not find
  // expected '-' indicator).
  const s = String(rule).trim().replace(/^['"]+/, '').replace(/['"]+$/, '').trim();
  if (s.includes("'") || s.includes('"') || s.includes('#')) return null; // defensive
  const parts = s.split(',').map((x) => x.trim());
  if (parts.length < 3) return null;
  let [type, value, target] = parts;
  type = (type || '').toUpperCase();
  if (!type || !value || DROP_TYPES.has(type)) return null;
  let t = (target || '').replace(/^['"]|['"]$/g, '');
  if (PROXY_TARGETS.has(t)) t = 'PROXY';
  else if (t === 'REJECT' || t === 'REJECT-DROP') t = 'ADS';
  if (!/^(PROXY|DIRECT|ADS)$/.test(t)) {
    unknownTargets.set(t, (unknownTargets.get(t) || 0) + 1);
    return null;
  }
  if (DROP_VALUE.has(value)) return null;
  if (type === 'DOMAIN-KEYWORD' && /^-?cn$|porn|adult/i.test(value)) return null; // keep simple, avoid broad keyword traps
  return { type, value, target: t, extra: parts.slice(3).map((s) => s.trim()).filter(Boolean), raw: rule };
}

const merged = [];
const seen = new Set();
const stats = [];
for (const src of SOURCES.sort((a, b) => a.prio - b.prio)) {
  const url = SUBS[src.key];
  const cacheFile = path.join(HY, 'state', `rules-${src.key}.txt`);
  console.log(`[${src.label}] fetching...`);
  let rules = null;
  let from = 'live';
  try {
    const body = await fetchWithRetry(url);
    const b = block(body, 'rules');
    if (b === null) throw new Error('no rules block in response');
    rules = b.split(/\r?\n/).map((l) => l.replace(/^\s*-\s*/, '').trim()).filter((l) => l && !l.startsWith('#'));
    fs.writeFileSync(cacheFile, rules.join('\n'), 'utf8');
  } catch (e) {
    if (fs.existsSync(cacheFile)) {
      rules = fs.readFileSync(cacheFile, 'utf8').split(/\r?\n/).filter(Boolean);
      from = 'cache';
      console.log(`   WARN live fetch failed: ${e.message}`);
      console.log(`   -> falling back to cached rules (${rules.length} lines from ${cacheFile})`);
    } else {
      console.log(`   ERROR source unavailable and no cache: ${e.message} -> skipped`);
      stats.push({ label: src.label, total: 0, added: 0, dup: 0, dropped: 0, from: 'failed' });
      continue;
    }
  }
  let added = 0, dup = 0, dropped = 0;
  for (const r of rules) {
    const n = normalize(r);
    if (!n) { dropped++; continue; }
    const key = n.type + ',' + n.value;
    if (seen.has(key)) { dup++; continue; }
    seen.add(key);
    merged.push(n);
    added++;
  }
  stats.push({ label: src.label, total: rules.length, added, dup, dropped, from });
  console.log(`   rules=${rules.length} added=${added} dup=${dup} dropped=${dropped} (${from})`);
  if (from === 'live') await sleep(3000); // be nice to the airport API
}
if (merged.length === 0) { console.error('FATAL: no rules could be collected from any source'); process.exit(5); }


const cnt = (t) => merged.filter((r) => r.target === t).length;
console.log(`merged unique rules: ${merged.length} (PROXY ${cnt('PROXY')} / DIRECT ${cnt('DIRECT')} / ADS ${cnt('ADS')})`);
if (unknownTargets.size) {
  const top = [...unknownTargets.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  console.log(`WARN dropped rules whose target group is not mapped (${[...unknownTargets.values()].reduce((a, b) => a + b, 0)} rules):`);
  for (const [t, n] of top) console.log(`   ${n.toString().padStart(4)} x "${t}"   <-- add to HYEXIT_PROXY_ALIASES in gen.env if this is a proxy group`);
}

// ---------- rule provider availability ----------
const PROVIDERS = [
  { name: 'local-area-network', behavior: 'classical', format: 'yaml', url: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/LocalAreaNetwork.list', target: 'DIRECT' },
  { name: 'ban-ad', behavior: 'classical', format: 'yaml', url: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/BanAD.list', target: 'ADS' },
  { name: 'ban-program-ad', behavior: 'classical', format: 'yaml', url: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/BanProgramAD.list', target: 'ADS' },
  { name: 'category-ads-all', behavior: 'domain', format: 'mrs', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs', target: 'ADS' },
  { name: 'geosite-cn', behavior: 'domain', format: 'mrs', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs', target: 'DIRECT' },
  { name: 'geoip-cn', behavior: 'ipcidr', format: 'mrs', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs', target: 'DIRECT' },
];
const okProviders = [];
for (const p of PROVIDERS) {
  try {
    const r = await get(p.url, 'clash-verge/v2.3.0');
    const ok = r.status === 200 && r.body.length > 200;
    console.log(`   provider ${p.name}: ${r.status} ${r.body.length}B ${ok ? 'OK' : 'SKIP'}`);
    if (ok) okProviders.push(p);
  } catch (e) { console.log(`   provider ${p.name}: ERR ${e.message} SKIP`); }
  await sleep(800);
}

// ---------- node name filters ----------
const JUNK = '(?i)(剩余|到期|官网|订阅|流量|失联|重置|续费|购买|群|频道|Traffic|Expire|Official|Website|防失联|节点异常|通知)';
// raw (unanchored) region patterns: mihomo matches filter/exclude-filter with unanchored regexp
const REGION_RAW = {
  hk: '香港|Hong ?Kong|HKG',
  jp: '日本|Japan|东京|大阪|JPN',
  sg: '新加坡|狮城|Singapore|SGP',
  us: '美国|United States|洛杉矶|圣何塞|西雅图|硅谷|Los Angeles|San Jos|Seattle|USA',
  tw: '台湾|臺灣|Taiwan|台北',
};
const FILTERS = Object.fromEntries(Object.entries(REGION_RAW).map(([k, v]) => [k, `(?i)(${v})`]));
const EXCLUDE_OTHERS = '(?i)(' + Object.values(REGION_RAW).join('|') + ')';

// ---------- secret ----------
const secretFile = path.join(HY, 'state', 'controller.secret');
let secret;
if (fs.existsSync(secretFile)) secret = fs.readFileSync(secretFile, 'utf8').trim();
else { secret = crypto.randomBytes(24).toString('base64url'); if (!DRY) fs.writeFileSync(secretFile, secret, { mode: 0o600 }); }

// ---------- ts ip ----------
let TSIP = '0.0.0.0';
try { TSIP = execFileSync('bash', ['-c', "ip -4 addr show tailscale0 | sed -n 's/.*inet \\([0-9.]*\\).*/\\1/p'"], { encoding: 'utf8' }).trim() || '0.0.0.0'; } catch {}
console.log('tailscale ip:', TSIP);

// ---------- YAML ----------
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
const L = [];
const P = (s = '') => L.push(s);

P('# ============================================================');
P('# GENERATED by /opt/hyexit/bin/gen-config.mjs - DO NOT EDIT BY HAND');
P(`# generated: ${TS}`);
P('# edits will be lost on next regeneration');
P('# ============================================================');
P('');
P('mixed-port: 17897');
P('socks-port: 17898');
// allow-lan + bind-address '*' are REQUIRED (measured): with bind-address pinned to 127.0.0.1
// mihomo only creates loopback listeners, the forwarded packets have no matching socket and the
// capture silently falls through to a DIRECT connection. The exposure is closed on the firewall
// side instead: nft drops 17897/17898 arriving from the tailnet (see deploy/02), and the ports
// are only reachable from the host.
P('allow-lan: true');
P("bind-address: '*'");
P('mode: rule');
P('log-level: warning');
P('ipv6: true');
P('unified-delay: true');
P('tcp-concurrent: true');
P('find-process-mode: "off"');
P('keep-alive-interval: 30');
P('');
P(`external-controller: 127.0.0.1:19120`);
P(`secret: ${q(secret)}`);
// allow any origin for the controller: the SPA is served from the same HTTPS origin as the
// gateway, but zashboard probes /version with an Authorization header (preflight) and its
// diagnosis falls back to a no-cors fetch, so a restrictive origin list makes the UI report
// "浏览器按同源策略拦下了响应（CORS）". The controller itself is only reachable on 127.0.0.1.
P('external-controller-cors:');
P('  allow-origins:');
P("    - '*'");
P('  allow-private-network: false');
P('external-ui: ""');
P('external-ui-name: ""');
P('');
P('profile:');
P('  store-selected: true');
P('  store-fake-ip: true');
P('');
P('geodata-mode: true');
P('');
// CAPTURE PATH = TUN (gvisor). Exit-node traffic is steered into the TUN by policy routing
// (route-up.sh: ip rule iif tailscale0 -> table 1000 -> default dev hyexit0).
//
// Why gvisor and not the kernel stacks: with auto-route: false -- which the host-isolation
// design requires, since we must never touch the host's own routing table -- the system/mixed
// TUN stacks do not capture anything, they simply break the path. gvisor is userspace TCP, so
// bulk throughput over a ~100 ms WireGuard RTT is window/RTT bound (expect ~0.1-0.2 MB/s for a
// single long download even though the VPS itself does 7-11 MB/s); latency-sensitive browsing
// is fine. TPROXY and REDIRECT were both attempted to get kernel TCP back and both failed to
// deliver connections to mihomo on this box (nft counters matched, mihomo logged nothing), so
// the TUN path is what ships. Put the bulk traffic on a local client-side proxy instead.
//
// MTU 1280 = tailscale0's MTU; anything larger fragments once the packets re-enter the tunnel.
P('tun:');
P('  enable: true');
P('  device: hyexit0');
P('  stack: gvisor');
P('  gso: true');
P('  gso-max-size: 65536');
P('  auto-route: false');
P('  auto-detect-interface: true');
P('  strict-route: false');
P('  mtu: 1280');
P('  udp-timeout: 300');
P('  dns-hijack:');
P("    - 'any:53'");
P('');
P('sniffer:');
P('  enable: false');
P('');
P('dns:');
P('  enable: true');
P('  listen: 0.0.0.0:5353');
P('  ipv6: true');
P('  enhanced-mode: fake-ip');
P('  fake-ip-range: 198.18.0.1/16');
P('  fake-ip-range6: fdfe:dcba:9876::1/64');
P('  use-hosts: true');
P('  use-system-hosts: false');
P('  default-nameserver:');
P('    - 223.5.5.5');
P('    - 119.29.29.29');
P('  nameserver:');
P("    - 'https://dns.alidns.com/dns-query'");
P("    - 'https://doh.pub/dns-query'");
P("    - '223.5.5.5'");
P('  proxy-server-nameserver:');
P('    - 223.5.5.5');
P('    - 119.29.29.29');
P('  fallback:');
P("    - 'https://1.1.1.1/dns-query'");
P("    - 'https://dns.google/dns-query'");
P('  fallback-filter:');
P('    geoip: true');
P('    geoip-code: CN');
P('  fake-ip-filter:');
for (const d of ['*.lan', '*.local', '*.localdomain', '*.localhost', '*.home.arpa', '*.invalid', '*.test',
  'time.*.com', 'time.*.apple.com', 'ntp.*.com', '*.ntp.org.cn', '+.pool.ntp.org',
  'localhost.ptlogin2.qq.com', '*.msftconnecttest.com', '*.msftncsi.com',
  '*.stun.*', 'stun.*.*', '*.turn.*']) P(`    - ${q(d)}`);
P('');
P('proxy-providers:');
const provKeys = { provider1: 'provider1', provider2: 'provider2', provider3: 'provider3' };
for (const s of SOURCES) {
  P(`  ${provKeys[s.key]}:`);
  P('    type: http');
  P('    url: ' + q(SUBS[s.key]));
  P(`    path: ./providers/${s.key}.yaml`);
  P('    interval: 1440');
  P('    exclude-filter: ' + q(JUNK));
  P('    health-check:');
  P('      enable: true');
  P('      url: https://www.gstatic.com/generate_204');
  P('      interval: 300');
  P('      timeout: 3000');
  P('      lazy: true');
  P('      expected-status: 204');
}
P('');
P('proxy-groups:');
P('  - name: ' + q('PROXY'));
P('    type: select');
P('    proxies:');
for (const g of ['♻️ 自动选择', '🇭🇰 香港', '🇯🇵 日本', '🇸🇬 新加坡', '🇺🇸 美国', '🇨🇳 台湾', '🌍 其他地区', '🔧 手动选择', 'DIRECT']) P('      - ' + q(g));
// A plain select group over all provider nodes: url-test groups optimise LATENCY, and a
// low-latency line is often a bandwidth-capped one, so a manual picker is essential when
// the user needs throughput (large downloads).
P('  - name: ' + q('🔧 手动选择'));
P('    type: select');
P('    use:');
for (const s of SOURCES) P(`      - ${provKeys[s.key]}`);
P('  - name: ' + q('♻️ 自动选择'));
P('    type: url-test');
P('    use:');
for (const s of SOURCES) P(`      - ${provKeys[s.key]}`);
P('    url: https://www.gstatic.com/generate_204');
P('    interval: 180');
P('    tolerance: 50');
P('    lazy: true');
const regions = [['🇭🇰 香港', FILTERS.hk], ['🇯🇵 日本', FILTERS.jp], ['🇸🇬 新加坡', FILTERS.sg], ['🇺🇸 美国', FILTERS.us], ['🇨🇳 台湾', FILTERS.tw]];
for (const [name, filter] of regions) {
  P('  - name: ' + q(name));
  P('    type: url-test');
  P('    use:');
  for (const s of SOURCES) P(`      - ${provKeys[s.key]}`);
  P('    filter: ' + q(filter));
  P('    url: https://www.gstatic.com/generate_204');
  P('    interval: 180');
  P('    tolerance: 50');
  P('    lazy: true');
}
P('  - name: ' + q('🌍 其他地区'));
P('    type: url-test');
P('    use:');
for (const s of SOURCES) P(`      - ${provKeys[s.key]}`);
P('    exclude-filter: ' + q(EXCLUDE_OTHERS));
P('    url: https://www.gstatic.com/generate_204');
P('    interval: 180');
P('    tolerance: 50');
P('    lazy: true');
P('  - name: ' + q('🛑 广告拦截'));
P('    type: select');
P('    proxies:');
P('      - REJECT');
P('      - DIRECT');
P('');
P('rule-providers:');
for (const p of okProviders) {
  P(`  ${p.name}:`);
  P('    type: http');
  P('    behavior: ' + p.behavior);
  P('    format: ' + p.format);
  P('    url: ' + q(p.url));
  P(`    path: ./ruleset/${p.name}.${p.format === 'mrs' ? 'mrs' : 'yaml'}`);
  P('    interval: 86400');
}
P('');
P('rules:');
// layer 0: self protection
P('  # --- layer 0: self protection (tailnet / private / own domains never proxied) ---');
P('  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve');
P('  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve');
P('  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve');
P('  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve');
P('  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve');
P('  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve');
P('  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve');
P('  - IP-CIDR,255.255.255.255/32,DIRECT,no-resolve');
P('  - IP-CIDR6,::1/128,DIRECT,no-resolve');
P('  - IP-CIDR6,fc00::/7,DIRECT,no-resolve');
P('  - IP-CIDR6,fe80::/10,DIRECT,no-resolve');
P('  - IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve');
for (const d of [...OWN_DOMAINS, 'local', 'lan', 'localhost']) P(`  - DOMAIN-SUFFIX,${d},DIRECT`);
// layer 1: providers for local/ads
P('  # --- layer 1: ACL4SSR / MetaCubeX maintained sets ---');
const ADS_GROUP = '🛑 广告拦截';
for (const p of okProviders) {
  if (p.name === 'geosite-cn' || p.name === 'geoip-cn') continue;
  const t = p.target === 'ADS' ? ADS_GROUP : p.target;
  P(`  - RULE-SET,${p.name},${t}`);
}
// layer 2: merged airport rules
P('  # --- layer 2: merged airport rules (provider1 order first, then provider3, then provider2) ---');
for (const r of merged) {
  const t = r.target === 'ADS' ? '🛑 广告拦截' : r.target;
  P(`  - ${r.type},${r.value},${t}${r.extra.length ? ',' + r.extra.join(',') : ''}`);
}
// layer 3: dynamic CN
P('  # --- layer 3: dynamic CN fallback ---');
for (const p of okProviders) {
  if (p.name === 'geosite-cn' || p.name === 'geoip-cn') P(`  - RULE-SET,${p.name},DIRECT`);
}
P('  - GEOIP,CN,DIRECT,no-resolve');
// explicit "always proxy" overrides, right before MATCH so nothing upstream can veto them
for (const d of FORCE_PROXY_DOMAINS) P(`  - DOMAIN-SUFFIX,${d},PROXY`);
P('  - MATCH,PROXY');

const yaml = L.join('\n') + '\n';

// guard: inside the rules: section a rule line must never contain a quote character
// (an unclosed scalar is what broke the first generation attempt)
const allLines = yaml.split('\n');
const rulesStart = allLines.findIndex((l) => l === 'rules:');
const badLines = allLines.map((l, i) => [l, i + 1])
  .filter(([l, i]) => i > rulesStart && /^\s*- /.test(l) && /['"]/.test(l));
if (badLines.length) {
  console.error('FATAL: ' + badLines.length + ' rule lines contain quote chars, refusing to write');
  badLines.slice(0, 8).forEach(([l, i]) => console.error('  L' + i + ': ' + l));
  process.exit(4);
}
const outPath = path.join(CFG, 'config.yaml');
if (DRY) {
  fs.writeFileSync(path.join(CFG, `config.dry-${TS}.yaml`), yaml, 'utf8');
  console.log('DRY RUN -> ' + path.join(CFG, `config.dry-${TS}.yaml`));
} else {
  if (fs.existsSync(outPath)) fs.copyFileSync(outPath, path.join(CFG, `config.bak-${TS}.yaml`));
  fs.writeFileSync(outPath, yaml, { mode: 0o600 });
  console.log('WROTE ' + outPath + ` (${Buffer.byteLength(yaml)} bytes, ${L.length} lines)`);
}

// validate
try {
  const out = execFileSync(path.join(HY, 'bin/mihomo'), ['-t', '-d', CFG], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  console.log('VALIDATE OK: ' + out.trim().split('\n').slice(-2).join(' | '));
} catch (e) {
  console.error('VALIDATE FAILED:\n' + (e.stdout || '') + (e.stderr || ''));
  console.error('config kept at ' + outPath + ' (fix before starting)');
  process.exit(3);
}
console.log('STATS ' + JSON.stringify(stats));
