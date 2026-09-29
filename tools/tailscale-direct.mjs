#!/usr/bin/env node
// ============================================================================
// tailscale-direct.mjs — keep Tailscale's OWN traffic off a Clash TUN,
//                        without breaking "this host is also an exit node"
//
// WHY (measured 2026-09-29, see docs/windows-tun.md):
//   A permanently-on Clash TUN owns the default route. Tailscale's public UDP
//   (STUN / DERP / WireGuard data) then has no bypass rule, so it is proxied too.
//   Tailscale ends up advertising the *proxy node's* NAT mapping as its own
//   candidate endpoint -> peers can never punch through -> full DERP relay.
//
// THE TRAP: the obvious fix `PROCESS-NAME,tailscaled.exe,DIRECT` is WRONG when
//   the same host is also a tailnet exit node. Forwarded traffic and tailscaled's
//   own traffic look identical to Clash (same process). And matching on source IP
//   does not work either: a Clash TUN normalises the source to its own gateway
//   address (198.18.0.1) -- measured on 38/38 live connections.
//
// THE FIX: match on DESTINATION only. Exit-node traffic goes to arbitrary public
//   addresses, so it can never match these rules and keeps following MATCH ->
//   proxy. The two requirements cannot conflict by construction.
//
// USAGE
//   node tools/tailscale-direct.mjs verify [peer]
//   node tools/tailscale-direct.mjs install [--apply]
//
//   `install` writes the rules into Clash Verge's GLOBAL SCRIPT
//   (profiles/Script.js), NOT into profiles/Merge.yaml -- see the note below.
//
// NOTE (second trap): Clash Verge's global Merge is a plain deep-merge template.
//   `prepend-rules` written there is copied into the output config as an unknown
//   top-level key and silently ignored by the core (`rules:` stays untouched).
//   The global script's `main(config)` is the hook that can really change config.
// ============================================================================
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const RULES = [
  "IP-CIDR,100.64.0.0/10,DIRECT",        // tailnet range
  "DOMAIN-SUFFIX,tailscale.com,DIRECT",  // control plane + DERP (443)
  "DOMAIN-SUFFIX,tailscale.io,DIRECT",
  // MagicDNS needs no rule of its own: it resolves to the 100.64.0.0/10 range above.
  "DST-PORT,3478,DIRECT",                // STUN (decides the advertised endpoint)
  "DST-PORT,41641,DIRECT",               // WireGuard direct data path
];
const MARK = "[tailscale-direct]";

const SCRIPT = `// ${MARK} Keep Tailscale's own traffic off the Clash TUN.
//   Match on DESTINATION only -- never on PROCESS-NAME or source IP:
//     * if this host is also an exit node, forwarded traffic and tailscaled's own
//       traffic are indistinguishable to Clash (same process);
//     * a Clash TUN rewrites the source IP to its gateway address.
//   Exit-node traffic targets arbitrary public addresses, so it cannot match any
//   rule below and keeps following MATCH -> proxy. No conflict by construction.
//   Written by tools/tailscale-direct.mjs
function main(config, profileName) {
  try {
    var extra = ${JSON.stringify(RULES, null, 6).replace(/\n/g, "\n    ")};
    var isArr = config && Object.prototype.toString.call(config.rules) === "[object Array]";
    var base = isArr ? config.rules : [];
    config.rules = extra.concat(base);
  } catch (e) {
    // fail-safe: never break the user's network over a cosmetic rule injection
  }
  return config;
}
`;

const ARGV = process.argv.slice(2);
const CMD = ARGV[0] || "verify";
const APPLY = ARGV.includes("--apply");
const PEER = ARGV.find((a) => !a.startsWith("-") && a !== CMD);

function clashDir() {
  const base = process.env.APPDATA || process.env.XDG_CONFIG_HOME;
  const cands = [
    join(base || "", "io.github.clash-verge-rev.clash-verge-rev"),
    join(base || "", "clash-verge"),
    join(process.env.HOME || "", ".config", "clash-verge"),
  ];
  for (const d of cands) if (d && existsSync(join(d, "clash-verge.yaml"))) return d;
  throw new Error("Clash Verge config directory not found (looked in: " + cands.join(", ") + ")");
}
function controller() {
  const d = clashDir();
  const cfg = readFileSync(join(d, "clash-verge.yaml"), "utf8");
  const ctrl = (cfg.match(/^external-controller:\s*(\S+)/m) || [])[1];
  const secret = (cfg.match(/^secret:\s*(\S+)/m) || [])[1];
  if (!ctrl) throw new Error("external-controller not found in clash-verge.yaml");
  return { dir: d, ctrl: ctrl.startsWith("http") ? ctrl : "http://" + ctrl, secret };
}
async function api(base, secret, path) {
  const r = await fetch(base + path, { headers: secret ? { Authorization: "Bearer " + secret } : {} });
  return r.json();
}

if (CMD === "install") {
  const d = clashDir();
  const file = join(d, "profiles", "Script.js");
  if (!existsSync(file)) { console.error("not found: " + file); process.exit(1); }
  const cur = readFileSync(file, "utf8");
  if (cur.includes(MARK)) { console.log("[i] already installed -- nothing to do"); process.exit(0); }
  // simulate against the real generated config first; refuse to write if it misbehaves
  const cfgPath = join(d, "clash-verge.yaml");
  const L = readFileSync(cfgPath, "utf8").split(/\r?\n/);
  const ri = L.findIndex((l) => /^rules:\s*$/.test(l));
  const real = [];
  for (let i = ri + 1; ri >= 0 && i < L.length; i++) {
    const m = /^- (.*)$/.exec(L[i]);
    if (!m) { if (/^[a-zA-Z-]+:/.test(L[i])) break; continue; }
    real.push(m[1].trim());
  }
  const factory = new Function(`${SCRIPT}\nreturn main;`);
  const out = factory()({ rules: real.slice() }, "simulate");
  const injected = out.rules.length - real.length;
  const kept = real.every((r, i) => out.rules[i + injected] === r);
  console.log(`[i] simulation: +${injected} rules, ${real.length} originals preserved = ${kept}`);
  if (injected !== RULES.length || !kept) { console.error("[NG] simulation failed -- refusing to write"); process.exit(1); }
  if (!APPLY) { console.log("[i] dry run -- pass --apply to write " + file); process.exit(0); }
  copyFileSync(file, `${file}.bak-${new Date().toISOString().replace(/[:.]/g, "-")}`);
  writeFileSync(file, SCRIPT, "utf8");
  console.log("[OK] wrote " + file);
  console.log("[i] now RE-APPLY in the Clash Verge GUI (click the profile card, or fully quit incl. tray and reopen).");
  process.exit(0);
}

if (CMD === "verify") {
  const { ctrl, secret } = controller();
  let bad = 0;
  const say = (ok, name, detail) => { if (!ok) bad++; console.log(`  ${ok ? "OK  " : "NG  "} ${name}${detail ? "  -- " + detail : ""}`); };

  console.log("Clash core rules");
  const j = await api(ctrl, secret, "/rules");
  // The API splits a rule into {type, payload}; a config rule is "TYPE,payload,DIRECT".
  // Compare on normalised type + payload (never the raw string) -- the core
  // reports e.g. type "IPCIDR" / payload "100.64.0.0/10" for "IP-CIDR,100.64.0.0/10,DIRECT".
  const norm = (s) => String(s).toUpperCase().replace(/[^A-Z0-9]/g, "");
  const live = new Set((j.rules || []).map((r) => norm(r.type) + "|" + String(r.payload)));
  say((j.rules || []).length > 0, `core reachable at ${ctrl}`, `${(j.rules || []).length} rules`);
  for (const r of RULES) {
    const parts = r.split(",");
    const key = norm(parts[0]) + "|" + parts.slice(1, -1).join(",");
    say(live.has(key), `rule present: ${r}`);
  }

  console.log("\nTailscale endpoint advertisement");
  const { execFileSync } = await import("node:child_process");
  const ts = process.platform === "win32" ? "C:\\Program Files\\Tailscale\\tailscale.exe" : "tailscale";
  let nc = "";
  try { nc = execFileSync(ts, ["netcheck"], { encoding: "utf8" }); } catch (e) { console.log("  [i] netcheck unavailable: " + e.message); }
  const mIp = /IPv4:\s*yes,\s*([0-9.]+)/.exec(nc);
  const mDerp = /Nearest DERP:\s*(.+)/.exec(nc);
  if (mIp) console.log(`  [i] STUN mapping = ${mIp[1]}   nearest DERP = ${mDerp ? mDerp[1].trim() : "?"}`);
  if (mIp) console.log("  [i] compare that address with your carrier's real public IP -- they must match.");

  if (PEER) {
    console.log(`\nPath to peer ${PEER}`);
    let st = "";
    try { st = execFileSync(ts, ["status"], { encoding: "utf8" }); } catch { /* ignore */ }
    const line = st.split(/\r?\n/).find((l) => l.includes(PEER)) || "";
    if (line) console.log("  [i] " + line.trim());
    say(!!line && !/relay/i.test(line), "not relayed via DERP");
    let pg = "";
    try { pg = execFileSync(ts, ["ping", "--c", "4", PEER], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }); } catch (e) { pg = String(e.stdout || ""); }
    const pongs = pg.split(/\r?\n/).filter((l) => l.includes("pong"));
    console.log("  [i] " + (pongs[pongs.length - 1] || "(no reply)"));
    say(pongs.length > 0 && !pongs.some((p) => /DERP/i.test(p)), "direct pong (via ip:port, not DERP)");
  }

  console.log(bad === 0 ? "\nAll checks passed." : `\n${bad} check(s) failed.`);
  process.exit(bad === 0 ? 0 : 1);
}

console.error("usage: tailscale-direct.mjs <install [--apply] | verify [peer]>");
process.exit(2);
