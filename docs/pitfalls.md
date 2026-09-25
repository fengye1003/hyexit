# Pitfalls

Every item here was hit for real, with the symptom as observed. Numbers like "0.1 MB/s" come from
measurements on a 4 vCPU Hong Kong VPS with ~100 ms RTT to the proxy nodes.

## 1. `bind-address: 127.0.0.1` silently disables the whole capture

**Symptom:** everything looks healthy — mihomo runs, the TUN device exists, the policy rule matches
(counters climb), the client has connectivity — but the exit IP is the *VPS's own* IP, i.e. nothing is
proxied. No error anywhere.

**Cause:** with `bind-address: 127.0.0.1` mihomo only creates loopback listeners. The forwarded packets
have no matching socket, so the connection falls through to a plain direct route.

**Fix:** `allow-lan: true` + `bind-address: '*'`, and then close the exposed ports for the tailnet with
an nft guard (`route-up.sh`). This is not optional, and it is easy to lose: a later "hardening" edit
that pins the bind address reintroduces the silent direct path.

## 2. The `to 100.64.0.0/10 lookup main` rule kills client DNS while TCP keeps working

**Symptom:** a client using the exit node can load pages by IP, TCP-based apps are fine, but DNS dies —
or the client appears entirely offline on some platforms (e.g. Crostini reported
`running without policy routing`).

**Cause:** a rule `ip rule add to 100.64.0.0/10 lookup main priority 5190` (added to "keep tailnet
traffic on the main table") matched the *replies* to the tailnet and sent them out the internet
gateway, where they were dropped.

**Fix:** never add that rule. Tailnet routes must stay in Tailscale's own table 52. `route-up.sh`
actively deletes it if it finds it.

## 3. `iif hyexit0` instead of `iif tailscale0`

**Symptom:** no traffic is proxied, but tests pass anyway — because they used the mixed-port
(`curl -x http://127.0.0.1:17897`), which works regardless of the capture path. Hours of false positives.

**Cause:** exit-node traffic *arrives on* `tailscale0`; `hyexit0` is where it must *leave*.

**Fix:** `ip rule add iif tailscale0 lookup 1000`. Test the capture path by changing the exit IP from a
real client, not by curling the local mixed-port.

## 4. Kernel TUN stacks do not capture with `auto-route: false`

**Symptom:** with `stack: system` or `stack: mixed` the tunnel appears to work and hits impressive
speeds (14–18 MB/s) — which turn out to be *direct* traffic, because nothing is actually being captured.

**Cause:** the kernel-backed TUN stacks rely on `auto-route` to install routes; with `auto-route: false`
(required by the host-isolation design) they never see the traffic.

**Fix:** `stack: gvisor`. Accept the throughput cost (see §5).

## 5. gvisor userspace TCP is window/RTT bound — that is physics, not a bug

**Symptom:** through the exit node a single download runs at ~0.1–0.2 MB/s while the VPS itself does
7–11 MB/s and an `iperf3` through the tunnel does ~65 MB/s.

**Cause:** gvisor terminates TCP in userspace; throughput ≈ receive window / RTT, and the RTT here is
~100 ms. Latency-sensitive browsing is fine (YouTube 1080p included), bulk transfer is not.

**Attempted and rejected:** TPROXY (`xt_TPROXY`, fwmark + `ip route local default dev lo table 100`)
and REDIRECT (`SO_ORIGINAL_DST`) both matched packets in nft counters but never delivered a connection
to mihomo. Both were reverted.

**Workaround that ships:** leave the exit node as a plain fast Hong Kong egress (proxy OFF) and run
Clash locally on the machine that needs bulk throughput.

## 6. MTU mismatch fragments everything

**Symptom:** connections establish, small transfers work, large ones stall.

**Cause:** TUN at 1500 while `tailscale0` is 1280 — every full-size packet re-entering the tunnel
fragments.

**Fix:** `mtu: 1280` on the TUN.

## 7. mihomo pushes a fake-IP resolver onto the TUN and poisons the host

**Symptom:** the VPS itself (blog, panel, apt, certbot) loses DNS minutes after the proxy starts;
`/run/systemd/resolve/resolv.conf` contains `198.18.x` / `fdfe:dcba…`.

**Cause:** creating the TUN link hands systemd-resolved a per-link DNS server, which it adopts as a
global upstream.

**Fix:** `resolvectl revert <tun>` after the link appears (in `route-up.sh`), plus a watchdog assertion
that repairs it and alerts. Note this is **not** caused by `dns-hijack` — that setting is unrelated.

## 8. Hand-patched live configs drift from the generator

**Symptom:** the running `config.yaml` worked, but re-running the generator produced a config that
silently disabled the capture path (`tun.enable: false`, `bind-address: 127.0.0.1`).

**Cause:** during debugging the *live* file had been patched in place (and an older generator revision
was left on disk), so "regenerate to fix it" would have broken a working deployment.

**Fix:** keep the generator authoritative. Validate the generated file key-by-key against the running
one (`deploy/302`-style diff) before trusting a regeneration, and drive all site-specific variance
through `config/gen.env`.

## 9. Unknown proxy-group targets silently drop hundreds of rules

**Symptom:** after a config regeneration the proxy "worked" but was much weaker than before:
`merged unique rules: 198 (PROXY 0 / …)` instead of 529 (PROXY 331).

**Cause:** subscription templates route through their **own** group names. Any rule whose target is not
recognised (`PROXY`/`DIRECT`/`ADS`/your aliases) is dropped — silently, because dropping is also how
junk rules are filtered.

**Fix:** list your subscriptions' group names in `gen.env` (`HYEXIT_PROXY_ALIASES="…"`), and watch the
generator's `WARN dropped rules whose target group is not mapped` summary, which prints the top
offending names with counts.

## 10. Renaming the subscription keys silently yields "no subscriptions"

**Symptom:** `FATAL: no subscriptions in subs.env` although the file is present and non-empty.

**Cause:** `subs.env` keys and the generator's `SOURCES` key names must match exactly; renaming one side
(e.g. to sanitise a name) breaks the lookup with no hint about which side is wrong.

**Fix:** keep the neutral `provider1/provider2/provider3` keys on both sides. The generator prints the
loaded key list, so this is visible in one run.

## 11. Quoted upstream rules produce an unclosed YAML scalar

**Symptom:** `yaml: line 274: did not find expected '-' indicator` — a valid-looking config rejected by
mihomo.

**Cause:** subscriptions emit rules as `- 'DOMAIN-SUFFIX,x.com,PROXY'`. Splitting on commas first leaves
the leading quote on the type field, so the emitted line starts but never closes a YAML scalar.

**Fix:** strip the wrapping quotes *before* splitting, and refuse to write the file if any line inside
the `rules:` block still contains a quote character.

## 12. Removed config keys

`global-client-fingerprint` is rejected by recent mihomo builds
(`The global-client-fingerprint configuration is removed`). Check the build's own `strings`/changelog
instead of trusting a config copied from an older setup.

## 13. Rule targets must exist as proxy groups

**Symptom:** `rules[17] [RULE-SET,ban-ad,ADS] error: proxy [ADS] not found` — mihomo refuses to start.

**Cause:** a rule set mapped to a target like `ADS` that is not a declared group.

**Fix:** map such targets onto real groups (here: an ad-block `select` group). The generator does this
mapping centrally so it cannot be forgotten in one place.

## 14. The watchdog's panel check must run in both ON and OFF branches

**Symptom:** a stale "panel auth may have failed" alert never cleared while the proxy was off.

**Cause:** the panel probe lived inside the `mihomo is active` branch.

**Fix:** the panel gate is the most dangerous thing to lose silently, so probe it unconditionally
(`panel_check` is called from both branches).

## 15. Hardcoded deployment values break when you open-source the scripts

**Symptom:** after replacing real hostnames/ports with placeholders in shared scripts, the deployed
watchdog probed `https://127.0.0.1:10443` (placeholder) and reported the panel as dead.

**Fix:** every script reads the non-committed `/opt/hyexit/config/gen.env` for site-specific values
(`PANEL_HOST`, `PANEL_PORT`, `HYEXIT_OWN_DOMAINS`, `HYEXIT_PROXY_ALIASES`, `HYEXIT_SITES`) and falls back
to documented placeholders. `verify.sh` sources it with `set -a` so child processes (python) inherit it.

## 16. nftables state does not survive a reboot

**Symptom:** the tailnet guard silently disappeared; the mixed/socks ports were exposed to the whole
tailnet after a reboot.

**Fix:** install such rules from `route-up.sh` (which systemd runs on every start) instead of once by
hand, and let the watchdog repair them.

## 17. The panel/UI traps

* **Missing URL parameter:** zashboard needs `?hostname=&port=&protocol=https`. Without `protocol` it
  defaults to `http`, the browser blocks the mix and the UI reports "backend unreachable" while issuing
  zero API calls. The gateway redirects with all three parameters.
* **CORS preflight:** the UI probes `/version` with an `Authorization` header, which triggers an
  `OPTIONS` request. If the gateway answers 404 to `OPTIONS`, the UI declares a CORS failure. Answer
  `204` with `Access-Control-Allow-Origin` for the same origin.
* **Blocking power switch:** a `/api/power` handler that waits ~30 s for a state change makes browsers
  abort the request (nginx logs it as 499) and the UI look broken. Return immediately and poll.
* **Unapproved exit node:** `tailscale set --advertise-exit-node` is not enough; the node must be
  approved in the admin console. `tailscale status --json` → `Self.ExitNodeOption` must be `true`.

## 18. Operational traps on the server

* **No `node` in a non-login shell:** cron and pushed scripts do not inherit your PATH; resolve node
  explicitly (`command -v node || ls /opt/*/nodejs/v*/bin/node`).
* **Telegram chat id truncated to one character** makes every alert fail *silently* — check the length
  and `getMe` when installing the watchdog. All the proxy alerts had been quietly lost for days.
* **`base64` over ssh breaks above ~30 KB** (Windows command-line limit). Use `scp` + remote `sha256sum`
  verification instead.
* **Do not reuse one TOTP secret for several services.** This gateway's secret must be independent; if
  you do share one, a single leak compromises everything and rotation becomes a multi-service job.

## 19–24. The local/Windows half (see `docs/windows-tun.md`)

**19. A "free" port can still refuse to bind.** On a machine with Hyper-V/WSL the system reserves
ranges; a port inside one fails with `EACCES` on an explicit bind — it is reserved, not in use.
`netsh int ipv4 show excludedportrange protocol=tcp` reveals it; carve yours out with
`netsh int ipv4 add excludedportrange ... store=persistent`, and if winnat still holds the range,
stop → add → start winnat. The port then appears as `<port> <port> *` and survives reboots.

**20. "Origin unrestricted" and "send cookies" cannot both be done with `*`.** The spec forbids
`Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`, so the gateway
reflects the request's `Origin`. Cross-site pages are kept away from an existing session by the cookie's
`SameSite=Lax`. Also remember the two dashboard classics: the SPA needs `?protocol=&hostname=&port=`
(without `protocol` it silently targets port 9090 and makes **zero** API calls) and `OPTIONS` must be
answered **204**, never 404.

**21. Do not kill processes by command-line substring.** An installer that cleaned up its old instance
with `Where-Object { $_.CommandLine -like '*MyPanel*' }` matched — and killed — the agent harness's own
shell runner, because the runner's command line contains the script text being executed. Symptom:
a tool call failing with a bogus `Job runner exited with exit code …`, or an elevated installer dying
silently mid-script. Kill by **port owner** instead
(`Get-NetTCPConnection -LocalPort N -State Listen | Select OwningProcess`) or by a PID recorded in a file.

**22. PowerShell 5.1 writes a UTF-8 BOM; Node's `JSON.parse` throws on it.** The failure is silent:
the error goes to stderr, gets swallowed by a `catch`, and the service falls back to defaults — so the
config "was written" but is not in effect. Write with
`[System.IO.File]::WriteAllText($p, $json, (New-Object System.Text.UTF8Encoding($false)))`, strip
`[char]0xFEFF` when reading, and make every `catch` log.

**23. Config templates wipe runtime-generated secrets.** An installer that rewrites the config from a
default template deletes any field the template does not know about — including a TOTP secret and the
session-signing key. Whenever you add a config field, add it to the template *and* to the
"preserve existing value" list, or a single idempotent re-run silently disables 2FA. Related:
`node script.mjs $arg` puts the argument in `process.argv[2]` (`[1]` is the script path) — pass the
wrong index and you silently store garbage. **Always read secrets back and compare length + hash.**

**24. A permanent TUN hijacks your own ops links.** With Clash TUN on, SSH to your *own* server's public
IP follows the default route into the TUN, exits via a proxy node, and the server drops the connection
at key exchange (`kex_exchange_identification`) — often a shared proxy-node IP tripping sshd's per-source
limits, not a ban list. Diagnose with `Find-NetRoute -RemoteIPAddress <target>`; fix by marking your own
servers `DIRECT` or by reaching them over the tailnet.