# hyexit — a Tailscale exit node whose egress runs through its own Clash

A small, dependency-light toolkit for two related setups:

* **Server side (Linux):** turn a cheap overseas VPS into a **Tailscale exit node whose outbound traffic
  is proxied by a private Clash/mihomo instance — while the server's own traffic (blog, panel, backups,
  apt) is never proxied.**
* **Local side (Windows):** run a local Clash **TUN permanently** for fast native domestic routing, with
  a **TOTP-gated dashboard** on your own machine, plus a health/rescue tool for the TUN stack.

```
  phone / laptop ──Tailscale──▶ VPS (tailscale0)
                                   │  ip rule  iif tailscale0 -> table 1000
                                   ▼
                            mihomo TUN (hyexit0)  ──rules──▶ 🚀 proxy nodes  (foreign traffic)
                                   │                       └▶ DIRECT        (CN traffic, your domains)
                                   │
  VPS itself ──eth0────────────────┴──────────────────────▶ plain direct egress (NEVER proxied)
```

The whole point is the last line: selecting the VPS as an exit node on one device must not disturb the
services already running on that VPS. That is achieved with **policy routing on the ingress interface**,
not with a global TUN default route:

```bash
ip rule  add iif tailscale0 lookup 1000
ip route add default dev hyexit0 table 1000
```

Traffic the host generates itself has no ingress interface, so it never matches the rule and keeps using
`main`. Nothing about the host's own routing table is touched.

## What you get

| Piece | Purpose |
|---|---|
| `bin/gen-config.mjs` | Builds `config.yaml`: merges the rule sets of your existing subscriptions into one deterministic config, validates it with `mihomo -t`, keeps a backup, refuses to write a broken file. |
| `bin/route-up.sh` | Installs the policy route + client-DNS redirect + tailnet guard. Run automatically by systemd on start. |
| `bin/route-down.sh` | Removes them and leaves a clean-DNS fallback so an "off" exit node is still a usable exit. |
| `bin/watchdog.sh` | Cron every 2 min: keeps the capture path honest, self-heals, alerts on Telegram, and **fails safe to direct egress instead of black-holing clients**. |
| `bin/panel-server.mjs` | A tiny TOTP gateway in front of the mihomo API + a [zashboard](https://github.com/Zephyruso/zashboard) UI, on a hidden URL. Zero npm dependencies. |
| `deploy/*.sh` | Idempotent install steps (mihomo + geo data + UI, systemd units, routing, panel, watchdog). |
| `deploy/99-verify.sh` | One command that asserts the whole design (isolation, capture path, panel auth, fail-safe). |
| `dashboard/` | **Local/Windows side:** a TOTP-gated dashboard gateway for the machine's own Clash, installed as a boot task, with port reservation and a 22-assertion self-test. |
| `tools/clash-tun-rescue.ps1` | **Windows:** diagnose/repair a locally run Clash TUN (default-route race, hung core, leftovers), with an optional watchdog task. |
| `tools/panel-cli.mjs`, `tools/push-file.ps1` | Operate the server panel from the CLI; push files with a sha256 round-trip check. |

## Quick start (server side)


On a Debian/Ubuntu VPS that already runs Tailscale, as root:

```bash
# 1. layout + mihomo + geo databases + zashboard UI
bash deploy/01-install-kernel.sh

# 2. your subscriptions and deployment-specific values
install -d -m 700 /opt/hyexit/config
cat > /opt/hyexit/config/subs.env <<'EOF'
provider1="https://your-provider/subscribe?token=..."
provider2="..."
provider3="..."
EOF
cp conf/gen.env.example /opt/hyexit/config/gen.env
$EDITOR /opt/hyexit/config/gen.env          # own domains, panel host/port, group aliases
chmod 600 /opt/hyexit/config/subs.env /opt/hyexit/config/gen.env

# 3. generate + validate the proxy config
${NODE:-node} /opt/hyexit/bin/gen-config.mjs

# 4. systemd unit, sysctl, first bring-up
bash deploy/02-install-service.sh

# 5. hidden TOTP panel (prints the TOTP secret + otpauth URL once)
PANEL_HOST=panel.example.com PANEL_PORT=10443 bash deploy/03-install-panel.sh

# 6. watchdog + cron
bash deploy/04-install-watchdog.sh

# 7. advertise as an exit node, then APPROVE it in the Tailscale admin console
tailscale set --advertise-exit-node

# 8. assert everything
bash /opt/hyexit/bin/verify.sh
```

Then on a client: `tailscale set --exit-node=<vps-name>`.

## The two iron rules

1. **Only traffic arriving on `tailscale0` may be captured.** Every change must be re-verified with
   `curl https://api.ipify.org` on the host (must print the VPS's own IP) and by checking that the
   host's `/run/systemd/resolve/resolv.conf` contains no `198.18.x`/`fdfe:dcba` fake-IP resolvers.
   `deploy/99-verify.sh` does both.
2. **A broken proxy must degrade to direct egress, never to a black hole.** The capture route lives in a
   table whose default route is bound to the TUN device: when mihomo stops, the device disappears, the
   kernel drops the route, the rule matches nothing and traffic falls through to Tailscale's own
   table 52 → plain Hong Kong egress. `route-down.sh` additionally redirects client DNS to the VPS
   resolver so "Clash off" is still a *usable* exit node.

## Panel

`https://<PANEL_HOST>:<PANEL_PORT>/clashConfiguePage` — TOTP (RFC 6238, 6 digits, 30 s, ±1 window,
replay-guarded), 5 wrong codes lock that IP for 2 hours, 30-day `SameSite=Strict` cookie. Everything
outside the gateway answers a bare **404** to unauthenticated clients, and the mihomo API secret is
injected server-side, so it never reaches the browser.

The **ON/OFF switch stops and starts the whole proxy** — that is the point: OFF = direct fast Hong Kong
egress, ON = proxied (other countries, ad-blocking, rules) which is slower because of the userspace TCP
stack (see `docs/pitfalls.md` §5).

## Security notes

* `external-controller` listens on `127.0.0.1` only; the browser talks to the gateway, which injects
  the secret. A fresh random secret is generated per deployment at `/opt/hyexit/state/controller.secret`.
* `allow-lan: true` + `bind-address: '*'` are **required** for the capture to work at all (see
  `docs/pitfalls.md` §1), so the mixed/socks ports are closed for the tailnet by an nft guard installed
  by `route-up.sh` and re-asserted by the watchdog.
* Subscription URLs are secrets: they live only in `/opt/hyexit/config/subs.env` (0600) and are never
  written into the generated config in a readable way, logged, or committed.
* This repository contains **no** deployment-specific values. Everything that is site-specific lives in
  the non-committed `config/gen.env` (see `conf/gen.env.example`).

## Quick start (local dashboard)

```powershell
cd dashboard
powershell -File fetch-ui.ps1                            # pulls the zashboard build into public/
copy ..\conf\dashboard.config.example.json config.json   # then edit port / clashConfig / totpSecret
powershell -File install.ps1                             # admin: port reservation + firewall + boot task
# open http://<machine-ip>:3000/panel/
```

Port reservation matters: on a machine with Hyper-V/WSL a "free" port can sit inside a system-reserved
range, where binding fails with `EACCES` until you carve it out — the installer does that and explains
what it is doing.

## Documentation

* `docs/design.md` — why the design looks like this (routing, capture, fail-safe, panel architecture).
* `docs/pitfalls.md` — every trap that cost real debugging time, with the symptom and the fix.
* `docs/repro.md` — reproduce / verify / roll back, step by step.
* `docs/windows-tun.md` — the local/Windows side: TUN crash radius, the default-route race, TUN vs
  Tailscale relaying, port reservation, and the rescue tool.
* `dashboard/README.md` — the TOTP-gated local dashboard: install, auth, troubleshooting.

## Requirements

Ubuntu 22.04 or similar, kernel ≥ 5.15, Tailscale ≥ 1.60, nftables, `iproute2`, Node ≥ 20 (for the two
`.mjs` tools), a TLS certificate for the panel hostname, and root.

## License

MIT — see `LICENSE`.
