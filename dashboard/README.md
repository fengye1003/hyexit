# dashboard — a TOTP-gated Clash dashboard served on your own machine

A **zero-dependency Node gateway** that serves [zashboard](https://github.com/Zephyruso/zashboard) and
reverse-proxies the local Clash/mihomo controller. Built for the "Clash Verge TUN mode always on"
setup: your machine keeps its own proxy client, and this gives you a panel you can open from a phone
(on the LAN or over the tailnet) without exposing the controller or its secret.

```
browser ──http://<machine>:3000/panel/──▶ server.mjs (Node, no deps)
                                            ├─ TOTP login (RFC 6238 / ±1 window / replay guard / IP lockout)
                                            ├─ static zashboard (public/)
                                            ├─ /local/status  aggregated local state
                                            └─ everything else ──inject Bearer secret──▶ controller
                                                                                          127.0.0.1:15120
```

## Why a gateway and not "point the browser at the controller"

1. **The controller secret never reaches the browser** — the gateway reads the Clash runtime config
   (mtime-cached, because Verge rewrites it whenever the core starts) and injects the credential.
2. **The controller's CORS allows only its own origins** (`tauri://localhost` and friends), so a page
   served from `http://<lan-ip>:3000` calling `http://<ip>:15120` is blocked. Same-origin proxying
   removes CORS from the picture entirely.
3. Both classic zashboard traps are handled: the SPA needs `?hostname=&port=&protocol=` (without
   `protocol` it silently targets `http://<host>:9090` and issues **zero** API calls), and the API
   probes trigger an `OPTIONS` preflight that must be answered **204**, not 404.

## Auth

| Feature | Behaviour |
|---|---|
| Algorithm | RFC 6238, SHA1, 6 digits, 30 s, **±1 window accepted** (tolerates clock drift) |
| Replay | a code is burned on first use; replaying it is refused |
| Lockout | `lockFails` (default 5) wrong codes lock that source IP for `lockMinutes` (default 120) |
| Session | 30-day `HttpOnly; SameSite=Lax` cookie; `/logout` clears it |
| Unauthenticated | API paths return a **bare 404** (no hint an API exists); the UI redirects to `/login` |
| Public | `/healthz` only — handy for monitoring |

CORS stays "origin unrestricted", but **reflects the caller's `Origin`** instead of sending a literal
`*`, plus `Access-Control-Allow-Credentials: true`. That is required: `*` and credentials are mutually
exclusive. Cross-site pages cannot ride an existing session thanks to `SameSite=Lax`.

`config.json` holds `totpSecret` in plaintext on the machine — fine for a single-user box; tighten the
ACL if you care. The panel is HTTP, so the code travels in cleartext on the LAN (over Tailscale it is
inside WireGuard).

## Files

| File | Purpose |
|---|---|
| `server.mjs` | the gateway (static + TOTP + proxy + websocket passthrough), zero deps |
| `public/` | zashboard build — fetch it with `fetch-ui.ps1`, do not commit it |
| `config.json` | gateway config (**must be BOM-free**) — see `../conf/dashboard.config.example.json` |
| `install.ps1` | **admin**: reserve the port, open the firewall, register the boot task, start, self-verify |
| `uninstall.ps1` | **admin**: remove task / firewall rule / port reservation (keeps the files) |
| `verify-gateway.mjs` | 22 end-to-end assertions incl. the auth flow — `node verify-gateway.mjs 3000` |
| `fetch-ui.ps1` | download + unpack the latest zashboard `dist-no-fonts.zip` into `public/` |

## Install

```powershell
# 1. payload
cd D:\ClashDashboard                  # or wherever you put this folder
powershell -ExecutionPolicy Bypass -File .\fetch-ui.ps1

# 2. edit config.json (see ../conf/dashboard.config.example.json):
#    port, clashesConfig path, and totpSecret (base32; empty = no TOTP gate)

# 3. install (needs Administrator; opens a UAC prompt)
powershell -ExecutionPolicy Bypass -File .\install.ps1

# 4. open http://<machine-ip>:3000/panel/  -> enter the 6-digit code
```

`install.ps1` is idempotent and **preserves the secret fields** in `config.json` (an earlier revision
wiped them on re-run — see `../docs/pitfalls.md` §"config templates").

## Port reservation (this is not optional)

A port can be **reserved by the system** and still look "free": if it falls inside a Hyper-V/winnat
*excluded* range, an explicit bind fails with `EACCES` — it is not "in use", it is "taken away".

```powershell
netsh int ipv4 show excludedportrange protocol=tcp      # is my port inside one of these ranges?
netsh int ipv4 add excludedportrange protocol=tcp startport=3000 numberofports=1 store=persistent
# if it is still not bindable (winnat holds the range):
net stop winnat ; <the netsh line above> ; net start winnat
```

After that the port shows up as `3000  3000  *` (`*` = administratively reserved, survives reboots).
`install.ps1` does all of this and prints the result.

## Auto-start

A scheduled task named `ClashDashboard`: trigger **At startup**, principal **SYSTEM** (no logon
needed, survives logoff), `ExecutionTimeLimit=0`, restart ×3 on failure.

```powershell
schtasks /query /tn ClashDashboard /fo LIST /v     # needs admin
Stop-ScheduledTask  -TaskName ClashDashboard
Start-ScheduledTask -TaskName ClashDashboard
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Bind fails with `EACCES` at startup | the port is inside a reserved range again — re-run `install.ps1` (it restarts winnat and re-carves it) |
| Page loads but every panel is empty | the SPA lost its `protocol` parameter — always enter via `/panel/` (the gateway injects it) |
| Every API call returns 502 | the controller is down or moved — check `/local/status` (`controller.address`, `secretLoaded`) |
| UI reports a CORS error | someone removed the `OPTIONS → 204` path; `node verify-gateway.mjs <port>` pinpoints it |
| Works locally, not from the phone | the firewall rule only allows the LAN CIDR and `100.64.0.0/10`; adjust `-LanCidr` |
| Locked out after wrong codes | stop the task, delete `state\auth.json`, start the task (no elevation needed — `install.ps1` grants Users modify on `state/`) |
