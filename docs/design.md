# Design

## Goal

Turn a VPS into a Tailscale exit node that egresses through a private Clash, **without** the proxy ever
touching the traffic the VPS generates for its own services (web sites, control panel, package
management, backups, monitoring).

The two requirements pull in opposite directions: "everything from clients must be proxied" versus
"nothing from the host may be proxied". The design therefore never touches the host's global routing —
it selects traffic by **ingress interface**.

## Traffic selection (the core idea)

```
ip rule  add iif tailscale0 lookup 1000        priority 5200
ip route replace 100.64.0.0/10 dev tailscale0 table 1000
ip route replace default        dev hyexit0   table 1000
```

* Forwarded exit-node traffic **arrives on `tailscale0`** → matches the rule → uses table 1000 → the
  default route sends it into the mihomo TUN.
* The same table also needs a route for `100.64.0.0/10` (the tailnet itself, e.g. replies to the
  client), pinned to `tailscale0`, so tailnet-internal traffic does not get dragged into the proxy.
* The host's own traffic is generated locally: it has no ingress interface, never matches `iif`, and
  keeps using the `main` table. `ip route get 1.1.1.1` on the host must still show `dev eth0`.
* Tailscale's own table 52 (peer routes) is left alone; the rule at priority 5200 is evaluated before it
  only for `iif tailscale0`.

**Never** add a rule that sends `100.64.0.0/10` to `main`: `main` has a default route, so tailnet-bound
replies would be pushed out to the internet gateway and dropped (see `pitfalls.md` §2).

## Capture

mihomo runs a TUN device (`hyexit0`, gvisor stack, `auto-route: false`, MTU 1280) that becomes the
default route of table 1000. Because the route is bound to the device:

* mihomo running → clients are captured, rules apply;
* mihomo stopped → the device disappears, the kernel removes the route, the rule matches nothing and
  traffic falls through to table 52/`main` → **direct Hong Kong egress**.

That is the fail-safe: it is a kernel property, not a script that has to run at the right moment.

DNS gets the same treatment. Client DNS (port 53 arriving on `tailscale0`) is redirected by nftables to
mihomo's fake-IP resolver on `:5353` so domain rules work. When the proxy is off, `route-down.sh`
replaces that redirect with a DNAT to the VPS's own resolver, so an "off" exit node still gives clients
clean (unpoisoned) DNS instead of leaking queries to whatever resolver the client had.

## Why a TUN and not TPROXY

TPROXY/REDIRECT would keep the kernel's TCP stack (much faster over a high-RTT link) but on this box
neither ever delivered a connection to mihomo: nft counters matched, mihomo logged nothing, traffic
silently fell through to direct. Both experiments were reverted; gvisor is what ships, with the known
throughput ceiling documented in `pitfalls.md` §5.

## Config generation

`gen-config.mjs` is the single source of truth for `config.yaml`:

1. reads `subs.env` (subscription URLs, 0600) and `gen.env` (site-specific values, 0600);
2. fetches each subscription, with retry/backoff, and falls back to a cached copy of the rules if the
   provider is down (rate limits and 5xx are the norm);
3. normalises and de-duplicates the rule sets, mapping each upstream target onto `PROXY` / `DIRECT` /
   `ADS`, and reports targets it could not map;
4. emits the config in layers:
   * layer 0 — self-protection: tailnet, private ranges, multicast, *your own domains* → `DIRECT`;
   * layer 1 — maintained rule sets (ad blocking, local network, CN geosite);
   * layer 2 — merged subscription rules (order: primary provider first);
   * layer 3 — dynamic CN fallback (`geosite-cn`, `geoip-cn`, `GEOIP,CN`) and `MATCH,PROXY`;
   * then any `HYEXIT_FORCE_PROXY_DOMAINS`, immediately before `MATCH`;
5. **refuses to write** if a rule line still contains a quote character, backs up the previous config,
   writes 0600, and validates with `mihomo -t` before anyone restarts anything.

Every rule is deterministic given the same upstream data, and every site-specific input is in `gen.env`,
so the same repository serves any deployment.

## Services and failure handling

| Unit | Role |
|---|---|
| `hyexit-mihomo.service` | mihomo. `ExecStartPost=route-up.sh`, `ExecStopPost=route-down.sh`. |
| `hyexit-panel.service` | TOTP gateway + zashboard, listening on `127.0.0.1:19121` only. |

Both use `StartLimitIntervalSec=0` and `Restart=always`/`on-failure` so systemd keeps them alive.
`hyexit-mihomo` is **not** enabled on the reference deployment: the accepted default is a fast direct
Hong Kong exit node, with the proxy switched on from the panel when needed. Disabling it also guarantees
a reboot cannot silently re-enable slow proxy mode.

The watchdog (cron, every 2 minutes) asserts, in this order:

1. TUN present (if the service is supposed to be up) → restart if not;
2. policy rule + client-DNS redirect present → re-run `route-up.sh`;
3. tailnet guard present → re-run `route-up.sh`;
4. host resolver not polluted → revert + flush + restart `systemd-resolved`;
5. proxy path really works (3 consecutive failures required, because url-test node switching produces
   single failures) → restart mihomo;
6. **panel auth still gates** (unauthenticated `/proxies` must be `404`) — checked whether the proxy is
   on or off;
7. if the proxy is intentionally off: remove stale rules, remove the guard, and make sure the DNS
   fallback exists.

Alerts go to Telegram only on state *change*, so a persistent problem does not spam.

## Panel architecture

```
browser ──TLS──▶ nginx (obscure port, hostname = panel host)
                   │
                   ▼
          panel-server.mjs  127.0.0.1:19121
            ├─ TOTP login (RFC 6238, ±1 window, replay guard, 5 fails → 2 h IP lock)
            ├─ 30-day SameSite=Strict cookie
            ├─ serves zashboard with the backend seed injected (protocol/hostname/port)
            ├─ control API: status / power / subs / logs
            └─ reverse proxy to the mihomo API, injecting the secret server-side
                   │
                   ▼
          mihomo external-controller  127.0.0.1:19120  (secret never reaches the browser)
```

Unauthenticated requests to anything except the login page return a bare `404`, so the entry point looks
like nothing at all. The `OPTIONS` preflight is answered `204` with an
`Access-Control-Allow-Origin` header for the same origin, because the UI probes the API with an
`Authorization` header.

## Deliberate non-goals

* No containerisation: the pieces need `CAP_NET_ADMIN` for routing and nftables anyway, and native
  systemd units keep the blast radius obvious.
* No automatic node selection for throughput: url-test groups optimise latency, and the lowest-latency
  line is often bandwidth-capped — hence the explicit "manual pick" group for large downloads.
* No attempt to hide the fact that this is a proxy from the client side; the panel is the only hidden
  surface.
