# Reproduce, verify, roll back

## 0. Preconditions

* Ubuntu 22.04 (or similar), kernel ≥ 5.15, root access.
* Tailscale installed, logged in, with a tailnet IP on `tailscale0`.
* A TLS certificate for the panel hostname (Let's Encrypt or any path you can point nginx at).
* Node ≥ 20 — resolve it explicitly if it is not on the default PATH
  (`command -v node || ls /opt/*/nodejs/v*/bin/node`).
* Your own subscriptions. Never commit them.

## 1. Install

```bash
bash deploy/01-install-kernel.sh      # /opt/hyexit tree, mihomo binary, geo data, zashboard dist
# write /opt/hyexit/config/subs.env (0600) and /opt/hyexit/config/gen.env (0600)  -> see conf/
node /opt/hyexit/bin/gen-config.mjs   # generate + mihomo -t validation
bash deploy/02-install-service.sh     # sysctl, systemd unit, logrotate, first start + checks
PANEL_HOST=... PANEL_PORT=... bash deploy/03-install-panel.sh   # prints TOTP secret + otpauth URL
bash deploy/04-install-watchdog.sh    # scripts + cron + telegram test
tailscale set --advertise-exit-node   # then approve it in the admin console
bash /opt/hyexit/bin/verify.sh
```

`gen.env` keys (all optional, all site-specific, never committed):

| Key | Meaning |
|---|---|
| `HYEXIT_OWN_DOMAINS` | Comma-separated domains that must never be proxied (your sites). |
| `HYEXIT_FORCE_PROXY_DOMAINS` | Domains that must be proxied even if an upstream rule says DIRECT. |
| `HYEXIT_PROXY_ALIASES` | Extra upstream proxy-group names treated as `PROXY` (see `pitfalls.md` §9). |
| `PANEL_HOST`, `PANEL_PORT` | Used by the watchdog/verify/panel-cli to probe the gateway. |
| `HYEXIT_HOST`, `HYEXIT_PORT` | Same, for `panel-cli.mjs`. |
| `HYEXIT_SITES` | Space-separated list of your own URLs to check for 200 during verification. |

## 2. Verify (the part that actually matters)

```bash
bash /opt/hyexit/bin/verify.sh
```

Expected report, with the proxy **off** (the default state):

```
1. services      hyexit-mihomo inactive | hyexit-panel active | nginx active | tailscaled active
2. routing       (no 5190/5200 rule, table 1000 empty, nft dns present = the client fallback)
3. isolation     host resolvers clean, no fake-ip leak, host exit = the VPS's own IP
4. panel         /,/proxies,/version -> 404 unauth ; /clashConfiguePage -> 200 ; TOTP login -> 200
                 authed /status -> 200 ; authed /proxies -> 502 (expected while the proxy is OFF)
5. watchdog      state empty, cron entry present
6. exit node     AdvertiseRoutes 0.0.0.0/0 and ::/0, ExitNodeOption = true
```

With the proxy **on**, additionally:

```bash
systemctl start hyexit-mihomo
ip link show hyexit0                                   # TUN present, mtu 1280
ip rule show | grep 'iif tailscale0 lookup 1000'        # capture rule present
ip route show table 1000                               # default dev hyexit0 + 100.64.0.0/10 dev tailscale0
nft list table ip hyexitdns                            # :53 redirect to :5353
nft list table ip hyexitguard                          # 17897/17898 dropped from tailscale0
curl -s https://api.ipify.org                          # MUST still be the VPS's own IP (host isolation)
curl -s -x http://127.0.0.1:17897 https://api.ipify.org  # a different IP = the proxy path works
```

Then from a real client (never from the server): `tailscale set --exit-node=<vps>`, check
`curl https://api.ipify.org`, and browse. Remember the throughput expectation (`pitfalls.md` §5).

Finally:

```bash
systemctl stop hyexit-mihomo
ip rule show | grep -c 'iif tailscale0 lookup 1000'    # 0
ip link show hyexit0                                   # gone
nft list table ip hyexitdns | grep -c 'dnat to'        # 2 = clean-DNS fallback installed
curl -s https://api.ipify.org                          # VPS's own IP, sites still 200
```

## 3. Change something safely

1. Edit the source of truth (`gen-config.mjs`, `route-up.sh`, ...), not the live files.
2. Push and, for config changes, always look at the diff first:

```bash
node /opt/hyexit/bin/gen-config.mjs --dry      # writes config.dry-<ts>.yaml, does not touch config.yaml
diff <(grep -E '^(allow-lan|bind-address)|^  (enable|stack|mtu):' /opt/hyexit/config/config.dry-*.yaml) \
     <(grep -E '^(allow-lan|bind-address)|^  (enable|stack|mtu):' /opt/hyexit/config/config.yaml)
```

3. For routing changes, snapshot first — the rule set is small and easy to restore by hand:

```bash
ip rule show > /root/snap-iprule.txt; ip route show table 1000 > /root/snap-t1000.txt
nft list ruleset > /root/snap-nft.txt
```

4. Apply, then re-run the §2 checks. **Both iron rules** must hold every single time: host exit IP
   unchanged, host resolvers clean, all of your own sites still 200.

## 4. Roll back

```bash
# proxy off (the normal state)
systemctl stop hyexit-mihomo && systemctl disable hyexit-mihomo

# undo routing completely
bash /opt/hyexit/bin/route-down.sh

# undo a bad generated config (the generator backs up automatically)
cp /opt/hyexit/config/config.bak-<timestamp>.yaml /opt/hyexit/config/config.yaml

# undo the panel
systemctl disable --now hyexit-panel
rm -f /etc/nginx/conf.d/zz-hyexit-panel.conf && nginx -t && systemctl reload nginx

# stop being an exit node
tailscale set --advertise-exit-node=false
```

Nothing in this design modifies the host's `main` routing table, so a rollback cannot leave the server
without internet access; worst case the proxy path stops working and clients fall back to direct egress.

## 5. Routine operations

```bash
systemctl start hyexit-mihomo     # proxy ON (turns itself back off at the next reboot: not enabled)
systemctl stop  hyexit-mihomo      # proxy OFF -> direct, fast
tail -f /opt/hyexit/logs/mihomo.log
cat /opt/hyexit/state/watchdog.state          # non-empty = an alert is active
tail -20 /opt/hyexit/logs/watchdog.log
node /opt/hyexit/bin/panel-cli.mjs status|on|off|subs|login
```

Rotate the panel TOTP secret: `rm /opt/hyexit/state/totp.secret && bash deploy/03-install-panel.sh`
(then re-enrol the authenticator). Rotate the mihomo controller secret:
`rm /opt/hyexit/state/controller.secret && node /opt/hyexit/bin/gen-config.mjs && systemctl restart
hyexit-mihomo`. Rotate subscription URLs: edit `subs.env`, regenerate, restart.
