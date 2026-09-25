#!/bin/bash
# /opt/hyexit/bin/route-up.sh   (TUN edition - the configuration that is verified working)
#
#   ip rule  iif tailscale0 -> table 1000 -> default dev hyexit0
#   nft nat iifname tailscale0 :53 -> mihomo's fake-ip resolver on :5353
#
# Only traffic ARRIVING ON tailscale0 (forwarded exit-node clients) enters the TUN; the
# host's own traffic is generated without an iif and is never touched.
#
# DO NOT add `ip rule to 100.64.0.0/10 lookup main`: the main table has a default route, so
# such a rule sends every tailnet-destined reply out to the internet gateway and drops it
# (symptom: client DNS dead while TCP still works).
#
# FAIL-SAFE: table 1000's default route is bound to the TUN device. When mihomo stops the
# device disappears, the kernel drops the route, this rule finds nothing and traffic falls
# through to table 52 / main -> direct Hong Kong egress. No script required.
set -u
IF=hyexit0
CLIENT_IF=tailscale0
T_V4=1000
T_V6=1006
log() { logger -t hyexit "$*"; echo "[hyexit] $*"; }

for i in $(seq 1 60); do ip link show "$IF" >/dev/null 2>&1 && break; sleep 0.5; done
if ! ip link show "$IF" >/dev/null 2>&1; then log "FATAL: $IF missing, not installing routes"; exit 1; fi

# host DNS protection: mihomo pushes its fake-ip resolver onto the TUN link and
# systemd-resolved would adopt it as a global upstream (host would lose egress)
before="$(resolvectl dns "$IF" 2>/dev/null | head -1)"
resolvectl revert "$IF" 2>/dev/null
resolvectl domain "$IF" "" 2>/dev/null
resolvectl flush-caches 2>/dev/null
log "host resolver for $IF reverted | before=[$before]"

# clean previous/legacy rules (including the TPROXY/redirect experiment)
ip rule del iif "$IF" lookup $T_V4 priority 5200 2>/dev/null
ip rule del iif "$CLIENT_IF" lookup $T_V4 priority 5200 2>/dev/null
ip rule del to 100.64.0.0/10 lookup main priority 5190 2>/dev/null
ip -6 rule del iif "$IF" lookup $T_V6 priority 5200 2>/dev/null
ip -6 rule del iif "$CLIENT_IF" lookup $T_V6 priority 5200 2>/dev/null
ip -6 rule del to fd7a:115c:a1e0::/48 lookup main priority 5190 2>/dev/null
ip rule del fwmark 0x1 lookup 100 priority 5100 2>/dev/null
ip -6 rule del fwmark 0x1 lookup 100 priority 5100 2>/dev/null
ip route flush table 100 2>/dev/null
ip -6 route flush table 100 2>/dev/null
nft delete table ip hyexitproxy 2>/dev/null
nft delete table ip6 hyexitproxy6 2>/dev/null
ip route flush table $T_V4 2>/dev/null
ip -6 route flush table $T_V6 2>/dev/null

# v4 policy routing
ip route replace 100.64.0.0/10 dev "$CLIENT_IF" table $T_V4
ip route replace default dev "$IF" table $T_V4
ip rule add iif "$CLIENT_IF" lookup $T_V4 priority 5200

# v6 policy routing
if ip -6 route show default 2>/dev/null | grep -q . && ip -6 addr show dev "$CLIENT_IF" 2>/dev/null | grep -q "inet6"; then
  ip -6 route replace fd7a:115c:a1e0::/48 dev "$CLIENT_IF" table $T_V6
  ip -6 route replace default dev "$IF" table $T_V6
  ip -6 rule add iif "$CLIENT_IF" lookup $T_V6 priority 5200
  log "v6 rules installed"
else
  log "v6 skipped"
fi

# client DNS -> mihomo's fake-ip resolver (scoped to the clients, host untouched)
nft delete table ip hyexitdns 2>/dev/null
nft -f - <<'NFT'
table ip hyexitdns {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "tailscale0" udp dport 53 redirect to :5353
    iifname "tailscale0" tcp dport 53 redirect to :5353
  }
}
NFT
nft delete table ip6 hyexitdns6 2>/dev/null
nft -f - <<'NFT'
table ip6 hyexitdns6 {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "tailscale0" udp dport 53 redirect to :5353
    iifname "tailscale0" tcp dport 53 redirect to :5353
  }
}
NFT
log "up: iif $CLIENT_IF -> table $T_V4 (default dev $IF)"

# Close the mixed/socks ports for tailnet peers. allow-lan + bind-address '*' make mihomo listen
# on every interface (that is what makes the capture work at all), so without this guard any
# device in the tailnet could use the VPS as an OPEN PROXY. nft tables do not survive a reboot,
# hence re-installing it here on every start instead of once by hand.
nft delete table ip hyexitguard 2>/dev/null
nft -f - <<'NFT'
table ip hyexitguard {
  chain input {
    type filter hook input priority filter - 5; policy accept;
    iifname "tailscale0" tcp dport { 17897, 17898 } drop
    iifname "tailscale0" udp dport { 17897, 17898 } drop
  }
}
NFT
log "tailnet guard installed (17897/17898 dropped from $CLIENT_IF)"
ip rule show | grep -E '5190|5200' | sed 's/^/[hyexit]   /'
exit 0
