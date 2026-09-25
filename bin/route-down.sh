#!/bin/bash
# /opt/hyexit/bin/route-down.sh   (TUN edition - verified working)
# Remove the policy rules. Table 1000's default route disappears with the TUN device, so
# clients fall back to tailscale's table 52 / main = DIRECT Hong Kong egress.
# Leaves a client-DNS fallback: DNAT client DNS to the VPS's own resolver (outside the GFW)
# so a "Clash off" exit node is still a usable Hong Kong exit instead of a poisoned-DNS trap.
set -u
IF=hyexit0
CLIENT_IF=tailscale0
T_V4=1000
T_V6=1006
TSIP="$(ip -4 addr show "$CLIENT_IF" 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1)"
log() { logger -t hyexit "$*"; echo "[hyexit] $*"; }

for i in $(seq 1 20); do ip link show "$IF" >/dev/null 2>&1 || break; sleep 0.5; done

ip rule del iif "$IF" lookup $T_V4 priority 5200 2>/dev/null
ip rule del iif "$CLIENT_IF" lookup $T_V4 priority 5200 2>/dev/null
ip rule del to 100.64.0.0/10 lookup main priority 5190 2>/dev/null
ip -6 rule del iif "$IF" lookup $T_V6 priority 5200 2>/dev/null
ip -6 rule del iif "$CLIENT_IF" lookup $T_V6 priority 5200 2>/dev/null
ip -6 rule del to fd7a:115c:a1e0::/48 lookup main priority 5190 2>/dev/null
ip rule del fwmark 0x1 lookup 100 priority 5100 2>/dev/null
ip -6 rule del fwmark 0x1 lookup 100 priority 5100 2>/dev/null
ip route flush table $T_V4 2>/dev/null
ip -6 route flush table $T_V6 2>/dev/null
ip route flush table 100 2>/dev/null
ip -6 route flush table 100 2>/dev/null
nft delete table ip hyexitproxy 2>/dev/null
nft delete table ip6 hyexitproxy6 2>/dev/null
nft delete table ip hyexitguard 2>/dev/null   # proxy ports are gone with mihomo, guard not needed
resolvectl revert "$IF" 2>/dev/null
resolvectl flush-caches 2>/dev/null

nft delete table ip hyexitdns 2>/dev/null
if [ -n "$TSIP" ]; then
  nft -f - <<NFT
table ip hyexitdns {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$CLIENT_IF" udp dport 53 dnat to $TSIP:53
    iifname "$CLIENT_IF" tcp dport 53 dnat to $TSIP:53
  }
}
NFT
  log "down: rules removed; client dns -> $TSIP:53 (clean fallback)"
else
  log "down: rules removed; dns fallback skipped (no tailscale ip)"
fi
nft delete table ip6 hyexitdns6 2>/dev/null
exit 0
