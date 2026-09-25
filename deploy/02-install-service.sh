#!/bin/bash
# 20-apply-routing.sh (v3) - sysctl + systemd unit + service bring-up and verification.
#
# NOTE: route-up.sh / route-down.sh are maintained as separate files (server/route-up.sh,
# server/route-down.sh in the work area) and pushed directly with push-file.ps1. This script
# deliberately does NOT write them any more: an earlier version embedded stale copies and
# silently reverted a routing fix.
set -u
HY=/opt/hyexit
IF=hyexit0
CLIENT_IF=tailscale0
T_V4=1000

echo "=== A. IPv6 facts ==="
echo "   v6 default route: $(ip -6 route show default 2>/dev/null | head -1)"
if ip -6 route show default 2>/dev/null | grep -q .; then V6_OK=1; else V6_OK=0; fi

echo
echo "=== B. sysctl ==="
cat > /etc/sysctl.d/99-hyexit.conf <<'EOF'
# added by hyexit (tailscale exit node + clash) - no host traffic is proxied
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
if [ "$V6_OK" = "1" ]; then
  cat >> /etc/sysctl.d/99-hyexit.conf <<'EOF'
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.eth0.accept_ra = 2
EOF
fi
sysctl -p /etc/sysctl.d/99-hyexit.conf | sed 's/^/   /'

echo
echo "=== C. route scripts present? (pushed separately) ==="
for f in route-up.sh route-down.sh; do
  if [ -x $HY/bin/$f ]; then echo "   OK  $f ($(stat -c%s $HY/bin/$f) bytes)"; else echo "   MISSING $f -- push it first"; exit 1; fi
done
grep -q "iif \$CLIENT_IF lookup" $HY/bin/route-up.sh && echo "   route-up uses iif tailscale0 (correct)" || echo "   WARN: route-up may still use iif hyexit0"
grep -q "priority 5190" $HY/bin/route-up.sh && echo "   !!! route-up still adds the harmful 5190 rule" || echo "   no 5190 rule (correct)"

echo
echo "=== D. systemd unit ==="
cat > /etc/systemd/system/hyexit-mihomo.service <<'EOF'
[Unit]
Description=hyexit mihomo - dedicated proxy for the Tailscale exit node (does NOT touch host traffic)
After=network-online.target tailscaled.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=/opt/hyexit
ExecStart=/opt/hyexit/bin/mihomo -d /opt/hyexit/config
ExecStartPost=/opt/hyexit/bin/route-up.sh
ExecStopPost=/opt/hyexit/bin/route-down.sh
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
StandardOutput=append:/opt/hyexit/logs/mihomo.log
StandardError=append:/opt/hyexit/logs/mihomo.log

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/logrotate.d/hyexit <<'EOF'
/opt/hyexit/logs/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
EOF
systemctl daemon-reload
systemctl enable hyexit-mihomo.service 2>&1 | sed 's/^/   /'

echo
echo "=== E. (re)start and verify ==="
systemctl restart hyexit-mihomo
sleep 8
echo "   active=$(systemctl is-active hyexit-mihomo)"
tail -4 $HY/logs/mihomo.log | sed 's/^/   /'
echo "--- rules ---"
ip rule show | grep -E "5200|5190" | sed 's/^/   /'
echo "--- table $T_V4 ---"; ip route show table $T_V4 | sed 's/^/   /'
echo "--- client dns ---"; nft list table ip hyexitdns 2>/dev/null | sed 's/^/   /'
echo "--- host isolation ---"
echo -n "   resolvers: "; grep -E '^nameserver' /run/systemd/resolve/resolv.conf | tr '\n' ' '; echo
echo -n "   fake-ip  : "; grep -qE '198\.18\.|fdfe:dcba' /run/systemd/resolve/resolv.conf && echo BAD || echo none
echo -n "   host exit: "; curl -s -m 12 https://api.ipify.org; echo
echo -n "   proxy    : "; curl -s -m 25 -x http://127.0.0.1:17897 https://api.ipify.org; echo
echo -n "   sites    : "; for u in example.com blog.example.com up.example.com panel.example.com scan.example.com; do printf "%s=%s " "${u%%.*}" "$(curl -s -o /dev/null -m 10 -w '%{http_code}' https://$u/)"; done; echo
echo
echo "=== DONE ==="
