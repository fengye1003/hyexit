#!/bin/bash
# /opt/hyexit/bin/watchdog.sh - runs every 2 minutes from cron.
# Keeps the exit-node proxy healthy and FAILS SAFE: a broken proxy must degrade to
# direct Hong Kong egress, never to a black hole. Alerts via telegram only on state change.
set -u
HY=/opt/hyexit
IF=hyexit0                 # mihomo TUN
CLIENT_IF=tailscale0       # where exit-node client traffic arrives
T_V4=1000
LOG=$HY/logs/watchdog.log
STATE=$HY/state/watchdog.state
# deployment-specific values live in the NOT-committed /opt/hyexit/config/gen.env, e.g.
#   PANEL_HOST="panel.example.com"
#   PANEL_PORT=10443
[ -r $HY/config/gen.env ] && . $HY/config/gen.env
PANEL_HOST=${PANEL_HOST:-panel.example.com}   # gateway vhost
PANEL_PORT=${PANEL_PORT:-10443}               # gateway https port
log() { echo "[$(date -Is)] $*" >> $LOG; }

# telegram creds live in /root/.hy-tg.conf (TG_TOKEN=..., TG_CHAT=...), same as hy-monitor.sh
TOKEN=""; CHAT=""
if [ -r /root/.hy-tg.conf ]; then
  . /root/.hy-tg.conf
  TOKEN="$(printf %s "${TG_TOKEN:-}" | tr -d '\r\n"')"
  CHAT="$(printf %s "${TG_CHAT:-}" | tr -d '\r\n"')"
fi
tg() {
  [ -n "$TOKEN" ] && [ -n "$CHAT" ] || return 0
  curl -s -m 15 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    --data-urlencode "chat_id=${CHAT}" --data-urlencode "text=$1" >/dev/null 2>&1
}
alert() {
  local key="$1" msg="$2" prev
  prev=$(grep -m1 "^$key=" $STATE 2>/dev/null | cut -d= -f2-)
  if [ "$prev" != "$msg" ]; then
    log "ALERT $key: $msg"
    tg "[hyexit] $msg"
    grep -v "^$key=" $STATE 2>/dev/null > $STATE.tmp || true
    echo "$key=$msg" >> $STATE.tmp
    mv $STATE.tmp $STATE
  fi
}
clear_alert() {
  local key="$1"
  if grep -q "^$key=" $STATE 2>/dev/null; then
    grep -v "^$key=" $STATE > $STATE.tmp; mv $STATE.tmp $STATE; log "CLEAR $key"
  fi
}
host_dns_polluted() { grep -qE "198\.18\.|fdfe:dcba" /run/systemd/resolve/resolv.conf 2>/dev/null; }
fix_host_dns() {
  resolvectl revert "$IF" >/dev/null 2>&1
  resolvectl domain "$IF" "" >/dev/null 2>&1
  resolvectl flush-caches >/dev/null 2>&1
  systemctl restart systemd-resolved >/dev/null 2>&1
}

host_dns_polluted() { grep -qE "198\.18\.|fdfe:dcba" /run/systemd/resolve/resolv.conf 2>/dev/null; }

# The panel must stay TOTP-gated whether the proxy is ON or OFF: a silently failing auth layer is
# the most dangerous failure mode, so this check runs in BOTH branches.
panel_check() {
  local pactive pcode
  pactive=$(systemctl is-active hyexit-panel.service 2>/dev/null)
  pcode=$(curl -sk -o /dev/null -m 10 -w "%{http_code}" -H "Host: $PANEL_HOST" https://127.0.0.1:$PANEL_PORT/proxies 2>/dev/null)
  if [ "$pactive" != "active" ]; then
    alert panel "控制面板服务未运行（systemd 应自动拉起）"
  elif [ "$pcode" != "404" ]; then
    alert panel "面板未登录访问 /proxies 返回 ${pcode}（应为 404）→ 认证层可能失效，请立刻检查"
  else
    clear_alert panel
  fi
}

active=$(systemctl is-active hyexit-mihomo.service 2>/dev/null)

if [ "$active" = "active" ]; then
  # 1. TUN present?
  if ! ip link show "$IF" >/dev/null 2>&1; then
    alert tun "Clash 已开启但 TUN($IF) 缺失 → 正在重启内核（此刻客户端走直出，不会断网）"
    systemctl restart hyexit-mihomo.service
    exit 0
  fi
  clear_alert tun

  # 2. policy route present?  (iif tailscale0 -> table 1000)
  if ! ip rule show | grep -q "iif $CLIENT_IF lookup $T_V4"; then
    log "policy rule missing -> route-up"
    $HY/bin/route-up.sh >> $LOG 2>&1
  fi
  # 3. client DNS must go to mihomo's fake-ip resolver
  if ! nft list table ip hyexitdns 2>/dev/null | grep -q "redirect to :5353"; then
    log "client dns redirect wrong/missing -> route-up"
    $HY/bin/route-up.sh >> $LOG 2>&1
  fi
  # 3b. tailnet guard: mihomo listens on all interfaces, so the proxy ports must stay closed
  #     for tailnet peers (otherwise the VPS is an open proxy for the whole tailnet)
  if ! nft list table ip hyexitguard 2>/dev/null | grep -q "17897"; then
    log "tailnet guard missing -> route-up"
    $HY/bin/route-up.sh >> $LOG 2>&1
  fi
  # 4. HOST resolver must not be polluted by mihomo's fake-ip DNS
  if host_dns_polluted; then
    fix_host_dns
    alert hostdns "宿主 DNS 被 fake-ip 污染 → 已自动修复（mihomo 建 TUN 时的已知行为）"
  else
    clear_alert hostdns
  fi
  # 5. proxy path: a single failure is normal (url-test switching nodes) -> 3 strikes
  lastcode=""
  for i in 1 2 3; do
    lastcode=$(curl -s -o /dev/null -m 12 -w "%{http_code}" --proxy http://127.0.0.1:17897 https://www.gstatic.com/generate_204 2>/dev/null)
    if [ "$lastcode" = "204" ] || [ "$lastcode" = "200" ]; then break; fi
    sleep 5
  done
  if [ "$lastcode" != "204" ] && [ "$lastcode" != "200" ]; then
    alert proxy "出口代理链路连续 3 次失败（HTTP ${lastcode:-none}）→ 已重启 mihomo（客户端短暂走直出）"
    systemctl restart hyexit-mihomo.service
  else
    clear_alert proxy
  fi

  # 6. panel auth layer must still gate (a silent fail-open is the most dangerous failure)
  panel_check
else
  # Clash intentionally OFF (or crashed): enforce the fail-safe direct state
  if ip rule show | grep -q "iif $CLIENT_IF lookup $T_V4" || nft list table ip hyexitproxy >/dev/null 2>&1; then
    log "mihomo inactive but capture rules present -> route-down"
    $HY/bin/route-down.sh >> $LOG 2>&1
  fi
  # no mihomo -> no listeners -> the tailnet guard must not linger
  nft list table ip hyexitguard >/dev/null 2>&1 && nft delete table ip hyexitguard 2>/dev/null
  # the clean-DNS fallback must exist even when Clash is off
  if ! nft list table ip hyexitdns 2>/dev/null | grep -q "dnat to"; then
    log "dns fallback missing while off -> route-down"
    $HY/bin/route-down.sh >> $LOG 2>&1
  fi
  host_dns_polluted && fix_host_dns
  clear_alert proxy; clear_alert tun; clear_alert hostdns
  panel_check
fi

# keep the log bounded
if [ -f "$LOG" ]; then tail -n 500 "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"; fi
exit 0
