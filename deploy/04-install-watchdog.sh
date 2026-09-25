#!/bin/bash
# 04-install-watchdog.sh - install bin/watchdog.sh + a 2-minute cron entry, then run it once.
# The watchdog is the fail-safe: if the proxy path is broken it degrades to DIRECT egress and
# alerts, it never leaves clients black-holed.
#
# Tunables (env): PANEL_HOST, PANEL_PORT (used for the "gateway must stay TOTP-gated" probe)
#                 TG_CONF (default /root/.hy-tg.conf, optional: TG_TOKEN=..., TG_CHAT=...)
set -u
HY=/opt/hyexit
SRC=$(cd "$(dirname "$0")/.." && pwd)

echo "=== A. install script + perms ==="
install -m 700 "$SRC/bin/watchdog.sh" $HY/bin/watchdog.sh
install -m 700 "$SRC/bin/route-up.sh" $HY/bin/route-up.sh
install -m 700 "$SRC/bin/route-down.sh" $HY/bin/route-down.sh
ls -l $HY/bin/*.sh | sed 's/^/   /'

echo
echo "=== B. cron entry (every 2 minutes) ==="
if crontab -l 2>/dev/null | grep -q "hyexit/bin/watchdog.sh"; then
  echo "   already installed"
else
  (crontab -l 2>/dev/null; echo "*/2 * * * * $HY/bin/watchdog.sh >/dev/null 2>&1") | crontab -
  echo "   installed every 2 minutes"
fi
crontab -l 2>/dev/null | grep hyexit | sed 's/^/   /'

echo
echo "=== C. telegram alert plumbing (optional) ==="
TG=${TG_CONF:-/root/.hy-tg.conf}
if [ -r "$TG" ]; then
  . "$TG"
  TOKEN="$(printf %s "${TG_TOKEN:-}" | tr -d '\r\n"')"
  CHAT="$(printf %s "${TG_CHAT:-}" | tr -d '\r\n"')"
  if [ -n "$TOKEN" ] && [ -n "$CHAT" ]; then
    # sanity: a chat id truncated to 1-2 chars makes every alert fail SILENTLY - check it
    L=${#CHAT}
    echo "   chat id length=$L (a real chat id is 9-13 digits; a short one means the conf is broken)"
    echo -n "   getMe: "; curl -s -m 12 "https://api.telegram.org/bot$TOKEN/getMe" | head -c 120; echo
    echo -n "   sendTest: "; curl -s -m 15 -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
      --data-urlencode "chat_id=$CHAT" --data-urlencode "text=[hyexit] watchdog installed" | head -c 160; echo
  else
    echo "   WARN: $TG present but TG_TOKEN/TG_CHAT missing"
  fi
else
  echo "   no $TG - watchdog will log locally and skip alerts (fine)"
fi

echo
echo "=== D. first run ==="
$HY/bin/watchdog.sh
echo "   state: $(cat $HY/state/watchdog.state 2>/dev/null | tr '\n' ' ')"
echo "   log tail:"; tail -6 $HY/logs/watchdog.log 2>/dev/null | sed 's/^/      /'

echo
echo "=== E. auth surface still closed (unauthenticated probes must be 404) ==="
P=${PANEL_PORT:-10443}; H=${PANEL_HOST:-panel.example.com}
for path in / /proxies /clashConfiguePage/api/status; do
  printf "   %-32s -> HTTP %s\n" "$path" "$(curl -sk -o /dev/null -m 10 -w '%{http_code}' "https://127.0.0.1:$P$path" -H "Host: $H")"
done
echo
echo "=== DONE ==="
