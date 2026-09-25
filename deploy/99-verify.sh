#!/bin/bash
# 34-final-check.sh - consolidated health report for the hyexit stack.
set -u
HY=/opt/hyexit
# deployment-specific values (NOT committed): /opt/hyexit/config/gen.env
# set -a so the values are also visible to the python child processes below
set -a
[ -r $HY/config/gen.env ] && . $HY/config/gen.env
set +a
echo "=== 1. services ==="
for s in hyexit-mihomo hyexit-panel nginx tailscaled; do printf "   %-16s %s\n" "$s" "$(systemctl is-active $s)"; done

echo
echo "=== 2. routing ==="
ip rule show | grep -E "5190|5200" | sed 's/^/   /'
echo "   table 1000: $(ip route show table 1000 | tr '\n' ' ')"
echo "   table 1006: $(ip -6 route show table 1006 | tr '\n' ' ')"
echo "   nft dns   : $(nft list table ip hyexitdns >/dev/null 2>&1 && echo present || echo MISSING)"

echo
echo "=== 3. host isolation assertions ==="
echo -n "   host resolvers: "; grep -E '^nameserver' /run/systemd/resolve/resolv.conf | tr '\n' ' '; echo
echo -n "   fake-ip leak  : "; grep -qE "198\.18\.|fdfe:dcba" /run/systemd/resolve/resolv.conf && echo "PRESENT (BAD)" || echo "none (good)"
echo -n "   resolvectl hyexit0: "; resolvectl dns hyexit0 2>/dev/null | sed 's/^ *//'
echo -n "   host exit ip  : "; curl -s -m 12 https://api.ipify.org; echo
echo -n "   proxy exit ip : "; curl -s -m 25 -x http://127.0.0.1:17897 https://api.ipify.org; echo
SITES=${HYEXIT_SITES:-example.com}   # space separated, override in gen.env
echo -n "   sites: "; for u in $SITES; do printf "%s=%s " "${u%%.*}" "$(curl -s -o /dev/null -m 10 -w '%{http_code}' https://$u/)"; done; echo

echo
echo "=== 4. panel ==="
P=${PANEL_PORT:-10443}; H=${PANEL_HOST:-panel.example.com}
for u in / /proxies /version /clashConfiguePage; do
  printf "   unauth %-18s %s\n" "$u" "$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" https://127.0.0.1:$P$u)"
done
python3 - <<'PY'
import hmac, base64, struct, time, hashlib, ssl, urllib.request, http.cookiejar, json, os
P, H = int(os.environ.get('PANEL_PORT', '10443')), os.environ.get('PANEL_HOST', 'panel.example.com')
BASE = f'https://127.0.0.1:{P}'
secret = open('/opt/hyexit/state/totp.secret').read().strip()
key = base64.b32decode(secret + '=' * ((8 - len(secret) % 8) % 8))
def code_for(c):
    h = hmac.new(key, struct.pack('>Q', c), hashlib.sha1).digest(); o = h[-1] & 0x0f
    return '%06d' % ((struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 10**6)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(cj))
op.addheaders = [('Host', H)]
req = urllib.request.Request(BASE + '/clashConfiguePage/login', data=('code=' + code_for(int(time.time()) // 30)).encode(), method='POST')
req.add_header('Content-Type', 'application/x-www-form-urlencoded')
try:
    st = op.open(req, timeout=20).status
except urllib.error.HTTPError as e:
    st = e.code
print('   login            ', st, '(expect 200/302)')

def get(p):
    try: return op.open(BASE + p, timeout=25).status
    except urllib.error.HTTPError as e: return e.code
mihomo_up = os.popen('systemctl is-active hyexit-mihomo 2>/dev/null').read().strip() == 'active'
# /proxies is proxied to the mihomo controller: with the proxy deliberately OFF the gateway
# answers 502, which is the correct behaviour and not a failure.
print('   authed /proxies  ', get('/proxies'), '(expect 200 with the proxy ON, 502 while OFF)')
print('   authed /status   ', get('/clashConfiguePage/api/status'), '(expect 200)')
print('   proxy state      ', 'ON' if mihomo_up else 'OFF (direct Hong Kong egress by design)')
PY

echo
echo "=== 5. watchdog + cron ==="
echo "   state: $(cat $HY/state/watchdog.state 2>/dev/null | tr '\n' ' ')"
echo "   cron : $(crontab -l 2>/dev/null | grep -c hyexit)"
crontab -l 2>/dev/null | grep hyexit | sed 's/^/      /'
$HY/bin/watchdog.sh && echo "   watchdog ran clean (panel auth + dns + proxy all pass)"

echo
echo "=== 6. exit node ==="
tailscale debug prefs 2>/dev/null | grep -A3 AdvertiseRoutes | sed 's/^/   /'
tailscale status --json | python3 -c "import sys,json;d=json.load(sys.stdin);s=d.get('Self',{});print('   approved (ExitNodeOption):', s.get('ExitNodeOption'))"
echo
echo "=== DONE ==="
