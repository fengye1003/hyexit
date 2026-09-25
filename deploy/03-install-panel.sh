#!/bin/bash
# 03-install-panel.sh - install the TOTP gateway service + hidden nginx vhost on an obscure port.
# Idempotent. Pure ASCII.
#
# Requires: zashboard dist already unpacked into /opt/hyexit/panel/public (step 01),
#           a TLS certificate for $PANEL_HOST, node on PATH.
#
# Tunables (env):  PANEL_HOST (default panel.example.com)
#                  PANEL_PORT (default 10443)   <-- pick a random free high port of your own
#                  NGINX_CONF_DIR (default /etc/nginx/conf.d)
#                  TLS_CERT / TLS_KEY (default Let's Encrypt paths for $PANEL_HOST)
set -u
HY=/opt/hyexit
PANEL_HOST=${PANEL_HOST:-panel.example.com}
PANEL_PORT=${PANEL_PORT:-10443}
NGINX_CONF_DIR=${NGINX_CONF_DIR:-/etc/nginx/conf.d}
TLS_CERT=${TLS_CERT:-/etc/letsencrypt/live/$PANEL_HOST/fullchain.pem}
TLS_KEY=${TLS_KEY:-/etc/letsencrypt/live/$PANEL_HOST/privkey.pem}

echo "=== A. preconditions ==="
[ -f "$TLS_CERT" ] || { echo "   MISSING cert $TLS_CERT - issue one first"; exit 1; }
[ -f "$TLS_KEY" ]  || { echo "   MISSING key  $TLS_KEY"; exit 1; }
NODE=$(command -v node) || { echo "   node not found on PATH"; exit 1; }
echo "   node=$NODE cert=$TLS_CERT"

echo
echo "=== B. port check ==="
if ss -tlnH "sport = :$PANEL_PORT" | grep -q .; then echo "   PORT $PANEL_PORT BUSY - abort"; exit 1; else echo "   port $PANEL_PORT free"; fi

echo
echo "=== C. TOTP secret (MUST be independent from any other panel's secret) ==="
if [ -s $HY/state/totp.secret ]; then
  echo "   existing secret reused"
else
  python3 - <<'PY'
import base64, os
raw = os.urandom(20)
s = base64.b32encode(raw).decode().rstrip('=')
with open('/opt/hyexit/state/totp.secret', 'w') as f:
    f.write(s)
PY
  chmod 600 $HY/state/totp.secret
  echo "   generated new secret"
fi
SECRET=$(cat $HY/state/totp.secret)
echo "   TOTP_SECRET=$SECRET"
echo "   OTPAUTH=otpauth://totp/hyexit:$PANEL_HOST?secret=$SECRET&issuer=hyexit&algorithm=SHA1&digits=6&period=30"
echo "   (policy: 5 wrong codes -> that IP locked 2 hours; replay of a used code rejected)"

echo
echo "=== D. panel frontend present? ==="
ls -1 $HY/panel/public/index.html 2>/dev/null || { echo "   MISSING zashboard dist"; exit 1; }
echo "   assets: $(ls -1 $HY/panel/public/assets 2>/dev/null | wc -l) files"

echo
echo "=== E. systemd unit (gateway keeps listening on 127.0.0.1 only) ==="
cat > /etc/systemd/system/hyexit-panel.service <<EOF
[Unit]
Description=hyexit control panel - TOTP gateway + zashboard (127.0.0.1 only)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=/opt/hyexit/panel
ExecStart=$NODE /opt/hyexit/panel/server.mjs
Restart=always
RestartSec=5
StandardOutput=append:/opt/hyexit/logs/panel.log
StandardError=append:/opt/hyexit/logs/panel.log

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable hyexit-panel.service 2>&1 | sed 's/^/   /'

echo
echo "=== F. nginx vhost (hidden entry: https://$PANEL_HOST:$PANEL_PORT/clashConfiguePage) ==="
cat > "$NGINX_CONF_DIR/zz-hyexit-panel.conf" <<EOF
# hyexit control panel - hidden entry on a non-standard port, TOTP gated.
# Everything outside the gateway returns a bare 404 when unauthenticated.
server {
    listen $PANEL_PORT ssl;
    listen [::]:$PANEL_PORT ssl;
    http2 on;
    server_name $PANEL_HOST;

    ssl_certificate     $TLS_CERT;
    ssl_certificate_key $TLS_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:HYEXIT:5m;
    ssl_session_timeout 1h;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header X-Frame-Options DENY always;

    access_log $HY/logs/panel-access.log;
    client_max_body_size 2m;
    server_tokens off;

    location / {
        proxy_pass http://127.0.0.1:19121;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$http_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
EOF
echo "   wrote $NGINX_CONF_DIR/zz-hyexit-panel.conf"

echo
echo "=== G. nginx config test (auto-rollback on failure) ==="
if ! nginx -t >/dev/null 2>&1; then
  nginx -t 2>&1 | sed 's/^/   /'
  echo "   NGINX TEST FAILED - removing vhost"; rm -f "$NGINX_CONF_DIR/zz-hyexit-panel.conf"; exit 1
fi
systemctl reload nginx && echo "   nginx reloaded"

echo
echo "=== H. firewall ==="
if command -v ufw >/dev/null 2>&1; then
  ufw allow $PANEL_PORT/tcp comment 'hyexit panel' 2>&1 | tail -1 | sed 's/^/   /'
  ufw status | grep -E "$PANEL_PORT" | sed 's/^/   /'
else
  echo "   ufw not present - open $PANEL_PORT/tcp in your own firewall"
fi

echo
echo "=== I. start panel ==="
systemctl restart hyexit-panel.service
sleep 3
echo "   active=$(systemctl is-active hyexit-panel.service)"
tail -4 $HY/logs/panel.log | sed 's/^/   /'
echo "   listening: $(ss -tlnp | grep 19121 | wc -l) socket(s) on 19121"
echo "   public listener: $(ss -tlnp | grep ":$PANEL_PORT" | wc -l) socket(s) on $PANEL_PORT"

echo
echo "=== J. local smoke test (through nginx, from the server itself) ==="
echo -n "   GET /clashConfiguePage -> HTTP "
curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1:$PANEL_PORT/clashConfiguePage" -H "Host: $PANEL_HOST"
echo -n "   GET /  (unauthenticated)  -> HTTP "
curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1:$PANEL_PORT/" -H "Host: $PANEL_HOST"
echo -n "   GET /proxies (unauthenticated) -> HTTP "
curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1:$PANEL_PORT/proxies" -H "Host: $PANEL_HOST"
echo -n "   login page contains form: "
curl -sk "https://127.0.0.1:$PANEL_PORT/clashConfiguePage" -H "Host: $PANEL_HOST" | grep -c "clashConfiguePage/login"

echo
echo "=== K. DNS: does the hidden hostname resolve? ==="
getent ahostsv4 $PANEL_HOST | head -2 | sed 's/^/   /'

echo
echo "=== DONE (panel phase) ==="
echo "ENTRY=https://$PANEL_HOST:$PANEL_PORT/clashConfiguePage"
echo "TOTP_SECRET=$SECRET"
