#!/bin/bash
# 10-snapshot-install.sh - snapshot current state, then install mihomo + geo data + panel frontend.
# Idempotent. Pure ASCII. No changes to existing services.
set -u
TS=$(date +%Y%m%d-%H%M%S)
BK=/root/hyexit-backup-$TS
HY=/opt/hyexit
MIHOMO_VER=v1.19.31
ZASH_VER=v3.29.1

echo "=== STEP 1: snapshot -> $BK ==="
mkdir -p "$BK"
tar czf "$BK/nginx-vhosts.tgz" /etc/nginx/conf.d 2>/dev/null
cp -a /etc/ufw/user.rules "$BK/ufw-user.rules" 2>/dev/null
ufw status verbose > "$BK/ufw-status.txt" 2>&1
ip rule show > "$BK/ip-rule-v4.txt" 2>&1
ip -6 rule show > "$BK/ip-rule-v6.txt" 2>&1
ip route show table all > "$BK/ip-route-all.txt" 2>&1
iptables-save > "$BK/iptables-save.txt" 2>&1
nft list ruleset > "$BK/nft-ruleset.txt" 2>&1
sysctl -a > "$BK/sysctl-all.txt" 2>&1
tailscale debug prefs > "$BK/tailscale-prefs.json" 2>&1
tailscale status > "$BK/tailscale-status.txt" 2>&1
systemctl list-units --type=service > "$BK/services.txt" 2>&1
ss -tulpn > "$BK/listeners.txt" 2>&1
ls -l /dev/net/tun > "$BK/tun.txt" 2>&1
echo "snapshot files:"; ls -1 "$BK" | sed 's/^/   /'

echo
echo "=== STEP 2: directories ==="
mkdir -p $HY/bin $HY/config $HY/providers $HY/panel/public $HY/state $HY/logs $HY/ruleset
chmod 700 $HY/state
ls -ld $HY $HY/*

echo
echo "=== STEP 3: mihomo kernel $MIHOMO_VER ==="
if [ -x $HY/bin/mihomo ]; then
  echo "already installed: $($HY/bin/mihomo -v 2>&1 | head -1)"
else
  cd /tmp
  rm -f mihomo.gz
  curl -sL --max-time 300 -o mihomo.gz "https://github.com/MetaCubeX/mihomo/releases/download/$MIHOMO_VER/mihomo-linux-amd64-compatible-$MIHOMO_VER.gz" -w "download http=%{http_code} bytes=%{size_download} time=%{time_total}s\n"
  gunzip -f mihomo.gz
  mv -f mihomo $HY/bin/mihomo
  chmod 755 $HY/bin/mihomo
  echo "installed: $($HY/bin/mihomo -v 2>&1 | head -1)"
fi

echo
echo "=== STEP 4: geo data ==="
for f in geoip.dat geosite.dat country.mmdb; do
  if [ -s $HY/config/$f ]; then echo "  have $f ($(stat -c%s $HY/config/$f) bytes)"; continue; fi
  curl -sL --max-time 300 -o $HY/config/$f "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/$f" -w "  $f http=%{http_code} bytes=%{size_download}\n"
done
ls -l $HY/config

echo
echo "=== STEP 5: zashboard frontend $ZASH_VER ==="
if [ -f $HY/panel/public/index.html ]; then
  echo "already installed"
else
  cd /tmp
  rm -rf zash zash.zip
  curl -sL --max-time 300 -o zash.zip "https://github.com/Zephyruso/zashboard/releases/download/$ZASH_VER/dist-no-fonts.zip" -w "download http=%{http_code} bytes=%{size_download}\n"
  mkdir -p zash && cd zash && unzip -oq ../zash.zip && cd /tmp
  # find index.html root
  IDX=$(find /tmp/zash -name index.html | head -1)
  if [ -z "$IDX" ]; then echo "ERROR: index.html not found in dist"; else
    SRC=$(dirname "$IDX")
    cp -a "$SRC"/. $HY/panel/public/
    echo "installed from $SRC"
  fi
  ls -1 $HY/panel/public | head -20
fi

echo
echo "=== STEP 6: node availability ==="
NODE=$(command -v node)
# if node is not on PATH, look for a versioned runtime under any panel/node prefix
[ -z "$NODE" ] && NODE=$(ls -1d /opt/*/nodejs/v*/bin/node /usr/local/*/bin/node 2>/dev/null | sort -V | tail -1)
echo "NODE=$NODE"
"$NODE" -v 2>&1

echo
echo "=== STEP 7: verify nothing changed in running services ==="
for s in nginx tailscaled ssh; do printf "  %-10s %s\n" "$s" "$(systemctl is-active $s 2>&1)"; done
echo "  ip rule count: $(ip rule show | wc -l)"
echo
echo "=== DONE (install phase) ==="
echo "BACKUP_DIR=$BK"
