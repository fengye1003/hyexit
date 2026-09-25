# Windows: running a Clash TUN permanently, and what that breaks

This is the other half of the project. On the Linux VPS the constraint was "**never** touch the host's
routing". On a domestic Windows workstation the trade-off flips: the user turned Clash Verge's **TUN
mode on permanently** because domestic traffic then goes out natively instead of detouring through a
foreign exit node — measurably faster everywhere, 4K streaming included. What follows is what that
choice does to the machine, and the traps that come with it.

## Crash radius: a dead core self-heals, a hung core black-holes

TUN mode only makes three system-level changes: it creates a virtual adapter (Wintun), adds a default
route through it, and sets a fake-IP DNS server on that adapter. **The physical NIC's IP, gateway,
DNS and metric are left alone.**

| Failure | What is left behind | Result |
|---|---|---|
| core process **exits** | the Wintun adapter dies with the process handle, its route goes with it | **self-heals**: traffic falls back to the physical NIC and the ISP resolver |
| core **hangs** (alive, not forwarding) | adapter *and* its default route survive | **black hole** — the one case worth defending against |
| power loss / hard reset | virtual adapter does not come back, no persistent routes | clean boot |

The only leftovers are firewall rules, and only if `strict-route: true` (those are the "DNS stays broken
after Clash died" reports). Never reach for `netsh winsock reset` — it is not needed here and it wipes
good state.

**The real danger is not the crash, it's state that persists.** Compare:

| Setting | Flipped to | State | Consequence |
|---|---|---|---|
| `enable_system_proxy` | `true` | registry `ProxyEnable` — **persistent** | when the core dies, every proxy-aware app points at a dead port: "the network is fine but the browser can't load anything"; combined with `auto_launch: false` it **survives a reboot** |
| `strict-route` | `true` | **firewall rules** — persistent | leftover Block rules keep DNS broken with TUN off; known to break virtual networking (VirtualBox is called out in the mihomo docs — relevant when VMware/Hyper-V/WSL are present) |
| `ipv6` | `true` | runtime | harmless without real IPv6; with half-working IPv6, Happy Eyeballs stalls page loads for seconds |
| `auto_launch` / `silent_start` | `false` | nothing | harmless alone; fatal only in combination with the first row |

## The default-route race (silent bypass)

TUN mode works by capturing `0.0.0.0/0`. Windows compares route metric first, then **interface metric**
(lower wins):

```
default-route race (lower effective metric wins)
  Mihomo   desc=Meta Tunnel          routeMetric=0  ifMetric=auto  <== winner
  WLAN     desc=Intel Wi-Fi 7 BE201  routeMetric=0  ifMetric=35
```

Clash's TUN interface metric is `auto` unless you pin it. Plug in Ethernet, add a NIC or install
another VPN and the winner can change. Two failure modes follow: a physical NIC wins and the **proxy
silently stops applying** (traffic still flows, so only an exit-IP check reveals it), or another
full-tunnel TUN wins and the two fight.

Pin it: `Set-NetIPInterface -InterfaceIndex <tun> -InterfaceAddressFamily IPv4 -InterfaceMetric 1`,
and keep an eye on "who wins the default route" as a routine health check.

## TUN vs Tailscale: does it force relays?

Measured on a LAN whose peer was reachable directly: **the peer stayed direct** (no `via DERP`). But the
routing table tells a different story than you would expect:

```
Find-NetRoute <peer endpoint> -> InterfaceAlias = Mihomo
```

The peer's address was outside the host's on-link subnet, so it followed the default route **into the
TUN** and only stayed direct because a rule said `IP-CIDR,172.16.0.0/12,DIRECT`. In other words: not
"bypassing the TUN", but "entering the TUN and being released as direct". Delete that private-range rule
and the same connection turns into "WireGuard over a proxy node" (most nodes do not relay UDP) and falls
back to a relay.

**The real damage is that STUN gets proxied too.** Evidence chain:

| Measurement | Value |
|---|---|
| `tailscale netcheck` STUN mapping IP | address A |
| exit IP of an ordinary foreign request (proxied) | address A — identical |
| exit IP of a request matched by the direct rules | address B (the real home IP) |
| DERP latencies | 300–470 ms, including a self-hosted relay in HK that should be ~40 ms |

So Tailscale advertises **the proxy node's NAT mapping** as its own candidate endpoint. Remote peers
cannot reach it → relay. This is the root cause behind "as soon as I enabled TUN, Tailscale got slower".

Fix (three rules prepended to the merged config):

```yaml
- PROCESS-NAME,tailscaled.exe,DIRECT
- DOMAIN-SUFFIX,tailscale.com,DIRECT   # DERP / STUN / control plane
- DOMAIN-SUFFIX,ts.net,DIRECT          # MagicDNS zone
```

The trade-off is that Tailscale's control-plane traffic no longer travels through the proxy.
(`PROCESS-NAME` needs process lookup enabled in the core.)

## TUN also hijacks your own ops links

With TUN on, `ssh` from this machine to your own VPS's **public** IP followed the default route into the
TUN, went out through a proxy node, and the server dropped the connection during key exchange:

```
kex_exchange_identification: Connection closed by remote host
```

`fail2ban` showed zero bans, so it was not a block list: most likely a shared proxy-node IP tripping
sshd's per-source connection limits. Diagnose with
`Find-NetRoute -RemoteIPAddress <target>` — if it says Mihomo, that is your answer. Fix by making your
own servers `DIRECT` (or by reaching them over the tailnet). **A proxy changes more than "your
browsing": it changes your ops, backup and sync paths too.**

## Port reservation: "free" does not mean you can bind it

Trying to serve a panel on a port that was free by every check, `listen()` failed with `EACCES`. The
port sat inside a Hyper-V/winnat *excluded* range — not "in use", but reserved by the system, which
also rejects explicit binds.

```powershell
netsh int ipv4 show excludedportrange protocol=tcp
netsh int ipv4 add excludedportrange protocol=tcp startport=3000 numberofports=1 store=persistent
# if winnat still holds it:
net stop winnat ; <the netsh line above> ; net start winnat
```

Afterwards the range list shows `3000  3000  *` (administratively reserved, survives reboots). Stopping
winnat briefly blips WSL/container networking — that is the only cost.

## Health check / rescue tool

`tools/clash-tun-rescue.ps1` is a zero-dependency PowerShell script (pure ASCII, PS 5.1 compatible):

```powershell
powershell -File clash-tun-rescue.ps1                  # read-only report
powershell -File clash-tun-rescue.ps1 -Fix             # kill a hung core; drop a leftover TUN route
powershell -File clash-tun-rescue.ps1 -Install         # 2-minute watchdog task (3 strikes before acting)
powershell -File clash-tun-rescue.ps1 -SetTunMetric 1  # pin the TUN's interface metric
powershell -File clash-tun-rescue.ps1 -ResetSystemProxy -CleanFirewall
```

It prints the default-route race, lists every TUN-family adapter, and — importantly — **identifies the
adapters by ownership, not by name**: on Windows every WireGuard-family virtual NIC is a TUN built on
the same Wintun driver, so `optun` and `Tailscale` are TUNs too. The script only ever touches the one
described as `Meta Tunnel` (Clash) and refuses anything described as `WireGuard Tunnel` or
`Tailscale Tunnel` unless you name it explicitly with `-AdapterName`.
