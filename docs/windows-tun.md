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

### The fix — and the trap in the obvious version (corrected 2026-09-29)

**The obvious fix is wrong when this host is also an exit node.** `PROCESS-NAME,tailscaled.exe,DIRECT`
cannot tell the two jobs apart: the same `tailscaled` process both talks to Tailscale's own
infrastructure *and* forwards other tailnet devices' traffic to the internet. Allow it by process and
you allow the exit node too — it silently stops using the proxy, which is the whole point of the
machine. Matching on source address does not work either: a Clash TUN normalises the source IP to its
own gateway address (`198.18.0.1`; measured on 38/38 live connections).

**So match on destination only:**

```yaml
- IP-CIDR,100.64.0.0/10,DIRECT          # tailnet range
- DOMAIN-SUFFIX,tailscale.com,DIRECT    # control plane + DERP (443)
- DOMAIN-SUFFIX,tailscale.io,DIRECT
- DST-PORT,3478,DIRECT                  # STUN (decides the advertised endpoint)
- DST-PORT,41641,DIRECT                 # WireGuard direct data path
```

Exit-node traffic targets arbitrary public addresses, so it cannot match any of these and keeps
following `MATCH -> proxy`. **The two requirements cannot conflict by construction** — there is no
rule ordering to gamble on. (MagicDNS needs no rule of its own: it resolves into `100.64.0.0/10`.)

**Where to put them, if you use Clash Verge — two traps:**

1. **The global Merge is a deep-merge template; `prepend-rules` is silently ignored there.** Written
   into `profiles/Merge.yaml`, it lands in the generated config as an unknown *top-level key*
   (`prepend-rules` appears in the top-level key list) while `rules:` stays untouched — and the core
   ignores unknown top-level keys. Put the rules in the **global script** `profiles/Script.js`
   instead, where `main(config)` can do `config.rules = extra.concat(config.rules || [])`.
2. **A generated config is not a loaded config.** The config was regenerated at 17:31:03 (with the
   rules) and the service started the core at 17:31:04 — yet `GET /rules` still reported the old
   count. There is no way around the GUI: the core's home lives under the service account, is not
   writable by a normal user, and `PUT /configs` rejects paths outside it. **Re-apply in the GUI**
   (click the profile card, or fully quit including the tray and reopen).

**Before / after (same host, same day, one core restart apart):**

| Metric | Before | After |
|---|---|---|
| rules in the running core | 518 | **523** (5 extra, first in the list) |
| `netcheck` `IPv4:` | the proxy node's address | **the carrier's real public IP** |
| `Nearest DERP` | Los Angeles / Tokyo (both detours) | **a self-hosted relay** |
| path to an on-LAN peer | `via DERP`, 490–900 ms | **`direct`, 10–114 ms** |

**One-line self-check:** run `tailscale netcheck` — if the `IPv4:` mapping is not your carrier's real
public IP, Tailscale is still being proxied.

`tools/tailscale-direct.mjs` implements all of this: `install` writes the rules into the global
script (simulating them against the real config first, and refusing to write if the result
misbehaves), and `verify [peer]` asserts that the rules are live in the *running* core and that the
peer is direct rather than relayed.

**Residual (cosmetic, same-LAN only):** even when fixed, an on-LAN peer may still be reached through
the *public* endpoint (10–114 ms, jittery) rather than the LAN one, although both sides advertise
`192.168.x.x:41641`. On iOS 14+ an app needs the **Local Network** permission to send to LAN
addresses at all, while a public IP needs no such permission — hence "works, but the long way round".
Granting it brings the same-Wi-Fi case down to single-digit ms; campus and cellular are unaffected.

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
