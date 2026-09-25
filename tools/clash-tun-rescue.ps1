# clash-tun-rescue.ps1 - diagnose / repair Clash Verge TUN mode on Windows.
#
# Why this exists: TUN mode adds a VIRTUAL adapter plus a default route on the host. If the
# core process exits, Windows removes the adapter and its routes and your real NIC takes over
# again automatically. If the core merely HANGS (process alive, not forwarding), the adapter and
# its default route stay and every packet is swallowed -> "no internet". This script detects both
# cases and, with -Fix, restores normal connectivity WITHOUT needing working DNS or the internet.
#
# Usage (run as Administrator for -Fix / -Install):
#   powershell -NoProfile -ExecutionPolicy Bypass -File clash-tun-rescue.ps1            # report only
#   powershell -NoProfile -ExecutionPolicy Bypass -File clash-tun-rescue.ps1 -Fix       # repair
#   powershell -NoProfile -ExecutionPolicy Bypass -File clash-tun-rescue.ps1 -Install   # + watchdog task (every 2 min)
#   powershell -NoProfile -ExecutionPolicy Bypass -File clash-tun-rescue.ps1 -Uninstall # remove the task
#
# PURE ASCII ONLY (Windows PowerShell 5.1 decodes BOM-less files as the system ANSI codepage).
[CmdletBinding()]
param(
    [switch]$Fix,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Auto,                       # used by the scheduled task: quiet unless it acts
    [int]$Port = 0,                      # controller port override
    [string]$AdapterName = '',           # explicit target adapter (bypasses auto-detection)
    # NOTE ON DETECTION: on Windows every WireGuard-family virtual NIC is a TUN device built on the
    # same Wintun driver, so the NAME is not a reliable discriminator ("optun" contains "tun" and
    # Tailscale is a TUN too). Clash's own adapter is identified by its description "Meta Tunnel",
    # and this script refuses to touch anything described as "WireGuard Tunnel"/"Tailscale Tunnel"
    # unless you name it explicitly with -AdapterName.
    [string]$AdapterPattern = '^(Mihomo|Clash|Meta)',
    [string]$CorePattern = 'verge-mihomo|^mihomo$|clash-meta|clash-win64|sing-box',
    [int]$SetTunMetric = 0,              # >0: pin the Clash TUN interface metric (multi-NIC safety)
    [switch]$ResetSystemProxy,           # force ProxyEnable=0 (persistent registry dead-pointer)
    [switch]$CleanFirewall               # remove leftover clash/mihomo firewall rules (strict-route)
)

$ErrorActionPreference = 'Continue'
$LogFile = Join-Path $env:TEMP 'clash-tun-rescue.log'
$TaskName = 'ClashTunRescue'

function Say([string]$msg, [string]$level = 'info') {
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$stamp][$level] $msg"
    if (-not $Auto -or $level -ne 'info') { Write-Host $line }
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
}
function Is-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- probe helpers
function Get-AllTunFamily {
    # every WireGuard-family virtual NIC is a TUN device; show them all so the report is honest
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match 'Tunnel' -or $_.DriverDescription -match 'Wintun' }
}
function Get-TunAdapter {
    if ($AdapterName) {
        return (Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue)
    }
    Get-AllTunFamily |
        Where-Object {
            # Clash's adapter: description "Meta Tunnel" (mihomo), or an explicit name match
            ($_.InterfaceDescription -match 'Meta Tunnel') -or ($_.Name -cmatch $AdapterPattern)
        } |
        Where-Object { $_.InterfaceDescription -notmatch 'WireGuard Tunnel|Tailscale Tunnel' } |
        Select-Object -First 1
}
function Test-ForeignTun($adapterObj) {
    # true when this adapter belongs to somebody else (a plain WireGuard tunnel or Tailscale)
    if (-not $adapterObj) { return $false }
    if ($AdapterName) { return $false }   # the user named it explicitly: their call
    return ($adapterObj.InterfaceDescription -match 'WireGuard Tunnel|Tailscale Tunnel')
}
function Get-CoreProcess {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $CorePattern }
}
function Get-ManagerProcess {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^(clash-verge|clash-verge-service)$' }
}
function Get-ControllerPort {
    if ($Port -gt 0) { return $Port }
    $candidates = @()
    $cfgDirs = @(
        (Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'),
        (Join-Path $env:APPDATA 'clash-verge'),
        (Join-Path $env:LOCALAPPDATA 'io.github.clash-verge-rev.clash-verge-rev')
    )
    foreach ($d in $cfgDirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $f = Get-ChildItem -LiteralPath $d -Filter '*.yaml' -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match 'verge|config|runtime|mihomo|clash' }
        foreach ($file in $f) {
            $m = Select-String -LiteralPath $file.FullName -Pattern '^\s*external-controller:\s*([^\s]+)' -ErrorAction SilentlyContinue |
                 Select-Object -First 1
            if ($m) {
                $v = $m.Matches[0].Groups[1].Value
                if ($v -match ':(\d+)\s*$') { $candidates += [int]$Matches[1] }
            }
        }
    }
    $candidates += 15120, 9090
    foreach ($p in ($candidates | Select-Object -Unique)) { if ($p -gt 0) { return $p } }
    return 15120
}
function Test-Controller([int]$p) {
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$p/version" -TimeoutSec 3 -ErrorAction Stop
        if ($r) { return $true }
    } catch { }
    # fall back to a plain TCP connect: proves the listener is alive
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect('127.0.0.1', $p); $ok = $c.Connected; $c.Close()
        return $ok
    } catch { return $false }
}
function Test-RawInternet {
    # IP literal, no DNS involved - must work even when name resolution is broken
    foreach ($target in @(@('223.5.5.5', 443), @('1.1.1.1', 443), @('119.29.29.29', 53))) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $iar = $c.BeginConnect($target[0], $target[1], $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(2500) -and $c.Connected) { $c.Close(); return $target[0] }
            $c.Close()
        } catch { }
    }
    return $null
}
function Test-Dns {
    try { $r = Resolve-DnsName -Name 'www.baidu.com' -Type A -QuickTimeout -ErrorAction Stop
          if ($r) { return ($r | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress } } catch { }
    return $null
}
function Get-DefaultRouteVia([int]$ifIndex) {
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.ifIndex -eq $ifIndex }
}
function Get-PhysicalDefaultRoute {
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notmatch $AdapterPattern -and $_.InterfaceAlias -ne $adapterName }
}
function Get-RouteRace {
    # Which adapter actually wins the default route, and is the margin thin enough to flip?
    $rows = @()
    foreach ($r in (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
        $a = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue
        $im = (Get-NetIPInterface -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
        $rows += [pscustomobject]@{
            ifIndex = $r.ifIndex; Alias = $r.InterfaceAlias; Desc = $(if ($a) { $a.InterfaceDescription } else { '' })
            RouteMetric = $r.RouteMetric; IfMetric = $im
            Effective = $(if ($im) { [int]$r.RouteMetric + [int]$im } else { [int]$r.RouteMetric })   # lower wins
        }
    }
    , ($rows | Sort-Object Effective)
}

# ---------------------------------------------------------------- report
$adapter   = Get-TunAdapter
$core      = Get-CoreProcess
$ctrlPort  = Get-ControllerPort
$ctrlOK    = $false
if ($ctrlPort) { $ctrlOK = Test-Controller $ctrlPort }
$tunRoute  = $null
if ($adapter) { $tunRoute = Get-DefaultRouteVia $adapter.ifIndex }
$physRoute = Get-PhysicalDefaultRoute
$race      = Get-RouteRace
$allTun    = Get-AllTunFamily
$rawOK     = Test-RawInternet
$dnsIP     = Test-Dns
$sysProxy  = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue)
$sysProxyOn = ($sysProxy.ProxyEnable -eq 1)

# verdict
$state = 'UNKNOWN'
if ($adapter -and $tunRoute -and -not ($core) )            { $state = 'ORPHAN-TUN' }      # adapter left, core gone
elseif ($adapter -and $tunRoute -and -not $ctrlOK)          { $state = 'CORE-HUNG' }      # adapter+route, core not answering
elseif ($adapter -and $tunRoute -and $ctrlOK -and $rawOK)   { $state = 'HEALTHY' }
elseif (-not $adapter -and $rawOK)                          { $state = 'TUN-OFF-DIRECT' }
elseif (-not $rawOK -and -not $adapter)                     { $state = 'NO-TUN-NO-NET' }  # real NIC problem, not TUN
else                                                        { $state = 'PARTIAL' }

Say "report: state=$state adapter=$(if($adapter){$adapter.Name + ' (if ' + $adapter.ifIndex + ')'}else{'none'}) core=$(if($core){($core.ProcessName -join ',')}else{'none'}) manager=$(if(Get-ManagerProcess){'up'}else{'down'}) controller=127.0.0.1:$ctrlPort responsive=$ctrlOK"
Say "report: tunDefaultRoute=$(if($tunRoute){'yes'}else{'no'}) physicalDefaultRoute=$(if($physRoute){($physRoute.InterfaceAlias -join ',')}else{'NONE'}) rawTCP=$rawOK dns=$dnsIP sysProxy=$sysProxyOn admin=$(Is-Admin)"

if (-not $Auto) {
    Write-Host ''
    Write-Host "state              : $state"
    Write-Host "TUN adapter        : $(if($adapter){$adapter.Name + ' ifIndex=' + $adapter.ifIndex + ' status=' + $adapter.Status}else{'not present'})"
    Write-Host "core process       : $(if($core){($core | ForEach-Object { $_.ProcessName + '#' + $_.Id }) -join ', '}else{'not running'})"
    Write-Host "controller :$ctrlPort : $(if($ctrlOK){'responding'}else{'NOT responding'})"
    Write-Host "default route via  : $(if($tunRoute){'TUN (traffic is captured)'}else{'physical NIC'})"
    Write-Host "physical fallback  : $(if($physRoute){($physRoute.InterfaceAlias -join ', ')}else{'MISSING (that is a real problem)'})"
    Write-Host "raw TCP (no DNS)   : $(if($rawOK){"OK via $rawOK"}else{'FAILED'})"
    Write-Host "DNS resolution     : $(if($dnsIP){$dnsIP}else{'FAILED'})"
    Write-Host ''
    Write-Host "default-route race (lower effective metric wins; the winner carries your traffic):"
    foreach ($r in $race) {
        $mark = if ($r.Effective -eq $race[0].Effective) { '  <== winner' } else { '' }
        $eff = if ($r.IfMetric) { "$($r.Effective)" } else { 'auto' }
        Write-Host ("  {0,-28} desc={1,-24} routeMetric={2} ifMetric={3} effective={4}{5}" -f $r.Alias, $r.Desc, $r.RouteMetric, $(if ($r.IfMetric) { $r.IfMetric } else { 'auto' }), $eff, $mark)
    }
    $foreign = $allTun | Where-Object { $_.InterfaceDescription -match 'WireGuard Tunnel|Tailscale Tunnel' }
    if ($foreign) {
        Write-Host ''
        Write-Host "other TUN devices on this machine (this script will NEVER touch them):"
        foreach ($t in $foreign) { Write-Host ("  {0,-12} {1}" -f $t.Name, $t.InterfaceDescription) }
    }
    # Firewall rules are PERSISTENT config (unlike the virtual adapter), so with strict-route: true a
    # hard crash can leave Block rules behind that keep DNS broken even after TUN is gone.
    $fw = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'clash|mihomo|verge|Meta Tunnel' }
    if ($fw) {
        Write-Host ''
        Write-Host "firewall rules owned by the proxy (persistent; Block+Outbound ones are the dangerous leftovers):"
        foreach ($r in $fw) { Write-Host ("  {0,-22} {1,-9} {2,-9} enabled={3} profile={4}" -f $r.DisplayName, $r.Direction, $r.Action, $r.Enabled, $r.Profile) }
        $bad = $fw | Where-Object { $_.Action -eq 'Block' }
        if ($bad) { Write-Host ("  -> {0} Block rule(s) present: if TUN is off and DNS is broken, run -CleanFirewall" -f $bad.Count) }
    }
    Write-Host "system proxy       : $(if($sysProxyOn){$sysProxy.ProxyServer}else{'off'})"
    Write-Host ''
}

# ---------------------------------------------------------------- repair
function Remove-LefoverTun {
    param($adapterObj, $tunRouteObj)
    if (-not (Is-Admin)) { Say 'repair needs Administrator; skipping privileged steps' 'warn'; return $false }
    if (Test-ForeignTun $adapterObj) {
        Say ("REFUSING to touch '$($adapterObj.Name)' ($($adapterObj.InterfaceDescription)): that is not Clash's tunnel. Use -AdapterName if you really mean it.") 'warn'
        return $false
    }
    $did = $false
    if ($tunRouteObj) {
        Say "removing leftover default route via $($adapterObj.Name) (this alone restores direct egress)"
        Remove-NetRoute -ifIndex $adapterObj.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
        $did = $true
    }
    if (-not (Get-CoreProcess)) {
        Say "no core process: removing orphan adapter $($adapterObj.Name)"
        Remove-NetAdapter -Name $adapterObj.Name -Confirm:$false -ErrorAction SilentlyContinue
        $did = $true
    }
    return $did
}

$acted = $false
if ($Fix -or $Auto) {
    switch ($state) {
        'CORE-HUNG' {
            $strikes = 0
            if ($Auto) {
                $sf = Join-Path $env:TEMP 'clash-tun-rescue.strikes'
                if (Test-Path -LiteralPath $sf) { $strikes = [int](Get-Content -LiteralPath $sf -Raw) }
                $strikes++
                Set-Content -LiteralPath $sf -Value $strikes -Encoding ASCII
                Say "core not responding (strike $strikes/3)" 'warn'
                if ($strikes -lt 3) { break }   # a single stall is normal (node switching, reload)
            }
            Say 'core is hung: killing it so the manager can restart it' 'warn'
            if (Is-Admin) { $core | ForEach-Object { try { Stop-Process -Id $_.Id -Force } catch { } } }
            Start-Sleep -Seconds 6
            $core2 = Get-CoreProcess
            $ctrl2 = if ($ctrlPort) { Test-Controller $ctrlPort } else { $false }
            Say "after kill: core=$(if($core2){'restarted'}else{'still down'}) controller=$ctrl2"
            if (-not $ctrl2) {
                Say 'core did not come back: removing the TUN default route so the host uses the physical NIC' 'warn'
                Remove-LefoverTun -adapterObj (Get-TunAdapter) -tunRouteObj $tunRoute | Out-Null
            }
            $acted = $true
            if (Test-Path -LiteralPath (Join-Path $env:TEMP 'clash-tun-rescue.strikes')) { Remove-Item -LiteralPath (Join-Path $env:TEMP 'clash-tun-rescue.strikes') -Force -ErrorAction SilentlyContinue }
        }
        'ORPHAN-TUN' {
            Say 'orphan TUN adapter/route detected' 'warn'
            Remove-LefoverTun -adapterObj $adapter -tunRouteObj $tunRoute | Out-Null
            $acted = $true
        }
        'HEALTHY' {
            $sf = Join-Path $env:TEMP 'clash-tun-rescue.strikes'
            if (Test-Path -LiteralPath $sf) { Remove-Item -LiteralPath $sf -Force -ErrorAction SilentlyContinue }
            if (-not $Auto) { Say 'healthy: nothing to do' }
        }
        'TUN-OFF-DIRECT' {
            if (-not $Auto) { Say 'TUN is off and the physical NIC is carrying traffic: nothing to do' }
        }
        'NO-TUN-NO-NET' {
            Say 'no TUN and no connectivity either: this is NOT a TUN problem (check Wi-Fi/DHCP/router)' 'warn'
        }
        default {
            if ($sysProxyOn -and -not (Get-CoreProcess)) {
                Say 'system proxy is enabled but no core is running: turning the system proxy off' 'warn'
                Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0
                $acted = $true
            } elseif (-not $Auto) { Say "partial state ($state): see the report above" 'warn' }
        }
    }
}

# ---------------------------------------------------------------- optional: pin the TUN metric
if ($SetTunMetric -gt 0) {
    if (-not (Is-Admin)) { Say 'setting the interface metric needs Administrator' 'warn' }
    elseif (-not $adapter) { Say 'no Clash TUN adapter found; nothing to pin' 'warn' }
    elseif (Test-ForeignTun $adapter) { Say 'refusing to change the metric of a foreign tunnel' 'warn' }
    else {
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -InterfaceMetric $SetTunMetric -ErrorAction SilentlyContinue
        $now = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).InterfaceMetric
        Say "Clash TUN ($($adapter.Name)) interface metric set to $now (guards against a physical NIC stealing the default route)"
        Write-Host "set: $($adapter.Name) interface metric = $now"
    }
}

# ---------------------------------------------------------------- explicit cleanups
if ($ResetSystemProxy) {
    $before = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyEnable
    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue
    Say "system proxy ProxyEnable: $before -> 0 (the value is persistent, so this is the only way back when no core is listening)"
    Write-Host 'system proxy disabled (ProxyEnable=0)'
}
if ($CleanFirewall) {
    if (-not (Is-Admin)) { Say 'cleaning firewall rules needs Administrator' 'warn' }
    else {
        $fw = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'clash|mihomo|verge|Meta Tunnel' }
        if (-not $fw) { Say 'no proxy-owned firewall rules found' }
        foreach ($r in $fw) {
            Say "removing firewall rule '$($r.DisplayName)' ($($r.Direction)/$($r.Action))"
            try { Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop } catch { Say "could not remove $($r.DisplayName): $($_.Exception.Message)" 'warn' }
        }
        $left = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'clash|mihomo|verge|Meta Tunnel' }
        Say "firewall rules left: $((($left | Measure-Object).Count))"
        Write-Host "leftover proxy firewall rules removed: $((($fw | Measure-Object).Count))"
    }
}

# ---------------------------------------------------------------- verify after repair
if ($acted) {
    Start-Sleep -Seconds 3
    $raw2 = Test-RawInternet
    $dns2 = Test-Dns
    Say "verify: rawTCP=$raw2 dns=$dns2"
    if (-not $Auto) {
        Write-Host "after repair: raw TCP = $(if($raw2){"OK via $raw2"}else{'FAILED'}) ; DNS = $(if($dns2){$dns2}else{'FAILED'})"
        if (-not $raw2) { Write-Host 'STILL DOWN -> this is not (only) a Clash problem: check Wi-Fi, DHCP and the router.' }
    }
}

# ---------------------------------------------------------------- watchdog task
if ($Install) {
    if (-not (Is-Admin)) { Say 'installing the scheduled task needs Administrator' 'warn'; exit 1 }
    $self = $MyInvocation.MyCommand.Path
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Auto' -f $self)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 2)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Say "scheduled task '$TaskName' installed (every 2 minutes, SYSTEM, 3-strike, log: $LogFile)"
    Write-Host "installed. check later with: Get-ScheduledTask -TaskName $TaskName ; Get-Content `"$LogFile`" -Tail 20"
}
if ($Uninstall) {
    if (-not (Is-Admin)) { Say 'removing the scheduled task needs Administrator' 'warn'; exit 1 }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Say "scheduled task '$TaskName' removed"
}
