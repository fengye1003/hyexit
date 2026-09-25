# install.ps1 - deploy the ClashDashboard gateway as a boot-started Windows service-like task.
#
# MUST RUN AS ADMINISTRATOR. It does four things:
#   1. reserves TCP 3000 so Windows/Hyper-V can never hand it to something else;
#   2. opens the firewall for the LAN and the tailnet only;
#   3. registers a scheduled task that starts the gateway at boot (as SYSTEM, so no login needed);
#   4. starts it and verifies the result end to end.
#
# PURE ASCII ONLY (Windows PowerShell 5.1 decodes BOM-less files as the system ANSI codepage).
[CmdletBinding()]
param(
    [int]$Port = 3000,
    [string]$Root = 'D:\ClashDashboard',
    [string]$LanCidr = '192.168.0.0/24',   # which LAN may reach the panel (tailnet 100.64.0.0/10 is always allowed)
    [switch]$NoVerify
)
$ErrorActionPreference = 'Continue'
$LogFile = Join-Path $Root 'logs\install.log'
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'logs') | Out-Null

function Say([string]$m, [string]$lvl = 'info') {
    $line = "[{0}][{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $lvl, $m
    Write-Host $line
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
}
function Is-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Test-Bind([int]$p) {
    $js = "const n=require('net');const s=n.createServer();s.on('error',e=>{console.log('FAIL '+e.code);process.exit(0)});s.listen($p,'0.0.0.0',()=>{console.log('OK');s.close()});"
    $tmp = Join-Path $env:TEMP ("bindtest-$p.js")
    Set-Content -LiteralPath $tmp -Value $js -Encoding ASCII
    $out = & $node $tmp 2>&1 | Out-String
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    return ($out -match 'OK')
}

Say "=== ClashDashboard install (port $Port, root $Root) ==="
if (-not (Is-Admin)) { Say 'NOT elevated: rerun this script from an Administrator PowerShell' 'error'; exit 1 }

# ---------------------------------------------------------------- 1. node + payload
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = 'C:\Program Files\nodejs\node.exe' }
if (-not (Test-Path $node)) { Say "node.exe not found (looked at $node)" 'error'; exit 1 }
Say "node: $node ($(& $node -v))"
foreach ($f in @('server.mjs', 'public\index.html')) {
    if (-not (Test-Path (Join-Path $Root $f))) { Say "missing payload: $f" 'error'; exit 1 }
}
Say "payload ok: server.mjs + public/ present"

# ---------------------------------------------------------------- 2. config.json (absolute paths for SYSTEM)
$vergeCfg = Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml'
$cfgObj = [ordered]@{
    host          = '0.0.0.0'
    port          = $Port
    uiPath        = '/panel'
    token         = ''
    controller    = ''
    clashConfig   = $vergeCfg
    # keep these in the template: a re-run must never wipe the TOTP secret or the session key
    totpSecret    = ''
    sessionSecret = ''
    sessionDays   = 30
    lockFails     = 5
    lockMinutes   = 120
}
$cfgPath = Join-Path $Root 'config.json'
if (Test-Path $cfgPath) {
    Say 'config.json exists: keeping its values (edit it to change the token/secret/port)'
    $existing = (Get-Content -LiteralPath $cfgPath -Raw).TrimStart([char]0xFEFF) | ConvertFrom-Json
    foreach ($k in @('host', 'port', 'uiPath', 'token', 'controller', 'clashConfig',
                     'totpSecret', 'sessionSecret', 'sessionDays', 'lockFails', 'lockMinutes')) {
        if ($existing.PSObject.Properties.Name -contains $k -and $existing.$k -ne '' -and $null -ne $existing.$k) {
            $cfgObj[$k] = $existing.$k
        }
    }
    if ($existing.clashConfig) { $vergeCfg = $existing.clashConfig }
}
# always rewrite BOM-free: Node's JSON.parse throws on a UTF-8 BOM and PS 5.1's -Encoding UTF8 adds one
$json = $cfgObj | ConvertTo-Json
[System.IO.File]::WriteAllText($cfgPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Say ("config.json: port={0} uiPath={1} token={2} totp={3} clashConfig={4}" -f `
    $cfgObj.port, $cfgObj.uiPath, $(if ($cfgObj.token) { 'set' } else { 'none' }), `
    $(if ($cfgObj.totpSecret) { 'ENABLED' } else { 'none' }), $vergeCfg)
if (-not (Test-Path $vergeCfg)) { Say "WARNING: $vergeCfg not found - the gateway will report the controller as unreachable" 'warn' }

# state/ and logs/ are written by the SYSTEM-run task: give Users modify rights so the operator can
# clear a lockout or rotate a log without elevation
foreach ($d in @('state', 'logs')) {
    $dp = Join-Path $Root $d
    New-Item -ItemType Directory -Force -Path $dp | Out-Null
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')   # BUILTIN\Users
        $acl = Get-Acl -LiteralPath $dp
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        Set-Acl -LiteralPath $dp -AclObject $acl
        Say "acl: Users=Modify on $d\"
    } catch { Say "acl grant on $d\ failed: $($_.Exception.Message)" 'warn' }
}

# ---------------------------------------------------------------- 3. reserve the port
# Stop whatever holds the port FIRST. Otherwise our own previous instance makes the bind test fail
# and the log reads as if the port were still blocked by Hyper-V.
$owners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
foreach ($op in $owners) {
    if ($op -and $op -gt 0) { Say "stopping instance currently holding port $Port (pid $op)"; Stop-Process -Id $op -Force -ErrorAction SilentlyContinue }
}
if ($owners) { Start-Sleep -Seconds 2 }

Say "--- port reservation for tcp/$Port ---"
$excluded = (netsh int ipv4 show excludedportrange protocol=tcp) -join "`n"
$alreadyOurs = $excluded -match ("(?m)^\s*{0}\s+{0}\s+\*" -f $Port)
if ($alreadyOurs) {
    Say "tcp/$Port is already reserved by us (marked with *)"
} else {
    # native tools print localized text; normalize it so the log stays readable
    $null = netsh int ipv4 add excludedportrange protocol=tcp startport=$Port numberofports=1 store=persistent 2>&1
    if ($LASTEXITCODE -eq 0) { Say "reserved tcp/$Port (excludedportrange, persistent)" } else { Say "reserve attempt 1 failed (exit $LASTEXITCODE) - another process holds the range" 'warn' }
}
if (-not (Test-Bind $Port)) {
    Say "tcp/$Port is NOT bindable yet - it sits inside a range Hyper-V/winnat reserved." 'warn'
    Say 'restarting winnat so it re-picks its ranges and leaves our reservation alone (WSL/containers may blink)'
    $null = net stop winnat 2>&1
    Say "  winnat stopped (exit $LASTEXITCODE)"
    Start-Sleep -Seconds 2
    $null = netsh int ipv4 add excludedportrange protocol=tcp startport=$Port numberofports=1 store=persistent 2>&1
    Say "  reserve retry (exit $LASTEXITCODE)"
    $null = net start winnat 2>&1
    Say "  winnat started (exit $LASTEXITCODE)"
    Start-Sleep -Seconds 2
}
if (Test-Bind $Port) {
    Say "OK: tcp/$Port is bindable"
} else {
    Say "STILL not bindable. The reservation is persistent; a reboot normally clears it (winnat re-picks ranges at boot)." 'warn'
}

# ---------------------------------------------------------------- 4. firewall (LAN + tailnet only)
Say '--- firewall ---'
$ruleName = "ClashDashboard $Port"
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port `
    -RemoteAddress $LanCidr, '100.64.0.0/10' -Profile Any -ErrorAction SilentlyContinue | Out-Null
$r = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($r) { Say "allow tcp/$Port from $LanCidr and 100.64.0.0/10 (LAN + tailnet)" } else { Say 'firewall rule creation FAILED' 'warn' }

# ---------------------------------------------------------------- 5. scheduled task at boot
Say '--- scheduled task (start at boot, as SYSTEM) ---'
$taskName = 'ClashDashboard'
$action = New-ScheduledTaskAction -Execute $node -Argument ('"{0}"' -f (Join-Path $Root 'server.mjs')) -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
$t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($t) { Say "task '$taskName' registered (state $($t.State))" } else { Say 'task registration FAILED' 'error' }

# ---------------------------------------------------------------- 6. (re)start now
Say '--- start ---'
# Stop whatever currently holds the port. NEVER match on a command-line substring here: an agent
# harness or IDE that embeds the script text in its own command line would match itself and the
# kill would take down the shell running this script (learned the hard way).
$owners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
foreach ($op in $owners) {
    if ($op -and $op -gt 0) {
        Say "stopping previous instance holding port $Port (pid $op)"
        Stop-Process -Id $op -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 5
$listen0 = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if (-not $listen0) {
    # the task can lose the race against the network stack at boot; start it directly as a fallback
    Say 'task did not open the port yet - starting the gateway directly as a fallback' 'warn'
    Start-Process -FilePath $node -ArgumentList ('"{0}"' -f (Join-Path $Root 'server.mjs')) -WorkingDirectory $Root -WindowStyle Hidden
    Start-Sleep -Seconds 4
}
$info = Get-ScheduledTask -TaskName $taskName | Get-ScheduledTaskInfo
Say "last task result: $($info.LastTaskResult) (0 = ok, 267009 = running)"
$listen = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listen) { Say ("listening: " + (($listen | ForEach-Object { $_.LocalAddress + ':' + $_.LocalPort }) -join ', ')) }
else { Say "NOT listening on $Port - check $Root\logs\server.log" 'error' }

# ---------------------------------------------------------------- 7. verify
if (-not $NoVerify) {
    Say '--- end-to-end verification ---'
    $verify = Join-Path $Root 'verify-gateway.mjs'
    if (Test-Path $verify) {
        $out = & $node $verify $Port 2>&1 | Out-String
        $out.Trim().Split("`n") | ForEach-Object { Say ("  " + $_.TrimEnd()) }
    }
    $ips = @('127.0.0.1') + ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -match 'WLAN|Ethernet|Tailscale' -and $_.IPAddress -notmatch '^169' } |
        Select-Object -ExpandProperty IPAddress))
    foreach ($ip in ($ips | Select-Object -Unique)) {
        try {
            $r = Invoke-WebRequest -Uri "http://$ip`:$Port/healthz" -TimeoutSec 5 -UseBasicParsing
            Say "  healthz via $ip`:$Port -> HTTP $($r.StatusCode)"
        } catch { Say "  healthz via $ip`:$Port -> FAILED ($($_.Exception.Message))" 'warn' }
    }
}
Say "=== DONE. Open the panel at http://<this-pc-ip>:$Port/panel/ ==="
Say "uninstall with: powershell -File `"$Root\uninstall.ps1`""
