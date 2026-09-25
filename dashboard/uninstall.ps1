# uninstall.ps1 - remove everything install.ps1 created (run as Administrator).
# The files in D:\ClashDashboard are left in place.
[CmdletBinding()]
param(
    [int]$Port = 3000,
    [switch]$KeepPortReservation
)
$ErrorActionPreference = 'Continue'
function Say([string]$m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say 'NOT elevated: rerun from an Administrator PowerShell'; exit 1
}

Say 'stopping the scheduled task'
Stop-ScheduledTask -TaskName 'ClashDashboard' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'ClashDashboard' -Confirm:$false -ErrorAction SilentlyContinue

Say "stopping whatever holds port $Port"
# never match command-line substrings: the caller (agent harness/IDE) may embed this text in its own
# command line and would be killed too
Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique |
    Where-Object { $_ -gt 0 } |
    ForEach-Object { Say ("  pid " + $_); Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }

Say 'removing the firewall rule'
Get-NetFirewallRule -DisplayName "ClashDashboard $Port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

if (-not $KeepPortReservation) {
    Say 'removing the port reservation'
    $out = (netsh int ipv4 delete excludedportrange protocol=tcp startport=$Port numberofports=1 2>&1) -join ' '
    Say ("  " + $out)
}
Say 'done (files under D:\ClashDashboard were NOT deleted)'
