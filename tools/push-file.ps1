# push-file.ps1 - push one local file to a remote host byte-exactly (scp + remote sha256 verify).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File push-file.ps1 `
#       -Local <path> -Remote <path> [-Mode 600] `
#       [-Target root@203.0.113.10] [-Port 22] [-Key C:\path\id_ed25519] [-KnownHosts C:\path\known_hosts]
#
# Why scp and not "base64 | ssh": a base64 payload on the Windows command line breaks above ~30 KB
# (command-line length limit), which silently truncates the file. scp plus a remote sha256 comparison
# is byte-exact and tells you immediately when it is not.
#
# PURE ASCII ONLY (Windows PowerShell 5.1 decodes BOM-less files as the system ANSI codepage).
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Local,
    [Parameter(Mandatory = $true)][string]$Remote,
    [string]$Mode = '',
    [string]$Target = 'root@203.0.113.10',
    [int]$Port = 22,
    [string]$Key = (Join-Path $HOME '.ssh\id_ed25519'),
    [string]$KnownHosts = (Join-Path $HOME '.ssh\known_hosts')
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Key)) { throw "ssh key not found: $Key" }
$src = (Resolve-Path -LiteralPath $Local).Path
$sha = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLower()
$bytes = (Get-Item -LiteralPath $src).Length

$common = @('-o', 'StrictHostKeyChecking=accept-new', '-o', "UserKnownHostsFile=$KnownHosts", '-o', 'ConnectTimeout=20')
$SshOpts = @('-i', $Key, '-p', "$Port") + $common
$ScpOpts = @('-i', $Key, '-P', "$Port") + $common

$dir = $Remote.Substring(0, $Remote.LastIndexOf('/'))
Write-Host ("=== push {0} -> {1}:{2} ({3} bytes) ===" -f (Split-Path $src -Leaf), $Target, $Remote, $bytes) -ForegroundColor Cyan

& ssh @SshOpts $Target "mkdir -p '$dir'" 2>&1 | Out-Null
& scp @ScpOpts $src "${Target}:$Remote" 2>&1 | ForEach-Object { if ($_ -notmatch '^\s*$') { Write-Host "   $_" } }

if ($Mode -ne '') { & ssh @SshOpts $Target "chmod $Mode '$Remote'" 2>&1 | Out-Null }
$out = & ssh @SshOpts $Target "sha256sum '$Remote'; stat -c%s '$Remote'" 2>&1 | Out-String
Write-Host $out.Trim()
if ($out -notmatch $sha) { throw "SHA256 MISMATCH: local=$sha`n$out" }
Write-Host "OK sha256=$sha" -ForegroundColor Green
