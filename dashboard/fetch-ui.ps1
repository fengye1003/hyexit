# fetch-ui.ps1 - download the latest zashboard build into .\public
#
# The SPA is third-party build output (a few MB), so it is NOT committed: fetch it here instead.
# Uses the "latest release asset" URL directly, because the GitHub API is rate-limited (403) often
# enough to be useless in practice.
#
# PURE ASCII ONLY (Windows PowerShell 5.1 decodes BOM-less files as the system ANSI codepage).
[CmdletBinding()]
param(
    [string]$Root = $PSScriptRoot,
    [string]$Url = 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-no-fonts.zip'
)
$ErrorActionPreference = 'Stop'
$public = Join-Path $Root 'public'
$zip = Join-Path $Root 'zashboard.zip'
$tmp = Join-Path $Root '_unzip'

if (Test-Path (Join-Path $public 'index.html')) {
    Write-Host "public/index.html already present - delete it first if you want to refresh" -ForegroundColor Yellow
    exit 0
}
New-Item -ItemType Directory -Force -Path $public | Out-Null

Write-Host "downloading $Url"
$sw = [Diagnostics.Stopwatch]::StartNew()
Invoke-WebRequest -Uri $Url -OutFile $zip -TimeoutSec 300 -UseBasicParsing
$sw.Stop()
$len = (Get-Item $zip).Length
Write-Host ("downloaded {0} KB in {1}s" -f [int]($len / 1KB), [int]$sw.Elapsed.TotalSeconds)
if ($len -lt 100000) { throw "download looks truncated ($len bytes)" }

if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $tmp -Force
$idx = Get-ChildItem $tmp -Recurse -Filter 'index.html' | Select-Object -First 1
if (-not $idx) { throw 'index.html not found in the archive' }
Copy-Item (Join-Path $idx.Directory.FullName '*') $public -Recurse -Force
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("installed {0} files into public\" -f (Get-ChildItem $public -Recurse -File | Measure-Object).Count) -ForegroundColor Green
