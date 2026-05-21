# tun0access installer — Windows (PowerShell)
# Usage (run from an elevated PowerShell prompt):
#   irm https://raw.githubusercontent.com/tun0access/tun0access/main/install.ps1 | iex
#
# The binary is placed in $env:LOCALAPPDATA\tun0access\ and that directory is
# added to the user PATH permanently.

$ErrorActionPreference = "Stop"
$Repo   = "KatrielMoses/tun0access"
$BinDir = Join-Path $env:LOCALAPPDATA "tun0access"

# ── detect arch ──────────────────────────────────────────────────────────────
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64"   { "amd64" }
    "ARM64"   { "arm64" }
    default   { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

# ── resolve latest release ───────────────────────────────────────────────────
Write-Host "Fetching latest release..."
$releaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
$release    = Invoke-RestMethod -Uri $releaseUrl -UseBasicParsing
$version    = $release.tag_name

if (-not $version) {
    throw "Could not determine latest version. Check https://github.com/$Repo/releases"
}

# ── download ─────────────────────────────────────────────────────────────────
$zipName = "tun0access_windows_${arch}.zip"
$url     = "https://github.com/$Repo/releases/download/$version/$zipName"

Write-Host "Downloading tun0access $version (windows/$arch)..."
$tmpZip = Join-Path $env:TEMP $zipName
Invoke-WebRequest -Uri $url -OutFile $tmpZip -UseBasicParsing

# ── extract ───────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Expand-Archive -Path $tmpZip -DestinationPath $BinDir -Force
Remove-Item $tmpZip

# ── add to PATH ───────────────────────────────────────────────────────────────
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$BinDir", "User")
    Write-Host "Added $BinDir to your PATH."
    Write-Host "Restart your terminal for the PATH change to take effect."
}

Write-Host ""
Write-Host "tun0access $version installed to $BinDir\tun0access.exe"
Write-Host "Run:  tun0access connect"
Write-Host "(Tip: run from an elevated prompt — OpenVPN needs admin rights)"
