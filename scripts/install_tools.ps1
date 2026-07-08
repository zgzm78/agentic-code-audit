param(
    [string]$Proxy = "",
    [string]$GitleaksVersion = "8.30.1",
    [string]$OsvScannerVersion = "2.4.0"
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Tools = Join-Path $Root ".tools"
$Bin = Join-Path $Tools "bin"
$Downloads = Join-Path $Tools "downloads"
$SemgrepVenv = Join-Path $Tools "semgrep-venv"

New-Item -ItemType Directory -Force -Path $Bin, $Downloads | Out-Null

function Invoke-Download {
    param(
        [string]$Uri,
        [string]$OutFile
    )
    if ($Proxy) {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Proxy $Proxy
    } else {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile
    }
}

Write-Host "Installing Gitleaks $GitleaksVersion..."
$GitleaksZip = Join-Path $Downloads "gitleaks_windows_x64.zip"
$GitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion/gitleaks_${GitleaksVersion}_windows_x64.zip"
Invoke-Download -Uri $GitleaksUrl -OutFile $GitleaksZip
Expand-Archive -LiteralPath $GitleaksZip -DestinationPath (Join-Path $Downloads "gitleaks") -Force
Copy-Item -LiteralPath (Join-Path $Downloads "gitleaks\gitleaks.exe") -Destination (Join-Path $Bin "gitleaks.exe") -Force

Write-Host "Installing OSV-Scanner $OsvScannerVersion..."
$OsvUrl = "https://github.com/google/osv-scanner/releases/download/v$OsvScannerVersion/osv-scanner_windows_amd64.exe"
Invoke-Download -Uri $OsvUrl -OutFile (Join-Path $Bin "osv-scanner.exe")

Write-Host "Installing Semgrep and Bandit..."
if (-not (Test-Path (Join-Path $SemgrepVenv "Scripts\python.exe"))) {
    python -m venv $SemgrepVenv
}
& (Join-Path $SemgrepVenv "Scripts\python.exe") -m pip install --upgrade pip
& (Join-Path $SemgrepVenv "Scripts\python.exe") -m pip install semgrep bandit

Write-Host "Versions:"
& (Join-Path $Bin "gitleaks.exe") version
& (Join-Path $Bin "osv-scanner.exe") --version
& (Join-Path $SemgrepVenv "Scripts\semgrep.exe") --version
& (Join-Path $SemgrepVenv "Scripts\bandit.exe") --version
