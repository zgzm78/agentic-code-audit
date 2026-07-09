param(
    [string]$Proxy = "",
    [string]$RipgrepVersion = "14.1.1",
    [string]$GitleaksVersion = "8.30.1",
    [string]$OsvScannerVersion = "2.4.0",
    [switch]$InstallStage4Tools,
    [switch]$CheckStage5Tools
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

function Add-LocalPath {
    $env:PATH = "$Bin;$SemgrepVenv\Scripts;$env:PATH"
}

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Require-Command {
    param(
        [string]$Name,
        [string]$InstallHint
    )
    if (-not (Test-Command $Name)) {
        throw "$Name is required but was not found. $InstallHint"
    }
}

function Report-OptionalCommand {
    param(
        [string]$Name,
        [string]$Purpose,
        [string]$InstallHint
    )
    if (Test-Command $Name) {
        $Resolved = (Get-Command $Name -ErrorAction SilentlyContinue).Source
        Write-Host "[ok] $Name - $Purpose ($Resolved)"
    } else {
        Write-Warning "[missing] $Name - $Purpose. $InstallHint"
    }
}

Write-Host "Installing ripgrep $RipgrepVersion..."
$RipgrepZip = Join-Path $Downloads "ripgrep_windows_x64.zip"
$RipgrepDir = Join-Path $Downloads "ripgrep"
$RipgrepUrl = "https://github.com/BurntSushi/ripgrep/releases/download/$RipgrepVersion/ripgrep-$RipgrepVersion-x86_64-pc-windows-msvc.zip"
Invoke-Download -Uri $RipgrepUrl -OutFile $RipgrepZip
Expand-Archive -LiteralPath $RipgrepZip -DestinationPath $RipgrepDir -Force
$RgExe = Get-ChildItem -Path $RipgrepDir -Recurse -Filter "rg.exe" | Select-Object -First 1
if (-not $RgExe) {
    throw "rg.exe was not found in ripgrep archive."
}
Copy-Item -LiteralPath $RgExe.FullName -Destination (Join-Path $Bin "rg.exe") -Force

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
& (Join-Path $SemgrepVenv "Scripts\python.exe") -m pip install semgrep bandit pip-audit

Add-LocalPath

if ($InstallStage4Tools) {
    Write-Host "Installing optional stage 4 Python tools..."
    & (Join-Path $SemgrepVenv "Scripts\python.exe") -m pip install pip-audit

    if (Test-Command go) {
        Write-Host "Installing gosec via go install..."
        go install github.com/securego/gosec/v2/cmd/gosec@latest
    } else {
        Write-Warning "go is not installed; gosec remains unavailable. Install Go and rerun with -InstallStage4Tools."
    }

    if (Test-Command cargo) {
        Write-Host "Installing cargo-audit via cargo install..."
        cargo install cargo-audit --locked
    } else {
        Write-Warning "cargo is not installed; cargo-audit remains unavailable. Install Rust/Cargo and rerun with -InstallStage4Tools."
    }

    if (-not (Test-Command cppcheck)) {
        Write-Warning "cppcheck is not installed. Install it with winget/choco or use the Docker sandbox."
    }
    if (-not (Test-Command clang-tidy)) {
        Write-Warning "clang-tidy is not installed. Install LLVM or use the Docker sandbox."
    }
}

if ($CheckStage5Tools) {
    Write-Host "Checking optional stage 5 verification tools..."
    Report-OptionalCommand -Name docker -Purpose "Docker sandbox execution" -InstallHint "Install Docker Desktop or use the provided Docker Compose environment."
    Report-OptionalCommand -Name cmake -Purpose "C/C++ CMake build preparation" -InstallHint "Install CMake with winget/choco, Visual Studio Build Tools, or use the sandbox image."
    Report-OptionalCommand -Name ninja -Purpose "C/C++ Ninja builds" -InstallHint "Install Ninja or rely on CMake's default generator."
    Report-OptionalCommand -Name make -Purpose "Makefile builds" -InstallHint "Use WSL/MSYS2/choco make or the sandbox image."
    Report-OptionalCommand -Name gcc -Purpose "C compiler for native harnesses" -InstallHint "Use MSYS2/WSL or the sandbox image."
    Report-OptionalCommand -Name g++ -Purpose "C++ compiler for native harnesses" -InstallHint "Use MSYS2/WSL or the sandbox image."
    Report-OptionalCommand -Name clang -Purpose "LLVM C compiler with sanitizer support" -InstallHint "Install LLVM or use the sandbox image."
    Report-OptionalCommand -Name clang++ -Purpose "LLVM C++ compiler with sanitizer support" -InstallHint "Install LLVM or use the sandbox image."
    Report-OptionalCommand -Name valgrind -Purpose "Memory-safety evidence collection" -InstallHint "Valgrind is not native-friendly on Windows; prefer WSL or Docker."
    Report-OptionalCommand -Name gdb -Purpose "Crash/debug evidence collection" -InstallHint "Install via MSYS2/MinGW, WSL, or Docker."
    Report-OptionalCommand -Name lldb -Purpose "LLVM debugger evidence collection" -InstallHint "Install LLVM or use Docker."
    Report-OptionalCommand -Name pytest -Purpose "Python harness/test execution" -InstallHint "Install with pip in the active Python environment."
    Report-OptionalCommand -Name node -Purpose "Node.js harness execution" -InstallHint "Install Node.js LTS."
    Report-OptionalCommand -Name npm -Purpose "Node.js package/test execution" -InstallHint "Install Node.js LTS."
    Report-OptionalCommand -Name curl -Purpose "HTTP service verification probes" -InstallHint "Install curl or use Windows built-in curl.exe."
    Report-OptionalCommand -Name sqlite3 -Purpose "SQLite oracle/debug checks" -InstallHint "Install sqlite-tools or use Python sqlite3 harnesses."
    Report-OptionalCommand -Name go -Purpose "Go runtime recognition/fallback" -InstallHint "Install Go if Go projects should be inspected locally."
    Report-OptionalCommand -Name cargo -Purpose "Rust runtime recognition/fallback" -InstallHint "Install Rustup if Rust projects should be inspected locally."
    Report-OptionalCommand -Name java -Purpose "Java runtime recognition/fallback" -InstallHint "Install a JDK if Java projects should be inspected locally."
    Report-OptionalCommand -Name mvn -Purpose "Maven build recognition/fallback" -InstallHint "Install Maven or use Docker."
    Report-OptionalCommand -Name gradle -Purpose "Gradle build recognition/fallback" -InstallHint "Install Gradle or use Docker."
    Report-OptionalCommand -Name php -Purpose "PHP runtime recognition/fallback" -InstallHint "Install PHP or use Docker."
    Report-OptionalCommand -Name composer -Purpose "PHP dependency/build recognition" -InstallHint "Install Composer or use Docker."
}

Require-Command -Name npm -InstallHint "Install Node.js LTS, or run the Docker Compose environment where nodejs/npm are installed."

Write-Host "Versions:"
& (Join-Path $Bin "rg.exe") --version
& (Join-Path $Bin "gitleaks.exe") version
& (Join-Path $Bin "osv-scanner.exe") --version
& (Join-Path $SemgrepVenv "Scripts\semgrep.exe") --version
& (Join-Path $SemgrepVenv "Scripts\bandit.exe") --version
& (Join-Path $SemgrepVenv "Scripts\pip-audit.exe") --version
npm --version
