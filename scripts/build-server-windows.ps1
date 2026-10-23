param(
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",
    [string]$BuildId = $(if ($env:BUILD_ID) { $env:BUILD_ID } else { Get-Date -Format "yyyyMMdd-HHmm" })
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendRoot = Join-Path $RepoRoot "backend"
$Python = Join-Path $BackendRoot ".venv\Scripts\python.exe"

if (-not $IsWindows -and $PSVersionTable.PSEdition -eq "Core") {
    throw "The Windows backend must be frozen on native Windows."
}
if (-not (Test-Path $Python -PathType Leaf)) {
    throw "backend\.venv is missing. Create it with: py -3.12 -m venv backend\.venv"
}

$pythonMachine = (& $Python -c "import platform; print(platform.machine().lower())").Trim()
$validMachines = if ($Architecture -eq "arm64") { @("arm64", "aarch64") } else { @("amd64", "x86_64") }
if ($pythonMachine -notin $validMachines) {
    throw "Python architecture '$pythonMachine' does not match requested Windows $Architecture build."
}

function Get-VerifiedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Sha256
    )
    if (-not (Test-Path $Destination -PathType Leaf)) {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Destination).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) {
        throw "Checksum mismatch for $Destination (expected $Sha256, got $actual)"
    }
}

Write-Host "==> Building native Windows $Architecture backend"
Write-Host "    Build ID: $BuildId"

$frontendDist = Join-Path $RepoRoot "frontend\dist"
if (-not (Test-Path $frontendDist -PathType Container)) {
    throw "frontend\dist is missing. Run npm --prefix frontend run build first."
}

$distRoot = Join-Path $BackendRoot "dist"
$wordlistRoot = Join-Path $distRoot "wordlists"
$toolRoot = Join-Path $distRoot "tools"
# Never allow stale helpers from a different OS or architecture into a release.
if (Test-Path $toolRoot -PathType Container) {
    Remove-Item -Recurse -Force $toolRoot
}
New-Item -ItemType Directory -Force -Path $wordlistRoot, $toolRoot | Out-Null

$wordlists = @(
    @{
        Name = "common.txt"
        Url = "https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/Web-Content/common.txt"
        Sha256 = "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a"
    },
    @{
        Name = "directories.txt"
        Url = "https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
        Sha256 = "d7619fe257485f3be56316c888e7392b2a0b1d4fce3593d298e8ab604118eaa7"
    },
    @{
        Name = "subdomains.txt"
        Url = "https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/DNS/subdomains-top1million-5000.txt"
        Sha256 = "e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19"
    }
)
foreach ($wordlist in $wordlists) {
    Get-VerifiedFile -Url $wordlist.Url -Destination (Join-Path $wordlistRoot $wordlist.Name) -Sha256 $wordlist.Sha256
}

$toolAssets = if ($Architecture -eq "arm64") {
    @(
        @{ Name = "gobuster"; Url = "https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Windows_arm64.zip"; Sha256 = "14ca560d798c200f264498f5f7598020fc6c42c47ae752258862cd71c7a70a24" },
        @{ Name = "ffuf"; Url = "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_arm64.zip"; Sha256 = "b2038093c9cf888ceb7a8733650ae2441b1374ca750504b9b4e6c36372b947db" },
        @{ Name = "subfinder"; Url = "https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_windows_arm64.zip"; Sha256 = "31ecae1a4cfdccf850cc1f0dc15687a941b1de8582e01cde7e7d152c5693cc50" }
    )
} else {
    @(
        @{ Name = "gobuster"; Url = "https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Windows_x86_64.zip"; Sha256 = "677abe8e56c5455804225ad2264dc6e9981e99673ef3ccd6a2fa2af8a2e92aba" },
        @{ Name = "ffuf"; Url = "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip"; Sha256 = "c0aec0289f1963cfc38a204f9ebe97712441c670fa7d7aad145cf87b15f038d4" },
        @{ Name = "subfinder"; Url = "https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_windows_amd64.zip"; Sha256 = "84e8a01d3d062484bb0958445e635a5773b6671566407fb4ab48417391539681" }
    )
}

$downloadRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("aegis-windows-tools-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null
try {
    foreach ($tool in $toolAssets) {
        $archive = Join-Path $downloadRoot ($tool.Name + ".zip")
        $expanded = Join-Path $downloadRoot ($tool.Name + "-expanded")
        Get-VerifiedFile -Url $tool.Url -Destination $archive -Sha256 $tool.Sha256
        Expand-Archive -Path $archive -DestinationPath $expanded -Force
        $executable = Get-ChildItem -Path $expanded -Recurse -File -Filter ($tool.Name + ".exe") | Select-Object -First 1
        if (-not $executable) {
            throw "The verified $($tool.Name) archive did not contain $($tool.Name).exe"
        }
        Copy-Item -Force $executable.FullName (Join-Path $toolRoot ($tool.Name + ".exe"))
        Write-Host "    verified and bundled $($tool.Name).exe"
    }
} finally {
    if (Test-Path $downloadRoot) {
        Remove-Item -Recurse -Force $downloadRoot
    }
}

# Naabu and httpx do not publish Windows ARM64 archives. Build both pinned Go
# modules natively on each runner so Windows ARM never receives x64 scanner
# helpers hidden inside an otherwise-native package.
$go = Get-Command "go.exe" -ErrorAction SilentlyContinue
if (-not $go) {
    throw "Go is required to build the pinned native naabu and httpx helpers."
}
$previousGoBin = $env:GOBIN
$env:GOBIN = $toolRoot
try {
    $goTools = @(
        @{ Name = "naabu"; Module = "github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1" },
        @{ Name = "httpx"; Module = "github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0" }
    )
    foreach ($tool in $goTools) {
        & $go.Source install $tool.Module
        if ($LASTEXITCODE -ne 0) { throw "Go build failed for $($tool.Name)" }
        $executable = Join-Path $toolRoot ($tool.Name + ".exe")
        if (-not (Test-Path $executable -PathType Leaf)) {
            throw "Go completed without producing $executable"
        }
        Write-Host "    built native $($tool.Name).exe"
    }
} finally {
    $env:GOBIN = $previousGoBin
}

$package = Get-Content (Join-Path $RepoRoot "package.json") -Raw | ConvertFrom-Json
$buildInfo = [ordered]@{
    buildId = $BuildId
    buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    version = $package.version
    platform = "windows"
    architecture = $Architecture
    bundledWordlists = $wordlists.Count
    bundledScriptSources = 0
}
$buildInfo | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $distRoot "build-info.json")

$serverOutput = Join-Path $distRoot "aegis-server"
$buildRoot = Join-Path $BackendRoot "build"
if (Test-Path $serverOutput) { Remove-Item -Recurse -Force $serverOutput }
New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
$env:PYINSTALLER_CONFIG_DIR = Join-Path $buildRoot "pyinstaller-config"

$pyiArgs = @(
    "--clean", "--onedir", "--name", "aegis-server",
    "--add-data", "$frontendDist;frontend/dist",
    "--add-data", "$wordlistRoot;wordlists",
    "--add-data", "$toolRoot;tools",
    "--add-data", "$(Join-Path $distRoot 'build-info.json');.",
    "--distpath", $distRoot,
    "--specpath", $buildRoot,
    "--workpath", (Join-Path $buildRoot "pyinstaller"),
    "--noconfirm", "--log-level", "WARN", "--noupx",
    (Join-Path $BackendRoot "server.py")
)
& $Python -m PyInstaller @pyiArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

$serverExe = Join-Path $serverOutput "aegis-server.exe"
if (-not (Test-Path $serverExe -PathType Leaf)) {
    throw "PyInstaller completed without producing $serverExe"
}
Write-Host "Windows backend ready: $serverExe"
