param(
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",
    [string]$BuildId = $(if ($env:BUILD_ID) { $env:BUILD_ID } else { Get-Date -Format "yyyyMMdd-HHmm" })
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutputDir = Join-Path $RepoRoot "dist-windows\$Architecture-$BuildId"

if (-not $IsWindows -and $PSVersionTable.PSEdition -eq "Core") {
    throw "Windows release packages must be built on native Windows."
}

Push-Location $RepoRoot
try {
    & npm.cmd --prefix frontend run build
    if ($LASTEXITCODE -ne 0) { throw "Frontend build failed" }

    & (Join-Path $PSScriptRoot "build-server-windows.ps1") -Architecture $Architecture -BuildId $BuildId

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    & npx.cmd electron-builder --win nsis zip "--$Architecture" --publish never `
        "-c.directories.output=$OutputDir" `
        "-c.artifactName=AEGIS-`${version}-$BuildId-`${arch}.`${ext}"
    if ($LASTEXITCODE -ne 0) { throw "electron-builder failed" }

    $artifacts = Get-ChildItem -Path $OutputDir -File | Where-Object { $_.Extension -in @(".exe", ".zip") }
    if ($artifacts.Count -lt 2) {
        throw "Expected an NSIS installer and ZIP archive in $OutputDir"
    }
    $checksumLines = foreach ($artifact in ($artifacts | Sort-Object Name)) {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $artifact.FullName).Hash.ToLowerInvariant()
        "$hash  $($artifact.Name)"
    }
    $checksumLines | Set-Content -Encoding ASCII (Join-Path $OutputDir "SHA256SUMS")
    Write-Host "Windows $Architecture artifacts ready: $OutputDir"
    Get-ChildItem $OutputDir -File | Format-Table Name, Length
} finally {
    Pop-Location
}
