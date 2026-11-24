$ErrorActionPreference = 'Stop'
$lunarisRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $lunarisRoot
$lunarisExecutable = Join-Path $lunarisRoot 'dist/windows-0.8.0/LunarisClient.exe'
if (Test-Path -LiteralPath $lunarisExecutable) {
    & $lunarisExecutable
} else {
    Push-Location app
    try {
        & npm.cmd run dev
        if ($LASTEXITCODE -ne 0) { throw 'Lunaris client failed to start' }
    } finally { Pop-Location }
}
