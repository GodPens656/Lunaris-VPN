param(
    [ValidateSet('windows', 'apk', 'all')][string]$Target = 'all',
    [string]$BuildDir = (Join-Path $env:TEMP 'lunaris-tauri-065-build')
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build_tauri.ps1') -Target $Target -BuildDir $BuildDir
