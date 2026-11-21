param(
    [ValidateSet('windows','apk','all')][string]$Target = 'all',
    [string]$BuildDir = (Join-Path $env:TEMP 'lunaris-tauri-071-build')
)
$ErrorActionPreference = 'Stop'
$lunarisRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $lunarisRoot
$lunarisPython = Join-Path $lunarisRoot '.venv/Scripts/python.exe'
$lunarisVersion = (& $lunarisPython -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])").Trim()
function Check-Step([string]$Step) { if ($LASTEXITCODE -ne 0) { throw "$Step failed" } }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'Install Rust with rustup and add cargo to PATH' }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Install Node.js 22 LTS' }
if (-not (Test-Path app/node_modules)) {
    Push-Location app
    try { & npm.cmd ci; Check-Step 'npm ci' } finally { Pop-Location }
}
& $lunarisPython scripts/fetch_core.py windows
Check-Step 'Windows cores'
& $lunarisPython scripts/fetch_core.py android
Check-Step 'Android cores'
& $lunarisPython scripts/prepare_tauri.py
Check-Step 'Native inputs'
& $lunarisPython scripts/stage_tauri.py $BuildDir
Check-Step 'Staging'
Push-Location (Join-Path $BuildDir 'app')
try {
    if ($Target -in @('windows','all')) {
        & npm.cmd run build
        Check-Step 'Tauri Windows'
        $lunarisRelease = Join-Path $lunarisRoot "dist/windows-$lunarisVersion"
        New-Item -ItemType Directory -Force $lunarisRelease | Out-Null
        $lunarisCargoTarget = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location) 'src-tauri/target' }
        Copy-Item (Join-Path $lunarisCargoTarget 'release/lunaris-vpn.exe') (Join-Path $lunarisRelease 'LunarisClient.exe') -Force
        New-Item -ItemType Directory -Force (Join-Path $lunarisRelease 'runtime') | Out-Null
        Copy-Item (Join-Path $BuildDir 'build/tauri-runtime-rust/*') (Join-Path $lunarisRelease 'runtime') -Recurse -Force
    }
    if ($Target -in @('apk','all')) {
        if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android/Sdk' }
        $env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
        if (-not $env:NDK_HOME) {
            $env:NDK_HOME = (Get-ChildItem (Join-Path $env:ANDROID_HOME 'ndk') -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
        }
        & rustup target add aarch64-linux-android
        Check-Step 'Rust Android target'
        if (-not (Test-Path src-tauri/gen/android)) {
            & npm.cmd run android:init
            Check-Step 'Tauri Android init'
        }
        & $lunarisPython (Join-Path $lunarisRoot 'scripts/patch_tauri_android.py') $BuildDir
        Check-Step 'Android packaging settings'
        & npm.cmd run android:build
        Check-Step 'Tauri Android'
        $lunarisApk = Get-ChildItem src-tauri/gen/android/app/build/outputs/apk -Recurse -Filter '*release*.apk' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $lunarisApk) { throw 'Release APK not found' }
        $lunarisOutput = Join-Path $lunarisRoot "dist/LunarisClient-$lunarisVersion-arm64.apk"
        Copy-Item $lunarisApk.FullName $lunarisOutput -Force
        & $lunarisPython (Join-Path $lunarisRoot 'scripts/verify_android_package.py') $lunarisOutput
        Check-Step 'Executable core verification'
    }
} finally { Pop-Location }
if (Test-Path "dist/windows-$lunarisVersion/LunarisClient.exe") {
    & $lunarisPython scripts/package_release.py --windows-dir "dist/windows-$lunarisVersion"
    Check-Step 'Release packaging'
}
