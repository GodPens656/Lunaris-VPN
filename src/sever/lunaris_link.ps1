param([Parameter(Mandatory = $true, Position = 0)][string]$Link)
$ErrorActionPreference = 'Stop'
if ($Link.Length -gt 25000 -or -not $Link.StartsWith('lunaris://', [StringComparison]::OrdinalIgnoreCase)) { exit 1 }
$lunarisClient = @@CLIENT@@
$lunarisEntry = @@ENTRY@@
$lunarisInbox = @@INBOX@@
Add-Type -AssemblyName System.Security
[IO.Directory]::CreateDirectory($lunarisInbox) | Out-Null
$lunarisBytes = [Text.Encoding]::UTF8.GetBytes($Link)
$lunarisProtected = [Security.Cryptography.ProtectedData]::Protect($lunarisBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
$lunarisFile = Join-Path $lunarisInbox (([DateTime]::UtcNow.Ticks.ToString('D19')) + '-' + [Guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllBytes($lunarisFile + '.tmp', $lunarisProtected)
[IO.File]::Move($lunarisFile + '.tmp', $lunarisFile + '.link')

# Serialize concurrent clicks while a cold client is acquiring its instance lock.
$lunarisLaunch = [Threading.Mutex]::new($false, 'Local\LunarisVPN.LinkLaunch')
$lunarisHeld = $false
try {
    try { $lunarisHeld = $lunarisLaunch.WaitOne(30000) }
    catch [Threading.AbandonedMutexException] { $lunarisHeld = $true }
    if (-not $lunarisHeld) { exit 1 }
    $lunarisRunning = $null
    try { $lunarisRunning = [Threading.Mutex]::OpenExisting('Local\SeverVPN') }
    catch [Threading.WaitHandleCannotBeOpenedException] { }
    if ($null -ne $lunarisRunning) { $lunarisRunning.Dispose(); exit 0 }
    if ($lunarisEntry) {
        Start-Process -FilePath $lunarisClient -ArgumentList ('"' + $lunarisEntry + '"') -WindowStyle Hidden
    } else {
        Start-Process -FilePath $lunarisClient -WindowStyle Hidden
    }
    for ($lunarisAttempt = 0; $lunarisAttempt -lt 60; $lunarisAttempt++) {
        Start-Sleep -Milliseconds 500
        try {
            $lunarisRunning = [Threading.Mutex]::OpenExisting('Local\SeverVPN')
            $lunarisRunning.Dispose()
            break
        } catch [Threading.WaitHandleCannotBeOpenedException] { }
    }
} finally {
    if ($lunarisHeld) { $lunarisLaunch.ReleaseMutex() }
    $lunarisLaunch.Dispose()
}
