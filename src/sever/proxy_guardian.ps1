param([int]$ParentId, [string]$Journal, [string]$Ready)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
try {
    $severParent = [System.Diagnostics.Process]::GetProcessById($ParentId)
    # Force the process handle open before declaring the guardian ready.
    [void]$severParent.Handle
    [System.IO.File]::WriteAllText($Ready, 'ready')
    $severParent.WaitForExit()
} catch { }
if (-not (Test-Path -LiteralPath $Journal)) { exit }
try {
    $severBytes = [System.Security.Cryptography.ProtectedData]::Unprotect([System.IO.File]::ReadAllBytes($Journal), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $severRecord = [System.Text.Encoding]::UTF8.GetString($severBytes) | ConvertFrom-Json
    $severKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings', $true)
    foreach ($severName in @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL')) {
        $severApplied = $severRecord.applied.$severName
        $severOld = $severRecord.previous.$severName
        $severCurrent = $severKey.GetValue($severName, $null)
        $severMatches = ($null -eq $severCurrent -and $null -eq $severApplied) -or ($null -ne $severApplied -and $severCurrent -eq $severApplied[0])
        if ($severMatches) {
            if ($null -eq $severOld) { $severKey.DeleteValue($severName, $false) }
            else { $severKey.SetValue($severName, $severOld[0], [Microsoft.Win32.RegistryValueKind][int]$severOld[1]) }
        }
    }
    $severKey.Close()
    Add-Type 'using System; using System.Runtime.InteropServices; public class SeverWinInet { [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr p, int n); }'
    [void][SeverWinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][SeverWinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
    Remove-Item -LiteralPath $Journal
} catch { exit 1 }
