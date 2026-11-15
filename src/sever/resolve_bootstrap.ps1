param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Server,
    [switch]$IPv4Only
)
$ErrorActionPreference = 'Stop'
$recordType = if ($IPv4Only) { 'A' } else { 'A_AAAA' }
$addresses = @(Resolve-DnsName -Name $Name -Server $Server -Type $recordType `
    -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue |
    Where-Object { $_.Type -in @('A', 'AAAA') -and $_.IPAddress } |
    Select-Object -ExpandProperty IPAddress -Unique)
if (-not $addresses.Count) { exit 1 }
ConvertTo-Json -InputObject $addresses -Compress
