param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$evidence = Join-Path $PSScriptRoot '../evidence'
New-Item -ItemType Directory -Force $evidence | Out-Null
$resultFile = Join-Path $evidence 'runner-status.json'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated PowerShell.' }
    $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 |
        Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric
    $chosen = $null
    foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        if ($adapter.Status -eq 'Up' -and $adapter.HardwareInterface) { $chosen = $route; break }
    }
    if (!$chosen) { throw 'No active physical IPv4 default-route adapter. Select an adapter explicitly before capture.' }
    $ip = Get-NetIPAddress -InterfaceIndex $chosen.InterfaceIndex -AddressFamily IPv4 |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
    $network = @{ ipv4=$ip.IPAddress; gateway=$chosen.NextHop; interface_index=$chosen.InterfaceIndex; interface_alias=$chosen.InterfaceAlias }
    $network | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'network-info.json') -Encoding utf8
    & $Python "$PSScriptRoot/integration.py" *> (Join-Path $evidence 'runner-output.txt')
    $exitCode = $LASTEXITCODE
    @{exit_code=$exitCode; finished=(Get-Date -Format o)} | ConvertTo-Json | Set-Content -LiteralPath $resultFile -Encoding utf8
    exit $exitCode
} catch {
    @{exit_code=1; error=$_.Exception.Message; finished=(Get-Date -Format o)} | ConvertTo-Json | Set-Content -LiteralPath $resultFile -Encoding utf8
    exit 1
}
