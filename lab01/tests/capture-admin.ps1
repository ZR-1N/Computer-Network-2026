param([ValidateSet('Preflight','Capture')][string]$Mode = 'Preflight', [string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$evidence = Join-Path $PSScriptRoot '../evidence'
New-Item -ItemType Directory -Force $evidence | Out-Null
$log = Join-Path $evidence 'capture-admin.txt'
Start-Transcript -Path $log -Force
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell (Windows UAC approval required).'
    }
    & pktmon status
    & pktmon filter list
    if ($Mode -eq 'Preflight') { return }
    $statusFile = Join-Path $evidence 'capture-status.txt'
    & cmd /d /c "pktmon status > `"$statusFile`""
    $statusExit = $LASTEXITCODE
    $statusText = [IO.File]::ReadAllText($statusFile,[Text.Encoding]::UTF8) -replace "`0", ''
    if ($statusExit -ne 0 -or $statusText -notmatch '(?i)(没有运行|not running|is stopped)') {
        throw 'An existing monitor may be running. Refusing to change its configuration.'
    }
    # Refuse to alter an existing monitoring configuration. Only recognize an
    # explicitly empty filter list; unfamiliar localization fails closed.
    $filterFile = Join-Path $evidence 'capture-filter-state.txt'
    & cmd /d /c "pktmon filter list > `"$filterFile`""
    $filterExit = $LASTEXITCODE
    $filters = [IO.File]::ReadAllText($filterFile,[Text.Encoding]::UTF8) -replace "`0", ''
    Write-Host "Filter command exit: $filterExit; decoded: $filters"
    if ($filterExit -ne 0 -or $filters -notmatch '(?im)^\s*(None\.?|无[。. ]?|没有筛选器[。.]?|未配置筛选器[。.]?)\s*$') {
        throw 'Filter list is not confirmed empty. Inspect capture-admin.txt before proceeding.'
    }
    $added = $false; $started = $false
    try {
        & pktmon filter add Lab01Chat -t TCP -p 9001
        if ($LASTEXITCODE -ne 0) { throw 'Cannot add experiment port filter' }
        $added = $true
        & pktmon start --capture --comp all --pkt-size 0 --file-size 32 --file-name "$evidence/chat.etl"
        if ($LASTEXITCODE -ne 0) { throw 'Capture start failed; existing captures are never stopped' }
        $started = $true
        & $Python "$PSScriptRoot/capture_workload.py"
        if ($LASTEXITCODE -ne 0) { throw 'Capture workload failed' }
    } finally {
        if ($started) { & pktmon stop }
        # The original list was explicitly empty; restore that exact state.
        if ($added) { & pktmon filter remove }
    }
    & pktmon etl2pcap "$evidence/chat.etl" --out "$evidence/chat.pcapng"
    if ($LASTEXITCODE -ne 0) { throw 'PCAPNG conversion failed' }
    & pktmon etl2pcap "$evidence/chat.etl" --drop-only --out "$evidence/chat-drops.pcapng"
    if ($LASTEXITCODE -ne 0) { throw 'Drop PCAPNG conversion failed' }
    & pktmon etl2txt "$evidence/chat.etl" --out "$evidence/chat-packets.txt"
    Write-Host 'Capture recorded. Packet count must be checked before drawing a loss conclusion.'
} catch {
    $_ | Out-String | Write-Host
    exit 1
} finally { Stop-Transcript }
