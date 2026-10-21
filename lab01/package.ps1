$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $repo 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$zipPath = Join-Path $dist 'lab01_2412456_尚文轩.zip'
# Explicit file allowlist: no private-demo, Git metadata, previews, or TeX intermediates.
$relative = @('README.md','PROTOCOL.md','CMakeLists.txt','build.ps1','build-msvc.cmd','package.ps1')
$relative += Get-ChildItem "$PSScriptRoot/src" -File | ForEach-Object { "src/$($_.Name)" }
$relative += @('bin/chat_server.exe','bin/chat_client.exe')
$relative += Get-ChildItem "$PSScriptRoot/tests" -File | ForEach-Object { "tests/$($_.Name)" }
$relative += Get-ChildItem "$PSScriptRoot/evidence" -File | ForEach-Object { "evidence/$($_.Name)" }
$relative += @('report/main.tex','report/main.pdf','report/nankai.jpg','report/TEMPLATE-LICENSE',
    'report/measurements.tex','report/tcp-table.tex','report/capture-observation.tex','report/build-report.ps1','report/client-transcript.txt')
Add-Type -AssemblyName System.IO.Compression
$stream = [IO.File]::Open($zipPath,[IO.FileMode]::Create)
$archive = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($item in $relative) {
        $source = Join-Path $PSScriptRoot $item
        if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing deliverable: $source" }
        $entry = $archive.CreateEntry("lab01/$item")
        $input = [IO.File]::OpenRead($source); $output = $entry.Open()
        try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    }
} finally { $archive.Dispose(); $stream.Dispose() }
Get-FileHash -Algorithm SHA256 $zipPath | Format-List
Write-Host "Submission archive: $zipPath"
