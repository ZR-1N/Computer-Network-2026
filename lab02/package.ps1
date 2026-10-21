$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $repo 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$zipPath = Join-Path $dist 'lab02_2412456_尚文轩.zip'
$relative = @('README.md','DESIGN.md','CMakeLists.txt','build.ps1','build-msvc.cmd','bootstrap-sdk.ps1','package.ps1')
$relative += Get-ChildItem "$PSScriptRoot/src" -File | ForEach-Object { "src/$($_.Name)" }
$relative += @('bin/packet_capture.exe','bin/parser_tests.exe')
$relative += Get-ChildItem "$PSScriptRoot/tests" -File | ForEach-Object { "tests/$($_.Name)" }
$relative += Get-ChildItem "$PSScriptRoot/evidence" -File | ForEach-Object { "evidence/$($_.Name)" }
$relative += @('report/main.tex','report/main.pdf','report/nankai.jpg','report/TEMPLATE-LICENSE',
    'report/measurements.tex','report/runtime-info.tex','report/mandatory-table.tex','report/icmp-table.tex',
    'report/first-frame-hex.txt','report/capture-screen.txt','report/build-report.ps1')
Add-Type -AssemblyName System.IO.Compression
$stream = [IO.File]::Open($zipPath,[IO.FileMode]::Create)
$archive = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($item in $relative) {
        $source = Join-Path $PSScriptRoot $item
        if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing deliverable: $source" }
        $entry = $archive.CreateEntry("lab02/$item")
        $input = [IO.File]::OpenRead($source); $output = $entry.Open()
        try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    }
} finally { $archive.Dispose(); $stream.Dispose() }
Get-FileHash -Algorithm SHA256 $zipPath | Format-List
Write-Host "Submission archive: $zipPath"
