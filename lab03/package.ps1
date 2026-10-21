$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $repo 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$zipPath = Join-Path $dist 'lab03_2412456_尚文轩.zip'
$relative = @('README.md','PROTOCOL.md','CMakeLists.txt','build.ps1','build-msvc.cmd','package.ps1')
foreach ($directory in @('src','tests','samples','evidence')) {
    $relative += Get-ChildItem (Join-Path $PSScriptRoot $directory) -Recurse -File |
        Where-Object { $_.FullName -notmatch '[\\/]__pycache__[\\/]' } |
        ForEach-Object { $_.FullName.Substring($PSScriptRoot.Length+1).Replace('\','/') }
}
$relative += @('bin/rudp.exe','bin/protocol_tests.exe')
$relative += @('report/main.tex','report/main.pdf','report/nankai.jpg','report/TEMPLATE-LICENSE',
    'report/measurements.tex','report/performance-table.tex','report/reliability-table.tex',
    'report/selective-excerpt.txt','report/close-excerpt.txt','report/window-performance.pdf',
    'report/window-performance.png','report/build-report.ps1')
Add-Type -AssemblyName System.IO.Compression
$stream = [IO.File]::Open($zipPath,[IO.FileMode]::Create)
$archive = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($item in $relative) {
        $source = Join-Path $PSScriptRoot $item
        if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing deliverable: $source" }
        $entry = $archive.CreateEntry("lab03/$item")
        $input = [IO.File]::OpenRead($source); $output = $entry.Open()
        try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    }
} finally { $archive.Dispose(); $stream.Dispose() }
Get-FileHash -Algorithm SHA256 $zipPath | Format-List
Write-Host "Submission archive: $zipPath"
