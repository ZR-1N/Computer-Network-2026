$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & python ../tests/prepare_report.py
    if ($LASTEXITCODE -ne 0) { throw 'Evidence validation failed' }
    1..2 | ForEach-Object {
        & xelatex -interaction=nonstopmode -halt-on-error main.tex
        if ($LASTEXITCODE -ne 0) { throw 'XeLaTeX failed' }
    }
} finally { Pop-Location }
