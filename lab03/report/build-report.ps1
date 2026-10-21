$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & python -X utf8 ../tests/prepare_report.py
    if ($LASTEXITCODE -ne 0) { throw 'Evidence validation failed' }
    1..3 | ForEach-Object {
        & xelatex -interaction=nonstopmode -halt-on-error main.tex
        if ($LASTEXITCODE -ne 0) { throw 'XeLaTeX failed' }
    }
} finally { Pop-Location }
