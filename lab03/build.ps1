$ErrorActionPreference = 'Stop'
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$install) { throw 'Visual Studio C++ Build Tools required.' }
$env:LAB03_VCVARS = "$install\VC\Auxiliary\Build\vcvars64.bat"
New-Item -ItemType Directory -Force "$PSScriptRoot/bin" | Out-Null
& cmd /d /c "$PSScriptRoot/build-msvc.cmd"
if ($LASTEXITCODE -ne 0) { throw 'C++ build failed' }
