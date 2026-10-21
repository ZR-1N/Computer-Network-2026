param([string]$NpcapSdk = (Join-Path $PSScriptRoot '../deps/npcap-sdk-1.16'))
$ErrorActionPreference = 'Stop'
$sdk = (Resolve-Path -LiteralPath $NpcapSdk).Path
if (!(Test-Path "$sdk/Include/pcap/pcap.h")) { throw 'Npcap SDK headers missing; run bootstrap-sdk.ps1 or pass -NpcapSdk.' }
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$install) { throw 'Visual Studio C++ Build Tools required.' }
$env:LAB02_VCVARS = "$install\VC\Auxiliary\Build\vcvars64.bat"
$env:LAB02_SDK = $sdk
New-Item -ItemType Directory -Force "$PSScriptRoot/bin" | Out-Null
& cmd /d /c "$PSScriptRoot/build-msvc.cmd"
if ($LASTEXITCODE -ne 0) { throw 'C++ build failed' }
