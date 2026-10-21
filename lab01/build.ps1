param([ValidateSet('MSVC','MinGW')][string]$Compiler = 'MSVC')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
New-Item -ItemType Directory -Force -Path "$root/bin" | Out-Null
if ($Compiler -eq 'MSVC') {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (!$install) { throw 'Install Visual Studio C++ Build Tools, or use -Compiler MinGW with modern MinGW-w64.' }
    $env:CHAT_VCVARS = "$install\VC\Auxiliary\Build\vcvars64.bat"
    & cmd /d /c "$root\build-msvc.cmd"
    if ($LASTEXITCODE -ne 0) { throw 'MSVC build failed' }
} else {
    foreach ($role in @('server', 'client')) {
        $extra = @(); if ($role -eq 'client') { $extra = @('-municode') }
        & g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -static @extra "$root/src/$role.cpp" -lws2_32 -o "$root/bin/chat_$role.exe"
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $role" }
    }
}
Write-Host 'Built lab01/bin/chat_server.exe and chat_client.exe'
