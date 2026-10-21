param([string]$Destination = (Join-Path $PSScriptRoot '../deps/npcap-sdk-1.16'))
$ErrorActionPreference = 'Stop'
$parent = Split-Path $Destination -Parent
New-Item -ItemType Directory -Force $parent | Out-Null
$archive = Join-Path $parent 'npcap-sdk-1.16.zip'
Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-sdk-1.16.zip' -OutFile $archive
$expected = 'F0A8BE7778EE3AE1B99BBBECB27A3FF0F6C111A4093F1C78C5C5A099607184DB'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'SDK SHA256 does not match the reviewed official download.'
}
Expand-Archive -LiteralPath $archive -DestinationPath $Destination -Force
Write-Host "Npcap SDK ready: $Destination"
