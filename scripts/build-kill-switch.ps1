$ErrorActionPreference = "Stop"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
  throw "Visual Studio Build Tools were not found"
}

$vcvars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "VC\Auxiliary\Build\vcvars64.bat" | Select-Object -First 1
if (-not $vcvars) {
  throw "MSVC x64 build environment was not found"
}

$outputDirectory = Join-Path $PSScriptRoot "..\vendor\kill-switch\windows-x64"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$source = Join-Path $PSScriptRoot "..\native\kill-switch.cpp"
$executable = Join-Path $outputDirectory "levik-kill-switch.exe"
$object = Join-Path $outputDirectory "levik-kill-switch.obj"
$command = 'call "{0}" && cl.exe /nologo /std:c++17 /EHsc /W4 /WX /DUNICODE /D_UNICODE /O2 /MT "{1}" /Fo:"{2}" /Fe:"{3}" /link fwpuclnt.lib iphlpapi.lib rpcrt4.lib userenv.lib ws2_32.lib' -f $vcvars, $source, $object, $executable

& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) {
  throw "Kill Switch helper compilation failed with exit code $LASTEXITCODE"
}

& $executable self-test
if ($LASTEXITCODE -ne 0) {
  throw "Kill Switch helper self-test failed with exit code $LASTEXITCODE"
}
