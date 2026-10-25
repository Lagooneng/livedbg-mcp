# Builds the integration-test target (needs the VS C++ workload).
#   powershell -File tests\fixtures\build.ps1
#   powershell -File tests\fixtures\build.ps1 -OutDir C:\tmp\x -ExeName t2.exe -PdbPath C:\tmp\x\t.pdb
# ASCII only: Windows PowerShell 5.1 misreads UTF-8 files without a BOM.
param(
    [string]$OutDir = '',
    [string]$ExeName = 'target.exe',
    [string]$PdbPath = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) { $OutDir = Join-Path $here 'bin' }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$pdbArg = if ($PdbPath) { "/PDB:`"$PdbPath`"" } else { '' }
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
# /GR- : RTTI off, like Unreal modules. /DEBUG:FULL : self-contained PDB.
cmd /c "`"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && cd /d `"$OutDir`" && cl /nologo /Zi /Od /EHsc /GR- `"$here\target.cpp`" /Fe:$ExeName /link /DEBUG:FULL $pdbArg"
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "built $OutDir\$ExeName"
