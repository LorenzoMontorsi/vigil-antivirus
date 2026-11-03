<#
.SYNOPSIS
  Compila il minifilter VigilFlt con cl/link di MSVC e il WDK da NuGet.
.DESCRIPTION
  Non richiede l'estensione WDK di Visual Studio: usa direttamente header e
  librerie dei pacchetti in .\packages (vedi packages.config).
  Opzioni allineate a quelle predefinite dei progetti driver del WDK.
#>
param([ValidateSet('Release', 'Debug')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$kit = '10.0.26100.6584'
$wdk = Join-Path $root "packages\Microsoft.Windows.WDK.x64.$kit\c"
$inc = Join-Path $wdk 'Include\10.0.26100.0'
$sdkInc = Join-Path $root "packages\Microsoft.Windows.SDK.CPP.$kit\c\Include\10.0.26100.0"
$lib = Join-Path $wdk 'Lib\10.0.26100.0\km\x64'
$src = Join-Path $root 'VigilFlt'
$out = Join-Path $root "build\$Configuration"
$obj = Join-Path $root "build\obj\$Configuration"
New-Item -ItemType Directory -Force $out, $obj | Out-Null

if (-not (Test-Path $inc)) { throw "WDK non trovato: esegui  tools\nuget.exe restore packages.config -PackagesDirectory packages" }

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -version '[17.0,18.0)' -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'

$opt = if ($Configuration -eq 'Release') { '/O2 /Oy- /DNDEBUG' } else { '/Od /Oi /DDBG=1' }
$defines = '/D_WIN64 /D_AMD64_ /DAMD64 /DWINNT=1 /DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DPOOL_NX_OPTIN=1 /DDEPRECATE_DDK_FUNCTIONS=1'
$cflags = "/nologo /c /kernel /Zi /W4 /WX /GS /Gy /GF /GR- /Zp8 /Zc:wchar_t- /Zc:inline /fp:precise /cbstring $opt $defines " +
          "/I`"$inc\km`" /I`"$inc\km\crt`" /I`"$sdkInc\shared`" /FI`"$sdkInc\shared\warning.h`" /Fo`"$obj\\`" /Fd`"$obj\vc.pdb`""
# /INTEGRITYCHECK: richiesto da ObRegisterCallbacks (protezione del processo del servizio).
$lflags = "/nologo /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry /NODEFAULTLIB /RELEASE /DEBUG /OPT:REF /OPT:ICF /INTEGRITYCHECK " +
          "/MERGE:_TEXT=.text;_PAGE=PAGE /SECTION:INIT,d /IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221 " +
          "/LIBPATH:`"$lib`" ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib fltMgr.lib " +
          "/PDB:`"$out\VigilFlt.pdb`" /OUT:`"$out\VigilFlt.sys`""

$env:PATH = "$(Split-Path $vswhere);$env:PATH"   # vcvars64 usa vswhere
$cmd = "call `"$vcvars`" >nul && cl $cflags `"$src\VigilFlt.c`" && link $lflags `"$obj\VigilFlt.obj`""
$ErrorActionPreference = 'Continue'   # l'esito lo decide il codice di uscita, non lo stderr
cmd /c "$cmd 2>&1" | Tee-Object -FilePath (Join-Path $obj 'build.log')
if ($LASTEXITCODE -ne 0) { throw "Compilazione fallita ($LASTEXITCODE)" }
$ErrorActionPreference = 'Stop'
Copy-Item (Join-Path $src 'VigilFlt.inf') $out -Force
Get-Item (Join-Path $out 'VigilFlt.sys') | Select-Object FullName, Length, LastWriteTime
