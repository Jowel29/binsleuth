<#
    Builds the re-skill benchmark samples from src\*.c into bin\*.exe using MSVC.

    These samples are HARMLESS by design (see the header in each .c file): they are
    built to look suspicious to a static scanner so we can test an AI analyst, but
    they never run the APIs they import and never touch the network or registry.

    The .exe files are NOT committed to git (see .gitignore). Each person builds
    them locally with this script, because antivirus and GitHub may flag binaries
    that are deliberately crafted to resemble malware.

    Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
#>
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$src  = Join-Path $root "src"
$bin  = Join-Path $root "bin"
New-Item -ItemType Directory -Force $bin | Out-Null

# Locate the MSVC developer environment (vcvars64.bat).
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$vcvars = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsPath) { $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat" }
}
if (-not $vcvars -or -not (Test-Path $vcvars)) {
    $vcvars = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat" -ErrorAction SilentlyContinue |
              Select-Object -First 1 -ExpandProperty FullName
}
if (-not $vcvars) { throw "MSVC not found. Install Visual Studio with the 'Desktop development with C++' workload." }

$sources = Get-ChildItem (Join-Path $src "*.c") | Sort-Object Name
Write-Host "Building $($sources.Count) sample(s) with:`n  $vcvars`n"

foreach ($s in $sources) {
    $exe = Join-Path $bin ($s.BaseName + ".exe")
    $obj = Join-Path $bin ($s.BaseName + ".obj")
    $rc  = Join-Path $src ($s.BaseName + ".rc")      # optional resource script
    $res = Join-Path $bin ($s.BaseName + ".res")

    # /nologo quiet, /W3 warnings, /O1 small. Compile an .rc of the same name if present.
    $resArg = ""
    if (Test-Path $rc) {
        cmd /c "`"$vcvars`" >nul 2>nul && rc /nologo /fo `"$res`" `"$rc`""
        $resArg = "`"$res`""
    }
    $cmd = "`"$vcvars`" >nul 2>nul && cl /nologo /W3 /O1 `"$($s.FullName)`" /Fe:`"$exe`" /Fo:`"$obj`" /link user32.lib advapi32.lib $resArg"
    cmd /c $cmd
    if (Test-Path $exe) {
        $sha = (Get-FileHash $exe -Algorithm SHA256).Hash.Substring(0, 16)
        Write-Host ("  OK  {0,-24} {1,8:N0} bytes  sha256:{2}..." -f $s.Name, (Get-Item $exe).Length, $sha)
    } else {
        Write-Host "  FAIL $($s.Name)" -ForegroundColor Red
    }
    Remove-Item $obj, $res -ErrorAction SilentlyContinue
}
Write-Host "`nDone. Samples in: $bin"
