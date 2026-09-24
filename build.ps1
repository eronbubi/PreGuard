# Builds PreGuard.exe with the C# compiler that ships with Windows (.NET Framework 4.8) - no SDK needed.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$out = Join-Path $root 'dist'
$obj = Join-Path $root 'obj'
New-Item -ItemType Directory -Force $out, $obj | Out-Null
$sources = Get-ChildItem (Join-Path $root 'src') -Filter *.cs | ForEach-Object FullName
$refs = @('-r:System.dll', '-r:System.Core.dll', '-r:System.Drawing.dll', '-r:System.Windows.Forms.dll', '-r:System.Management.dll')

# Pass 1: build without an icon so the program can draw its own .ico.
$bootstrap = Join-Path $obj 'PreGuard-bootstrap.exe'
& $csc -nologo -optimize+ -target:winexe "-out:$bootstrap" @refs @sources
if ($LASTEXITCODE -ne 0) { throw "Kompilieren fehlgeschlagen (Schritt 1)" }
$ico = Join-Path $obj 'PreGuard.ico'
Start-Process -FilePath $bootstrap -ArgumentList '--make-icon', "`"$ico`"" -Wait -NoNewWindow

# Pass 2: final exe with icon and manifest.
& $csc -nologo -optimize+ -target:winexe "-out:$(Join-Path $out 'PreGuard.exe')" "-win32icon:$ico" "-win32manifest:$(Join-Path $root 'PreGuard.manifest')" @refs @sources
if ($LASTEXITCODE -ne 0) { throw "Kompilieren fehlgeschlagen (Schritt 2)" }
Write-Host "Fertig: $(Join-Path $out 'PreGuard.exe')"
