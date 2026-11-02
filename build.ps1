# Builds, tests and packages Night Tech Business tools on Windows.
# Needs: .NET 8 SDK and Inno Setup 6.  Usage: powershell -ExecutionPolicy Bypass -File .\build.ps1 [-SkipTests]
# Each tool's version comes from its <Version> in the .csproj.
param([switch]$SkipTests)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "The .NET 8 SDK was not found (winget install Microsoft.DotNet.SDK.8)." }
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 was not found (winget install JRSoftware.InnoSetup)." }

if (-not $SkipTests) {
    dotnet test tests\NightTech.Business.Tests\NightTech.Business.Tests.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw "Tests failed. Nothing was packaged." }
}

function Get-ProjectVersion([string]$csproj) {
    $v = ([xml](Get-Content $csproj)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
    if (-not $v) { throw "No <Version> in $csproj" }
    return $v
}
function Write-Hash([string]$file) {
    $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
    "$hash  $(Split-Path $file -Leaf)" | Out-File -Encoding ascii "$file.sha256.txt"
    Write-Host "  $(Split-Path $file -Leaf)  SHA-256 $hash"
}

$tools = @(
    @{ Name = "Night Tech Security Checkup"; Project = "src\NightTech.SecurityCheckup\NightTech.SecurityCheckup.csproj"; Out = "publish\securitycheckup"; Iss = "installer\NightTechSecurityCheckup.iss"; Setup = "NightTechSecurityCheckup-Setup.exe"; Folder = "Security Checkup" }
)

if (Test-Path publish) { Remove-Item -Recurse -Force publish }
New-Item -ItemType Directory -Force installer\Output | Out-Null
$kit = "publish\usb\Night Tech Business Kit"

foreach ($t in $tools) {
    $v = Get-ProjectVersion $t.Project
    Write-Host "== $($t.Name) $v ==" -ForegroundColor Cyan
    # Native files stay beside the exe, so nothing is unpacked into a customer's temp folder.
    dotnet publish $t.Project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=false -p:DebugType=None -p:Version=$v -o $t.Out
    if ($LASTEXITCODE -ne 0) { throw "Publishing $($t.Name) failed." }
    & $iscc "/DAppVersion=$v" $t.Iss
    if ($LASTEXITCODE -ne 0) { throw "Building the $($t.Name) installer failed." }
    Write-Hash "installer\Output\$($t.Setup)"
    New-Item -ItemType Directory -Force "$kit\$($t.Folder)" | Out-Null
    Copy-Item -Recurse "$($t.Out)\*" "$kit\$($t.Folder)"
    "This file tells Night Tech tools to keep their logs and reports on this USB stick. Don't delete it." |
        Out-File -Encoding ascii "$kit\$($t.Folder)\portable.txt"
}

Copy-Item packaging\USB-README.txt "$kit\README.txt"
$zip = "installer\Output\NightTechBusinessKit-USB.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "publish\usb\*" -DestinationPath $zip
Write-Hash $zip
Write-Host "Done. Everything is in installer\Output\" -ForegroundColor Green
