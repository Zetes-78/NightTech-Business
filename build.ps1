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
    @{ Name = "Night Tech Security Checkup"; Project = "src\NightTech.SecurityCheckup\NightTech.SecurityCheckup.csproj"; Out = "publish\securitycheckup"; Iss = "installer\NightTechSecurityCheckup.iss"; Setup = "NightTechSecurityCheckup-Setup.exe"; Folder = "Security Checkup" },
    @{ Name = "Night Tech Network Scan"; Project = "src\NightTech.NetworkScan\NightTech.NetworkScan.csproj"; Out = "publish\networkscan"; Iss = "installer\NightTechNetworkScan.iss"; Setup = "NightTechNetworkScan-Setup.exe"; Folder = "Network Scan" },
    # AI Setup carries the Private AI program it installs, in a "server" folder next to it.
    @{ Name = "Night Tech AI Setup"; Project = "src\NightTech.AiSetup\NightTech.AiSetup.csproj"; Out = "publish\aisetup"; Iss = "installer\NightTechAiSetup.iss"; Setup = "NightTechAiSetup-Setup.exe"; Folder = "AI Setup"; Server = "src\NightTech.PrivateAi\NightTech.PrivateAi.csproj" }
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
    if ($t.Server) {
        $sv = Get-ProjectVersion $t.Server
        Write-Host "   with Night Tech Private AI $sv" -ForegroundColor Cyan
        dotnet publish $t.Server -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
            -p:IncludeNativeLibrariesForSelfExtract=false -p:DebugType=None -p:Version=$sv -o "$($t.Out)\server"
        if ($LASTEXITCODE -ne 0) { throw "Publishing Night Tech Private AI failed." }
        if (-not (Test-Path "$($t.Out)\server\wwwroot\index.html")) { throw "Night Tech Private AI was published without its web page." }
    }
    & $iscc "/DAppVersion=$v" $t.Iss
    if ($LASTEXITCODE -ne 0) { throw "Building the $($t.Name) installer failed." }
    Write-Hash "installer\Output\$($t.Setup)"
    New-Item -ItemType Directory -Force "$kit\$($t.Folder)" | Out-Null
    Copy-Item -Recurse "$($t.Out)\*" "$kit\$($t.Folder)"
    "This file tells Night Tech tools to keep their logs and reports on this USB stick. Don't delete it." |
        Out-File -Encoding ascii "$kit\$($t.Folder)\portable.txt"
}

# Night Tech Sentinel client: the service and the taskbar icon go in one folder and one installer (not on the USB kit).
$sv = Get-ProjectVersion "src\NightTech.Sentinel.Agent\NightTech.Sentinel.Agent.csproj"
Write-Host "== Night Tech Sentinel $sv ==" -ForegroundColor Cyan
foreach ($p in @("src\NightTech.Sentinel.Agent\NightTech.Sentinel.Agent.csproj", "src\NightTech.Sentinel.Tray\NightTech.Sentinel.Tray.csproj")) {
    # Native files stay next to the exe in Program Files: never unpacked into a folder other accounts can write to.
    dotnet publish $p -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=false -p:DebugType=None -p:Version=$sv -o publish\sentinel
    if ($LASTEXITCODE -ne 0) { throw "Publishing $p failed." }
}
& $iscc "/DAppVersion=$sv" installer\NightTechSentinel.iss
if ($LASTEXITCODE -ne 0) { throw "Building the Sentinel installer failed." }
Write-Hash "installer\Output\NightTechSentinel-Setup.exe"

# Sentinel Signer, for technicians' own PCs (one exe, nothing to install).
dotnet publish src\NightTech.Sentinel.Signer\NightTech.Sentinel.Signer.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:Version=$sv -o publish\signer
if ($LASTEXITCODE -ne 0) { throw "Publishing Sentinel Signer failed." }
Copy-Item publish\signer\NightTechSentinelSigner.exe installer\Output\NightTechSentinelSigner.exe
Write-Hash "installer\Output\NightTechSentinelSigner.exe"

Copy-Item packaging\USB-README.txt "$kit\README.txt"
$zip = "installer\Output\NightTechBusinessKit-USB.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "publish\usb\*" -DestinationPath $zip
Write-Hash $zip
Write-Host "Done. Everything is in installer\Output\" -ForegroundColor Green
