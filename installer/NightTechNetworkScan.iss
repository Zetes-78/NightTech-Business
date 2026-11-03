; Night Tech Network Scan installer (Inno Setup 6)
; Built by build.ps1 or the GitHub workflow:  ISCC /DAppVersion=0.1.0 installer\NightTechNetworkScan.iss

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define AppName "Night Tech Network Scan"
#define AppPublisher "Night Tech Solutions"
#define AppURL "https://nighttech.solutions"
#define AppExe "NightTechNetworkScan.exe"

[Setup]
AppId={{793D269E-6C99-4581-ACB5-F218EAED3594}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={localappdata}\Programs\Night Tech Network Scan
DefaultGroupName=Night Tech Network Scan
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=Output
OutputBaseFilename=NightTechNetworkScan-Setup
SetupIconFile=NightTechNetworkScan.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\publish\networkscan\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\packaging\USB-README.txt"; DestDir: "{app}"; DestName: "README.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\Night Tech Network Scan"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall Night Tech Network Scan"; Filename: "{uninstallexe}"
Name: "{userdesktop}\Night Tech Network Scan"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Start Night Tech Network Scan now"; Flags: shellexec nowait postinstall skipifsilent
