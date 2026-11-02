; Night Tech AI Setup installer (Inno Setup 6)
; Installs the technician tool. The tool itself asks for administrator rights when it runs.
; Built by build.ps1 or the GitHub workflow:  ISCC /DAppVersion=0.1.0 installer\NightTechAiSetup.iss

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define AppName "Night Tech AI Setup"
#define AppPublisher "Night Tech Solutions"
#define AppURL "https://nighttech.solutions"
#define AppExe "NightTechAiSetup.exe"

[Setup]
AppId={{B8D763A7-E96F-4162-8820-5E5675E32C5E}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\Night Tech\AI Setup
DefaultGroupName=Night Tech AI Setup
DisableProgramGroupPage=yes
; Installed for the whole computer, where only administrators can change it: this tool runs as administrator
; and copies Private AI from its own folder into Program Files.
PrivilegesRequired=admin
OutputDir=Output
OutputBaseFilename=NightTechAiSetup-Setup
SetupIconFile=NightTechAiSetup.ico
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
Source: "..\publish\aisetup\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\packaging\USB-README.txt"; DestDir: "{app}"; DestName: "README.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\Night Tech AI Setup"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall Night Tech AI Setup"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Night Tech AI Setup"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Start Night Tech AI Setup now"; Flags: shellexec nowait postinstall skipifsilent
