; Night Tech Sentinel client installer (Inno Setup 6). Built by build.ps1.
; Interactive: asks for the enrollment code from the Sentinel console.
; Silent:      NightTechSentinel-Setup.exe /VERYSILENT /CODE=NTS1.... [/UNATTENDED=1] [/NODESKTOP=1] [/NOSHELL=1] [/NOSCRIPTS=1] [/AUTORESTART=1]

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define AppName "Night Tech Sentinel"
#define AppPublisher "Night Tech Solutions"
#define AppURL "https://nighttech.solutions/business-it/"
#define AgentExe "NightTechSentinelAgent.exe"
#define TrayExe "NightTechSentinel.exe"

[Setup]
; Never change AppId after the first release.
AppId={{B3C1A7E4-2F6D-4E8B-9A51-7C0D3E9F2A16}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\Night Tech Sentinel
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=admin
OutputDir=Output
OutputBaseFilename=NightTechSentinel-Setup
SetupIconFile=..\src\NightTech.Sentinel.Tray\Assets\sentinel.ico
UninstallDisplayIcon={app}\{#TrayExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
CloseApplications=force

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This installs [name/ver].%n%nSentinel lets Night Tech Solutions keep an eye on this computer's health, security and backups, and fix problems remotely. A technician can only connect when you allow it, and a banner shows the whole time.%n%nYou'll need the enrollment code Night Tech gave you.

[Files]
Source: "..\publish\sentinel\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
; The taskbar icon starts for everyone who signs in.
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NightTechSentinel"; ValueData: """{app}\{#TrayExe}"""; Flags: uninsdeletevalue

[Run]
Filename: "{sys}\sc.exe"; Parameters: "create NightTechSentinel binPath= ""\""{app}\{#AgentExe}\"""" start= delayed-auto obj= LocalSystem DisplayName= ""Night Tech Sentinel"""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "description NightTechSentinel ""Lets Night Tech Solutions monitor and look after this PC. Remote access only with your permission."""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure NightTechSentinel reset= 86400 actions= restart/60000/restart/60000/restart/300000"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start NightTechSentinel"; Flags: runhidden waituntilterminated
Filename: "{app}\{#TrayExe}"; Flags: nowait runasoriginaluser skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop NightTechSentinel"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#TrayExe}"; Flags: runhidden waituntilterminated; RunOnceId: "StopTray"
Filename: "{sys}\sc.exe"; Parameters: "delete NightTechSentinel"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"
Filename: "{app}\{#AgentExe}"; Parameters: "forget"; Flags: runhidden waituntilterminated; RunOnceId: "Forget"

[Code]
var
  CodePage: TInputQueryWizardPage;
  OptionsPage: TInputOptionWizardPage;

function Param(Name: String): String;
begin
  Result := ExpandConstant('{param:' + Name + '|}');
end;

function Upgrading: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonappdata}\Night Tech Solutions\Sentinel\agent.json'));
end;

procedure InitializeWizard;
begin
  CodePage := CreateInputQueryPage(wpWelcome, 'Enrollment code', 'Connect this PC to Night Tech',
    'Paste the code from Night Tech Solutions. It starts with NTS1.');
  CodePage.Add('Code:', False);
  CodePage.Values[0] := Param('CODE');
  OptionsPage := CreateInputOptionPage(CodePage.ID, 'Remote access', 'What may Night Tech do on this PC?',
    'These settings stay on this PC; Night Tech''s server can''t change them. To change them later, reinstall Sentinel.', False, False);
  OptionsPage.Add('Allow remote desktop (with your permission each time)');
  OptionsPage.Add('Allow a remote command window (with your permission each time)');
  OptionsPage.Add('Allow maintenance scripts (with your permission each time)');
  OptionsPage.Add('Unattended: allow these without asking (only for servers or PCs nobody sits at)');
  OptionsPage.Values[0] := Param('NODESKTOP') <> '1';
  OptionsPage.Values[1] := Param('NOSHELL') <> '1';
  OptionsPage.Values[2] := Param('NOSCRIPTS') <> '1';
  OptionsPage.Values[3] := Param('UNATTENDED') = '1';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  // An upgrade keeps the PC's existing setup.
  Result := Upgrading and ((PageID = CodePage.ID) or (PageID = OptionsPage.ID));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = CodePage.ID) and (Copy(Trim(CodePage.Values[0]), 1, 5) <> 'NTS1.') then
  begin
    MsgBox('That doesn''t look like a Sentinel code. Copy it again from Night Tech; it starts with NTS1.', mbError, MB_OK);
    Result := False;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Args: String;
  Code: Integer;
begin
  if CurStep = ssInstall then
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop NightTechSentinel', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if (CurStep = ssPostInstall) and not Upgrading then
  begin
    Args := 'enroll "' + Trim(CodePage.Values[0]) + '"';
    if not OptionsPage.Values[0] then Args := Args + ' --no-remote-desktop';
    if not OptionsPage.Values[1] then Args := Args + ' --no-remote-shell';
    if not OptionsPage.Values[2] then Args := Args + ' --no-scripts';
    if OptionsPage.Values[3] then Args := Args + ' --unattended';
    if Param('AUTORESTART') = '1' then Args := Args + ' --restart-without-asking';
    if not Exec(ExpandConstant('{app}\{#AgentExe}'), Args, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
      MsgBox('Sentinel was installed, but this PC couldn''t join Night Tech (code ' + IntToStr(Code) + '). Check the internet connection and the enrollment code, then run the installer again, or call Night Tech at (864) 381-8510.', mbError, MB_OK);
  end;
end;
