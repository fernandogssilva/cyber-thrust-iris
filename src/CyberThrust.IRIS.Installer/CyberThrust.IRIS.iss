; ===========================================================
;  CyberThrust.IRIS — Inno Setup script
;  Build: ISCC.exe CyberThrust.IRIS.iss
; ===========================================================

#define MyAppName      "CyberThrust.IRIS"
#define MyAppVersion   "0.2.0"
#define MyAppPublisher "CYBER THRUST"
#define MyAppURL       "https://github.com/fernandogssilva/cyber-thrust-iris"
#define MyAppExeName   "CyberThrust.IRIS.exe"

[Setup]
AppId={{A0010007-CYBR-THST-IRIS-000000000001}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion} (Apache-2.0 Open Source)
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
AppCopyright=Copyright (C) CYBER THRUST 2026
DefaultDirName={autopf}\CyberThrust\IRIS
DefaultGroupName=CyberThrust.IRIS
DisableProgramGroupPage=yes
DisableDirPage=no
LicenseFile=..\..\LICENSE
InfoBeforeFile=..\..\docs\INSTALL_PT.txt
OutputDir=..\..\publish\installer
OutputBaseFilename=CyberThrust.IRIS-{#MyAppVersion}-Setup
SetupIconFile=..\CyberThrust.IRIS.App\Assets\iris.ico
WizardImageFile=
WizardSmallImageFile=
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
MinVersion=10.0.19041
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Incident Response & Investigation Suite (Apache-2.0 Open Source)
ShowLanguageDialog=yes
LanguageDetectionMethod=uilanguage

[Languages]
Name: "ptbr";    MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\..\publish\win-x64\CyberThrust.IRIS.exe";   DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\publish\win-x64\appsettings.json";       DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\publish\win-x64\WebAssets\*";            DestDir: "{app}\WebAssets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\CyberThrust.IRIS.App\appsettings.local.json.example"; DestDir: "{app}"; DestName: "appsettings.local.json.example"; Flags: ignoreversion
Source: "..\..\docs\INSTALL_PT.txt";                    DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\docs\ERROR_CODES.md";                    DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\docs\ENTRA_SETUP.md";                    DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\docs\CROWDSTRIKE_SETUP.md";              DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\LICENSE";                                DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Documentação";              Filename: "{app}\docs"
Name: "{group}\Pasta de instalação";       Filename: "{app}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";        Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\{#MyAppExeName}"
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  MsgBox(
    'CyberThrust.IRIS — Open Source DFIR Suite (Apache 2.0).' + #13#10#13#10 +
    'IMPORTANTE: esta ferramenta executa Resposta a Incidente e Forense Remota.' + #13#10 +
    'Use somente contra hosts para os quais você tem autorização escrita.' + #13#10#13#10 +
    'Uso não autorizado pode violar a Lei 12.737/2012 (Lei Carolina Dieckmann),' + #13#10 +
    'CFAA (EUA), GDPR (UE) e equivalentes.' + #13#10#13#10 +
    'Continuar com a instalação?',
    mbConfirmation, MB_YESNO);
end;
