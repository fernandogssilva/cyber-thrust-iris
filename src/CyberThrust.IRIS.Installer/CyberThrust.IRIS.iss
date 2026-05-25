; ===========================================================
;  CyberThrust.IRIS — Inno Setup script
;  Build: ISCC.exe CyberThrust.IRIS.iss
; ===========================================================

#define MyAppName      "CyberThrust.IRIS"
#define MyAppVersion   "0.4.10"
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
; Empacota TODO o conteúdo do publish (EXE apphost + DLL gerenciada + ~80 DLLs do runtime + runtimeconfig.json + deps.json + WebAssets).
; CRITICAL: o EXE é apenas o apphost — sem as DLLs (especialmente CyberThrust.IRIS.dll, .runtimeconfig.json e .deps.json), o app falha com
; ".NET Runtime: The application to execute does not exist: CyberThrust.IRIS.dll" antes mesmo de inicializar o logger.
Source: "..\..\publish\win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\CyberThrust.IRIS.App\appsettings.local.json.example"; DestDir: "{app}"; DestName: "appsettings.local.json.example"; Flags: ignoreversion onlyifdoesntexist
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

; Aviso ético de uso fica no LICENSE (Apache-2.0 ethical-use notice) e em
; docs\INSTALL_PT.txt (mostrado pelo wizard via InfoBeforeFile).
; Nenhum MsgBox interativo aqui — permite instalação 100% silenciosa via /VERYSILENT.
