; CryptoPad Inno Setup installer script
; Called from CI (repo root) with:
;   ISCC.exe /DAppVersion=X.Y.Z /DSrcDir=<deploy_dir> /O<output_dir> share\windows\installer.iss

#ifndef AppVersion
  #error AppVersion not defined – pass /DAppVersion=X.Y.Z on the command line
#endif
#ifndef SrcDir
  #error SrcDir not defined – pass /DSrcDir=<path> on the command line
#endif

[Setup]
AppName=CryptoPad
AppVersion={#AppVersion}
AppPublisher=CryptoPad
AppId={{B4F2A1C3-7E8D-4F5A-9B2E-1D6C3A8F0E7B}
DefaultDirName={autopf}\CryptoPad
DefaultGroupName=CryptoPad
OutputBaseFilename=cryptopad-{#AppVersion}-windows-setup
Compression=lzma/ultra64
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
SetupIconFile=cryptopad.ico
UninstallDisplayIcon={app}\cryptopad.exe
WizardStyle=modern
MinVersion=10.0

[Languages]
Name: "french";  MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\CryptoPad";       Filename: "{app}\cryptopad.exe"
Name: "{commondesktop}\CryptoPad"; Filename: "{app}\cryptopad.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Run]
Filename: "{app}\cryptopad.exe"; \
  Description: "{cm:LaunchProgram,CryptoPad}"; \
  Flags: nowait postinstall skipifsilent
