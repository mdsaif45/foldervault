; FolderVault installer (Inno Setup). Per-user, no admin required.
; Built by build-release.ps1, which passes AppVersion / Rel / Root.
;   iscc /DAppVersion=0.1.0 /DRel=...\target\release /DRoot=...\foldervault foldervault.iss

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef Rel
  #define Rel "..\target\release"
#endif
#ifndef Root
  #define Root ".."
#endif

[Setup]
AppId={{9B7E5F2C-0A41-4D8E-9F3B-FOLDERVAULT01}
AppName=FolderVault
AppVersion={#AppVersion}
AppPublisher=FolderVault
DefaultDirName={autopf}\FolderVault
DefaultGroupName=FolderVault
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\FolderVault.exe
OutputDir={#Root}\dist
OutputBaseFilename=FolderVault-{#AppVersion}-installer
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile={#Root}\assets\app.ico

[Files]
Source: "{#Rel}\FolderVault.exe";      DestDir: "{app}"; Flags: ignoreversion
Source: "{#Rel}\vault_shellext.dll";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#Rel}\fvlt.exe";             DestDir: "{app}"; Flags: ignoreversion
Source: "{#Root}\installer\PACKAGE-README.txt"; DestDir: "{app}"; DestName: "README.txt"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\FolderVault";           Filename: "{app}\FolderVault.exe"
Name: "{group}\Uninstall FolderVault"; Filename: "{uninstallexe}"

[Run]
; first-run setup: registers the right-click menu + .fvlt association and
; shows the one-time recovery code. Runs as the user, no elevation.
Filename: "{app}\FolderVault.exe"; Parameters: "setup"; \
    Description: "Set up FolderVault (register right-click menu + recovery code)"; \
    Flags: postinstall nowait skipifsilent

[UninstallRun]
; clean up the HKCU integration before files are removed
Filename: "{app}\FolderVault.exe"; Parameters: "unregister"; Flags: runhidden; RunOnceId: "fvltunreg"
