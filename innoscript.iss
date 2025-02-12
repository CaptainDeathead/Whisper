; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define MyAppName "Whisper"
#define MyAppVersion "1.0"
#define MyAppPublisher "Plazma Software"
#define MyAppURL "https://github.com/CaptainDeathead/Whisper"
#define MyAppExeName "whisper.exe"

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{687CAACD-ED6E-4B42-B5B6-86BA0C4363CB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
; "ArchitecturesAllowed=x64compatible" specifies that Setup cannot run
; on anything but x64 and Windows 11 on Arm.
ArchitecturesAllowed=x64compatible
; "ArchitecturesInstallIn64BitMode=x64compatible" requests that the
; install be done in "64-bit mode" on x64 or Windows 11 on Arm,
; meaning it should use the native 64-bit Program Files directory and
; the 64-bit view of the registry.
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
LicenseFile=D:\Nextcloud\HardDrive\PythonProjects\Whisper\LICENCE.txt
InfoBeforeFile=D:\Nextcloud\HardDrive\PythonProjects\Whisper\Installation\BEFORE_INSTALL.txt
InfoAfterFile=D:\Nextcloud\HardDrive\PythonProjects\Whisper\Installation\AFTER_INSTALL.txt
; Remove the following line to run in administrative install mode (install for all users).
PrivilegesRequired=lowest
OutputDir=D:\Nextcloud\HardDrive\PythonProjects\Whisper\Build
OutputBaseFilename=whispersetup
SetupIconFile=D:\Nextcloud\HardDrive\PythonProjects\Whisper\whisper.ico
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "D:\Nextcloud\HardDrive\PythonProjects\Whisper\Build\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\Nextcloud\HardDrive\PythonProjects\Whisper\whisper.ico"; DestDir: "{app}"; Flags: ignoreversion

; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

