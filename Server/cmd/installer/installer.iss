[Setup]
AppName=Watchtower EDR
AppVersion=1.0
DefaultDirName={autopf}\WatchtowerEDR
DefaultGroupName=Watchtower EDR
PrivilegesRequired=admin
OutputBaseFilename=WatchtowerServerInstaller
; FIXED: Removed the trailing 'os' from x64
ArchitecturesInstallIn64BitMode=x64compatible

; --- Icon Settings ---
SetupIconFile=.\icon.ico
UninstallDisplayIcon={app}\watchtower.exe

[Files]
Source: "..\..\watchtower.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\web\*"; DestDir: "{app}\web"; Flags: ignoreversion recursesubdirs
Source: "..\..\internal\data\*"; DestDir: "{app}\internal\data"; Flags: ignoreversion recursesubdirs

[Dirs]
; Ensure the System account and Users have explicit rights to modify files here
Name: "{app}\internal\data"; Permissions: users-modify system-full
Name: "{app}\internal\data\logs"; Permissions: users-modify system-full

[Icons]
Name: "{group}\Watchtower EDR"; Filename: "{app}\watchtower.exe"; IconFilename: "{app}\icon.ico"

[Run]
; 1. Provisioning - Ensure this runs before the service starts
Filename: "{app}\watchtower.exe"; \
    Parameters: "seed -user ""{code:GetUser}"" -email ""{code:GetEmail}"" -pass ""{code:GetPass}"" -fqdn ""{code:GetFQDN}"" -nist ""{code:GetNistKey}"""; \
    WorkingDir: "{app}"; Flags: runhidden waituntilterminated

; NEW: Delete the log created by 'seed' so the Service starts fresh
Filename: "{cmd}"; Parameters: "/c del ""{app}\internal\data\logs\watchtower.log"""; Flags: runhidden

; 2. Registration - Using {quote} for cleaner path handling. 
; Note: The space after 'binPath=' is mandatory for sc.exe
Filename: "{sys}\sc.exe"; \
    Parameters: "create WatchtowerEDR binPath= ""\""{app}\watchtower.exe\"""" DisplayName= ""Watchtower EDR"" start= auto"; \
    Flags: runhidden waituntilterminated

; 3. Description - Helpful for users looking at services.msc
Filename: "{sys}\sc.exe"; \
    Parameters: "description WatchtowerEDR ""Watchtower Endpoint Detection and Response Server"""; \
    Flags: runhidden

; 4. Startup
Filename: "{sys}\sc.exe"; Parameters: "start WatchtowerEDR"; Flags: runhidden

[UninstallRun]
; Stop and Delete with 'RunOnceId' to prevent duplicate execution
Filename: "{sys}\sc.exe"; Parameters: "stop WatchtowerEDR"; Flags: runhidden; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete WatchtowerEDR"; Flags: runhidden; RunOnceId: "DeleteService"
[Code]
var
  ConfigPage: TInputQueryWizardPage;

procedure InitializeWizard;
var
  Idx: Integer;
begin
  ConfigPage := CreateInputQueryPage(wpSelectDir,
    'Server Configuration', 'Admin Account & Network Settings',
    'Please enter the initial setup details for your Watchtower EDR instance.');

  Idx := ConfigPage.Add('Server FQDN (e.g. edr.example.com):', False);
  Idx := ConfigPage.Add('NIST NVD API Key:', False);
  Idx := ConfigPage.Add('Admin Username:', False);
  Idx := ConfigPage.Add('Admin Email:', False);
  Idx := ConfigPage.Add('Admin Password (4-16 characters):', True);

  ConfigPage.Values[2] := 'admin';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  S: String;
begin
  Result := True;
  if (ConfigPage <> nil) and (CurPageID = ConfigPage.ID) then begin
    S := ConfigPage.Values[4];
    if (Length(S) < 4) or (Length(S) > 16) then begin
      MsgBox('Password must be between 4 and 16 characters long.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function GetFQDN(Param: String): String;
begin
  if ConfigPage = nil then Result := '' else Result := ConfigPage.Values[0];
end;

function GetNistKey(Param: String): String;
begin
  if ConfigPage = nil then Result := '' else Result := ConfigPage.Values[1];
end;

function GetUser(Param: String): String;
begin
  if ConfigPage = nil then Result := '' else Result := ConfigPage.Values[2];
end;

function GetEmail(Param: String): String;
begin
  if ConfigPage = nil then Result := '' else Result := ConfigPage.Values[3];
end;

function GetPass(Param: String): String;
begin
  if ConfigPage = nil then Result := '' else Result := ConfigPage.Values[4];
end;
