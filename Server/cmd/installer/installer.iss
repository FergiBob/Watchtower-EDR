[Setup]
AppName=Watchtower EDR
AppVersion=1.0
DefaultDirName={autopf}\WatchtowerEDR
DefaultGroupName=Watchtower EDR
PrivilegesRequired=admin
OutputBaseFilename=WatchtowerServerInstaller

; --- Icon Settings ---
SetupIconFile=.\icon.ico
UninstallDisplayIcon={app}\watchtower.exe

[Files]
Source: "..\..\watchtower.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\web\*"; DestDir: "{app}\web"; Flags: ignoreversion recursesubdirs
Source: "..\..\internal\data\*"; DestDir: "{app}\internal\data"; Flags: ignoreversion recursesubdirs

[Dirs]
; Granting full permissions to the data folder ensures the Go app can write config.yaml and databases[cite: 2]
Name: "{app}\internal\data"; Permissions: everyone-full[cite: 2]
Name: "{app}\internal\data\logs"; Permissions: everyone-full[cite: 2]

[Icons]
Name: "{group}\Watchtower EDR"; Filename: "{app}\watchtower.exe"; IconFilename: "{app}\icon.ico"

[Run]
; WorkingDir is critical so the Go app's relative path logic finds the internal folder[cite: 2]
Filename: "{app}\watchtower.exe"; \
    Parameters: "seed -user ""{code:GetUser}"" -email ""{code:GetEmail}"" -pass ""{code:GetPass}"" -fqdn ""{code:GetFQDN}"" -nist ""{code:GetNistKey}"""; \
    WorkingDir: "{app}"; Flags: runhidden[cite: 2]
    
; Register and start the background service[cite: 2]
Filename: "{sys}\sc.exe"; Parameters: "create WatchtowerEDR binPath= ""{app}\watchtower.exe"" start= auto"; Flags: runhidden[cite: 2]
Filename: "{sys}\sc.exe"; Parameters: "start WatchtowerEDR"; Flags: runhidden[cite: 2]

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop WatchtowerEDR"; Flags: runhidden; RunOnceId: "StopWatchtowerService"[cite: 2]
Filename: "{sys}\sc.exe"; Parameters: "delete WatchtowerEDR"; Flags: runhidden; RunOnceId: "DeleteWatchtowerService"[cite: 2]

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

  // Using False as the second parameter acts as an empty default string in this context[cite: 2]
  Idx := ConfigPage.Add('Server FQDN (e.g. edr.example.com):', False);
  Idx := ConfigPage.Add('NIST NVD API Key (https://nvd.nist.gov/developers/request-an-api-key):', False);
  Idx := ConfigPage.Add('Admin Username:', False);
  Idx := ConfigPage.Add('Admin Email:', False);
  Idx := ConfigPage.Add('Admin Password (4-16 characters):', True);

  // Set default admin username
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

{ Helper functions to pass Wizard data to the [Run] section[cite: 2] }

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