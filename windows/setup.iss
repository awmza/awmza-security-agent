; AWMZA Security - Windows installer (Inno Setup 6). Silent: AWMZA-Security-Setup.exe /VERYSILENT /TOKEN=awe_...
#define AppVer "1.1.0"
[Setup]
AppId={{D562ED85-4C32-4648-A731-4403EA359887}
AppName=AWMZA Security Agent
AppVersion={#AppVer}
AppPublisher=AWMZA - HUSSAIN MUHAMMAD MAJID
AppPublisherURL=https://security.awmza.com/
AppSupportURL=https://security.awmza.com/
DefaultDirName={autopf64}\AWMZA Security
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=out
OutputBaseFilename=AWMZA-Security-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=AWMZA Security Agent
VersionInfoVersion={#AppVer}
VersionInfoCompany=AWMZA - HUSSAIN MUHAMMAD MAJID (P.IVA IT14191810960)
VersionInfoDescription=AWMZA Security Agent Setup
CloseApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[CustomMessages]
en.TokTitle=Install token
en.TokDesc=Paste the install token from your dashboard (security.awmza.com > Endpoints > Add computer).
en.TokLabel=Token (starts with awe_):
en.TokBad=The token must start with awe_. Copy it again from the dashboard.
en.Fail=The agent could not be registered:
it.TokTitle=Token di installazione
it.TokDesc=Incolla il token dalla dashboard (security.awmza.com > Endpoints > Aggiungi computer).
it.TokLabel=Token (inizia con awe_):
it.TokBad=Il token deve iniziare con awe_. Copialo di nuovo dalla dashboard.
it.Fail=Registrazione dell'agent non riuscita:
de.TokTitle=Installations-Token
de.TokDesc=Fuegen Sie den Token aus dem Dashboard ein (security.awmza.com > Endpoints > Computer hinzufuegen).
de.TokLabel=Token (beginnt mit awe_):
de.TokBad=Der Token muss mit awe_ beginnen. Bitte erneut aus dem Dashboard kopieren.
de.Fail=Der Agent konnte nicht registriert werden:
fr.TokTitle=Jeton d'installation
fr.TokDesc=Collez le jeton du tableau de bord (security.awmza.com > Endpoints > Ajouter un ordinateur).
fr.TokLabel=Jeton (commence par awe_) :
fr.TokBad=Le jeton doit commencer par awe_. Copiez-le a nouveau depuis le tableau de bord.
fr.Fail=L'agent n'a pas pu etre enregistre :
es.TokTitle=Token de instalacion
es.TokDesc=Pegue el token del panel (security.awmza.com > Endpoints > Anadir equipo).
es.TokLabel=Token (empieza por awe_):
es.TokBad=El token debe empezar por awe_. Copielo de nuevo desde el panel.
es.Fail=No se pudo registrar el agente:

[Files]
Source: "dist\awmza-agent\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[UninstallRun]
Filename: "{app}\awmza-agent.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "AwmzaUninstall"

[Code]
var TokPage: TInputQueryWizardPage; Upgrade: Boolean;

function Installed(): Boolean;
begin
  Result := FileExists(ExpandConstant('{commonappdata}\AWMZA\state.json'));
end;

procedure InitializeWizard();
begin
  Upgrade := Installed();
  TokPage := CreateInputQueryPage(wpWelcome, CustomMessage('TokTitle'), CustomMessage('TokDesc'), '');
  TokPage.Add(CustomMessage('TokLabel'), False);
  TokPage.Values[0] := ExpandConstant('{param:TOKEN|}');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = TokPage.ID) and Upgrade and (Trim(TokPage.Values[0]) = '');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = TokPage.ID) and (Copy(Trim(TokPage.Values[0]), 1, 4) <> 'awe_') then begin
    MsgBox(CustomMessage('TokBad'), mbError, MB_OK);
    Result := False;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if WizardSilent() and not Installed() and (Copy(ExpandConstant('{param:TOKEN|}'), 1, 4) <> 'awe_') then begin
    Log('Silent install needs /TOKEN=awe_...');
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  { stop a running agent so its files can be replaced }
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "AWMZA Security Agent"', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM awmza-agent.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var tok, params: String; res: TExecOutput; ok: Boolean; i, rc: Integer; msg: String;
begin
  if CurStep <> ssPostInstall then exit;
  tok := Trim(TokPage.Values[0]);
  if tok <> '' then params := 'install --token ' + tok else params := 'service';
  ok := ExecAndCaptureOutput(ExpandConstant('{app}\awmza-agent.exe'), params, ExpandConstant('{app}'),
                             SW_HIDE, ewWaitUntilTerminated, rc, res);
  msg := '';
  for i := 0 to GetArrayLength(res.StdOut) - 1 do msg := msg + res.StdOut[i] + #13#10;
  for i := 0 to GetArrayLength(res.StdErr) - 1 do msg := msg + res.StdErr[i] + #13#10;
  Log(msg);
  if not ok or (rc <> 0) then
    SuppressibleMsgBox(CustomMessage('Fail') + #13#10 + msg, mbError, MB_OK, IDOK)
  else if not WizardSilent() then
    MsgBox(msg, mbInformation, MB_OK);
end;
