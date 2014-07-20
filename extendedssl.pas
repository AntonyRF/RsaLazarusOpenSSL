{*******************************************************************************

  Класс для использования OPENSSL, что бы юзать RSA - Anton Rodin 2014

*******************************************************************************}

unit ExtendedSSL;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,
  {%H-}
  OpenSSL,
  {%H+}
  dynlibs, Dialogs;

const
  PUB_EXP = 3;

const
  RSA_STATE_NONE = -1;
  RSA_STATE_PAIR = 0;
  RSA_STATE_OPEN = 1;
  RSA_STATE_PRIV = 2;

type
  TPEM_write_bio_RSAPrivateKey = function(Pri: PBIO; KeyPair: PRSA;
    var1, var2, var3, var4, var5: pointer): integer; cdecl;
  TPEM_write_bio_RSAPublicKey = function(Pri: PBIO; KeyPair: PRSA): integer; cdecl;

  TPEM_read_bio_RSA_PUBKEY = function(keybio: PBIO; rsa: PPRSA;
    Pass: Pointer; CallBack: Pointer): PRSA; cdecl;

  TPEM_read_bio_RSAPrivateKey = function(keybio: PBIO; rsa: PPRSA;
    Pass: Pointer; CallBack: Pointer): PRSA; cdecl;
  TPEM_read_bio_RSAPublicKey = function(keybio: PBIO; rsa: PPRSA;
    Pass: Pointer; CallBack: Pointer): PRSA; cdecl;

type

  { TCustomRSA }

  TCustomRSA = class(TObject)
    PubKey: PRSA;
    PriKey: PRSA;
  private
    ErrMsg: PChar;
  public
    constructor Create;
    destructor Destroy; virtual;
  public
    PrivateKey: string;
    PublicKey:  string;
    KeySize:    integer;
    procedure GenKeys;
    function Encrypt(var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte;
      var EncLen: integer): integer;
    function Decrypt(var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte;
      var EncLen: integer): integer;
    procedure CloseKeys;
  public
    function PemToRsa(Pem: Pointer; Flag: integer = 0): PRSA;
    procedure SaveKeyPair(PathToPubKey, PathToPriKey: string);
  public
    procedure LoadPubKeyFromFile(FileName: string);
    procedure LoadPubKeyFromMem(PEM: string);
    procedure LoadPriKeyFromFile(FileName: string);
    procedure LoadPriKeyFromMem(PEM: string);
  end;

var
  PEM_write_bio_RSAPrivateKey: TPEM_write_bio_RSAPrivateKey;
  PEM_write_bio_RSAPublicKey:  TPEM_write_bio_RSAPublicKey;
  PEM_read_bio_RSA_PUBKEY:     TPEM_read_bio_RSA_PUBKEY;

  PEM_read_bio_RSAPublicKey: TPEM_read_bio_RSAPublicKey;
  PEM_read_bio_RSAPrivateKey: TPEM_read_bio_RSAPrivateKey;
  hLibSSL: THandle;

function GenRsaKeys(KeySize: integer; var PriKey: string; var PubKey: string): PRSA;
function EncryptRsa(KeyPair: PRSA; var OrigMsg: PByte; LenMsg: integer;
  var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
function DecryptRsa(KeyPair: PRSA; var OrigMsg: PByte; var LenMsg: integer;
  var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
procedure CloseRSA(KeyPair: PRSA);

implementation

procedure DoUnloadOpenSSL;
begin
  FreeLibrary(hLibSSL);
end;

procedure DoLoadOpenSSL;
begin
  hLibSSL := LoadLibrary(DLLSSLName + '.so');
  OpenSSL_add_all_algorithms();

  PEM_write_bio_RSAPrivateKey :=
    TPEM_write_bio_RSAPrivateKey(GetProcAddress(hLibSSL, 'PEM_write_bio_RSAPrivateKey'));
  if PEM_write_bio_RSAPrivateKey = nil then
    raise Exception.Create('Error Loading function #1');

  PEM_write_bio_RSAPublicKey :=
    TPEM_write_bio_RSAPublicKey(GetProcAddress(hLibSSL, 'PEM_write_bio_RSAPublicKey'));
  if PEM_write_bio_RSAPublicKey = nil then
    raise Exception.Create('Error Loading function #2');

  PEM_read_bio_RSA_PUBKEY :=
    TPEM_read_bio_RSA_PUBKEY(GetProcAddress(hLibSSL, 'PEM_read_bio_RSA_PUBKEY'));
  if PEM_read_bio_RSA_PUBKEY = nil then
    raise Exception.Create('Error Loading function #3');

  PEM_read_bio_RSAPrivateKey :=
    TPEM_read_bio_RSAPrivateKey(GetProcAddress(hLibSSL, 'PEM_read_bio_RSAPrivateKey'));
  if PEM_read_bio_RSAPrivateKey = nil then
    raise Exception.Create('Error Loading function #4');

  PEM_read_bio_RSAPublicKey :=
    TPEM_read_bio_RSAPublicKey(GetProcAddress(hLibSSL, 'PEM_read_bio_RSAPublicKey'));
  if PEM_read_bio_RSAPublicKey = nil then
    raise Exception.Create('Error Loading function #5');

end;


function GenRsaKeys(KeySize: integer; var PriKey: string; var PubKey: string): PRSA;
var
  PriLen, PubLen: integer;
  KeyPair: PRSA;
  Pri:     PBIO;
  Pub:     PBIO;
begin
  KeyPair := RsaGenerateKey(KeySize, PUB_EXP, nil, nil);
  Pri     := BioNew(BioSMem);
  Pub     := BioNew(BioSMem);
  PEM_write_bio_RSAPrivateKey(pri, keypair, nil, nil, nil, nil, nil);
  PEM_write_bio_RSAPublicKey(pub, keypair);
  Prilen := BioCtrlPending(pri);
  Publen := BioCtrlPending(pub);
  SetLength(PriKey, PriLen);
  SetLength(PubKey, PubLen);
  BioRead(pri, PriKey, PriLen);
  BioRead(pub, PubKey, PubLen);
  BioFreeAll(pub);
  BioFreeAll(pri);
  Result := keypair;
end;

function EncryptRsa(KeyPair: PRSA; var OrigMsg: PByte; LenMsg: integer;
  var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
begin
  EncLen := RSA_public_encrypt(LenMsg, OrigMsg, EncMsg, KeyPair, RSA_PKCS1_OAEP_PADDING);
  if EncLen = -1 then
  begin
    ERR_load_crypto_strings();
    Err_Error_String(ErrGetError(), err);
    Result := 0;
  end
  else
    Result := EncLen;
end;

function DecryptRsa(KeyPair: PRSA; var OrigMsg: PByte; var LenMsg: integer;
  var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
begin
  LenMsg := RSA_private_decrypt(EncLen, EncMsg, OrigMsg, KeyPair,
    RSA_PKCS1_OAEP_PADDING);
  if LenMsg = -1 then
  begin
    ERR_load_crypto_strings();
    Err_Error_String(ErrGetError(), err);
    Result := 0;
  end
  else
    Result := LenMsg;
end;

procedure CloseRSA(KeyPair: PRSA);
begin
  RSA_free(KeyPair);
end;

{ TCustomRSA }

constructor TCustomRSA.Create;
begin
  GetMem(ErrMsg, MAX_PATH);
end;

destructor TCustomRSA.Destroy;
begin
  FreeMem(ErrMsg);
end;

 //******************************************************************************
 // Генерация RSA ключей
 //******************************************************************************
procedure TCustomRSA.GenKeys;
var
  KeyPair: PRSA;
begin
  KeyPair := GenRsaKeys(KeySize, PrivateKey, PublicKey);
  CloseRSA(KeyPair);
  LoadPriKeyFromMem(PrivateKey);
  LoadPubKeyFromMem(PublicKey);
end;

 //******************************************************************************
 // RSA шифрование
 //******************************************************************************
function TCustomRSA.Encrypt(var OrigMsg: PByte; LenMsg: integer;
  var EncMsg: PByte; var EncLen: integer): integer;
begin
  Result := EncryptRsa(PubKey, OrigMsg, LenMsg, EncMsg, EncLen, ErrMsg);
end;

 //******************************************************************************
 // RSA расшифровка
 //******************************************************************************
function TCustomRSA.Decrypt(var OrigMsg: PByte; LenMsg: integer;
  var EncMsg: PByte; var EncLen: integer): integer;
begin
  Result := DecryptRsa(PriKey, OrigMsg, LenMsg, EncMsg, EncLen, ErrMsg);
end;

 //******************************************************************************
 // RSA закрытие и освобождение ключей и структур RSA
 //******************************************************************************
procedure TCustomRSA.CloseKeys;
begin
  CloseRSA(PubKey);
  CloseRSA(PriKey);
end;

 //******************************************************************************
 // Преобразование формата PEM в структуру PRSA
 //******************************************************************************
function TCustomRSA.PemToRsa(Pem: Pointer; Flag: integer): PRSA;
var
  KeyBIO: PBIO;
  TmpRsa: PRSA;
  err:    PChar;
begin
  GetMem(err, MAX_PATH);
  ERR_load_crypto_strings();
  TmpRsa := nil;
  KeyBIO := BIO_new_mem_buf(Pem, -1);
  if KeyBIO = nil then
  begin
    Err_Error_String(ErrGetError(), err);
    raise Exception.Create('Failed to create key PBIO ' + string(err));
    Freemem(err);
    abort;
  end;
  case flag of
    0: Result := PEM_read_bio_RSAPublicKey(KeyBIO, @TmpRsa, nil, nil);
    1: Result := PEM_read_bio_RSAPrivateKey(KeyBIO, @TmpRsa, nil, nil);
    2: Result := PEM_read_bio_RSA_PUBKEY(KeyBIO, @TmpRsa, nil, nil);
  end;
  if Result = nil then
  begin
    Err_Error_String(ErrGetError(), err);
    ShowMessage('Failed to create PRSA ' + string(err));
    Freemem(err);
    abort;
  end;
end;

 //******************************************************************************
 // RSA сохранение ключей в PEM формате
 //******************************************************************************
procedure TCustomRSA.SaveKeyPair(PathToPubKey, PathToPriKey: string);
var
  hfile: TextFile;
begin
  if PathToPubKey <> '' then
  begin
    AssignFile(hFile, PathToPubKey);
    ReWrite(hFile);
    Write(hFile, PublicKey);
    Close(hFile);
  end;
  if PathToPriKey <> '' then
  begin
    AssignFile(hFile, PathToPriKey);
    ReWrite(hFile);
    Write(hFile, PrivateKey);
    Close(hFile);
  end;
end;

 //******************************************************************************
 // Загрузка открытого ключа
 //******************************************************************************
procedure TCustomRSA.LoadPubKeyFromFile(FileName: string);
var
  StringList: TStringList;
begin
  CloseRSA(PubKey);
  StringList := TStringList.Create;
  StringList.LoadFromFile(FileName);
  PublicKey := StringList.Text;
  PubKey    := PemToRsa(PChar(PublicKey), 0);
  StringList.Free;
end;

procedure TCustomRSA.LoadPubKeyFromMem(PEM: string);
begin
  CloseRSA(PubKey);
  PublicKey := PEM;
  PubKey    := PemToRsa(PChar(PublicKey), 0);
end;

 //******************************************************************************
 // Загрузка приватного ключа
 //******************************************************************************
procedure TCustomRSA.LoadPriKeyFromFile(FileName: string);
var
  StringList: TStringList;
begin
  CloseRSA(PriKey);
  StringList := TStringList.Create;
  StringList.LoadFromFile(FileName);
  PrivateKey := StringList.Text;
  PriKey     := PemToRsa(PChar(PrivateKey), 1);
  StringList.Free;
end;

procedure TCustomRSA.LoadPriKeyFromMem(PEM: string);
begin
  CloseRSA(PriKey);
  PrivateKey := PEM;
  PriKey     := PemToRsa(PChar(PrivateKey), 1);
end;

initialization
  DoLoadOpenSSL;

finalization
  DoUnloadOpenSSL;

end.
