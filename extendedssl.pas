{*******************************************************************************

  Класс для использования OPENSSL, что бы юзать RSA - Anton Rodin 2014

*******************************************************************************}

unit ExtendedSSL;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, ctypes,
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
  TPEM_write_bio_RSAPrivateKey = function(Pri: PBIO; KeyPair: PRSA; var1, var2, var3, var4, var5: pointer): integer; cdecl;
  TPEM_write_bio_RSAPublicKey = function(Pri: PBIO; KeyPair: PRSA): integer; cdecl;
  TPEM_read_bio_RSA_PUBKEY = function(keybio: PBIO; rsa: PPRSA; Pass: Pointer; CallBack: Pointer): PRSA; cdecl;
  TPEM_read_bio_RSAPrivateKey = function(keybio: PBIO; rsa: PPRSA; Pass: Pointer; CallBack: Pointer): PRSA; cdecl;
  TPEM_read_bio_RSAPublicKey = function(keybio: PBIO; rsa: PPRSA; Pass: Pointer; CallBack: Pointer): PRSA; cdecl;

  // Для цифровой подписи      
  TEVP_sha256 = function(): PEVP_MD; cdecl;
  TEVP_MD_CTX_create = function(): PEVP_MD_CTX; cdecl;
  TEVP_DigestSignInit = function(ctx: PEVP_MD_CTX;
    pctx: Pointer {На самом деле указатель на указатель на EVP_PKEY_CTX, но некогда описывать EVP_PKEY_CTX};
    const evp_type: Pointer {EVP_MD}; e: Pointer {*ENGINE}; pkey: PEVP_PKEY): integer; cdecl;
  TEVP_DigestSignFinal = function(ctx: PEVP_MD_CTX; sig: PAnsiChar; siglen: PSizeUInt): integer; cdecl;
  TCRYPTO_malloc = function(length: longint; const f: PChar; line: integer): pointer; cdecl;
  TCRYPTO_free = procedure(str: pointer); cdecl;
  TEVP_MD_CTX_destroy = procedure(ctx: PEVP_MD_CTX); cdecl;
  TEVP_DigestVerifyInit = function(ctx: PEVP_MD_CTX;
    pctx: Pointer {На самом деле указатель на указатель на EVP_PKEY_CTX, но некогда описывать EVP_PKEY_CTX};
    const evp_type: Pointer {EVP_MD}; e: Pointer {*ENGINE}; pkey: PEVP_PKEY): integer; cdecl;
  TEVP_DigestVerifyFinal = function(ctx: PEVP_MD_CTX; sig: PAnsiChar; siglen: SizeUInt): integer; cdecl;
  TBN_set_word = function(a: Pointer; w: UInt32): integer; cdecl;
  TBN_new = function(): Pointer; cdecl;

type

  { TCustomRSA }

  TCustomRSA = class(TObject)
    PubKey: PRSA;
    PriKey: PRSA;
  private
    ErrMsg: PChar;
  public
    constructor Create;
    destructor Destroy; override;
  public
    PrivateKey: string;
    PublicKey: string;
    KeySize: integer;
    procedure GenKeys;
    function Encrypt(var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte; var EncLen: integer): integer;
    function Decrypt(var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte; var EncLen: integer): integer;
    procedure CloseKeys;
  public
    function PemToRsa(Pem: Pointer; Flag: integer = 0): PRSA;
    procedure SaveDer(Mem: Pointer; MSize: integer = 0);
    procedure SaveKeyPair(PathToPubKey, PathToPriKey: string);
  public
    procedure LoadPubKeyFromFile(FileName: string);
    procedure LoadPubKeyFromMem(PEM: string);
    procedure LoadPriKeyFromFile(FileName: string);
    procedure LoadPriKeyFromMem(PEM: string);
  end;

var
  PEM_write_bio_RSAPrivateKey: TPEM_write_bio_RSAPrivateKey;
  PEM_write_bio_RSAPublicKey: TPEM_write_bio_RSAPublicKey;
  PEM_read_bio_RSA_PUBKEY: TPEM_read_bio_RSA_PUBKEY;
  PEM_read_bio_RSAPublicKey: TPEM_read_bio_RSAPublicKey;
  PEM_read_bio_RSAPrivateKey: TPEM_read_bio_RSAPrivateKey;
  EVP_sha256: TEVP_sha256;
  EVP_MD_CTX_create: TEVP_MD_CTX_create;
  EVP_DigestSignInit: TEVP_DigestSignInit;
  EVP_DigestSignFinal: TEVP_DigestSignFinal;
  CRYPTO_malloc: TCRYPTO_malloc;
  CRYPTO_free: TCRYPTO_free;
  EVP_MD_CTX_destroy: TEVP_MD_CTX_destroy;
  EVP_DigestVerifyInit: TEVP_DigestVerifyInit;
  EVP_DigestVerifyFinal: TEVP_DigestVerifyFinal;
  BN_set_word: TBN_set_word;
  BN_new: TBN_new;

  hLibSSL, hLibCrypto: THandle;

function GenRsaKeys(KeySize: integer; var PriKey: string; var PubKey: string): PRSA;
function EncryptRsa(KeyPair: PRSA; var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
function DecryptRsa(KeyPair: PRSA; var OrigMsg: PByte; var LenMsg: integer; var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
procedure CloseRSA(KeyPair: PRSA);
function OPENSSL_malloc(length: longint): pointer; inline;
procedure OPENSSL_free(address: pointer); inline;
function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: csize_t): cint; inline;
function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: csize_t): cint; inline;

function GetCryptErrText: string;


implementation

function OPENSSL_malloc(length: longint): pointer; inline;
  // Грёбанный макрос
begin
  OPENSSL_malloc := CRYPTO_malloc(length, nil, 0);
end;

procedure OPENSSL_free(address: pointer); inline;
// Грёбанный макрос
begin
  CRYPTO_free(address);
end;

function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: csize_t): cint; inline;
  // Грёбанный макрос
begin
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;

function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: csize_t): cint; inline;
  // Грёбанный макрос
begin
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;

function GetCryptErrText: string;
var
  err: PChar;
begin
  Err_Error_String(ErrGetError(), err);
  Result := StrPas(Err);
end;

procedure DoUnloadOpenSSL;
begin
  FreeLibrary(hLibSSL);
end;

procedure DoLoadOpenSSL;

  function LoadFunc(hLib: THandle; FuncName: string): Pointer;
  begin
    Result := GetProcAddress(hLib, FuncName);
    if Result = nil then
      raise Exception.Create('Error Loading function ' + FuncName);
  end;

begin
  {$IFDEF WINDOWS}
  {$NESSAGE FATAL 'Нужно перепроверить от куда в Windows загружаются функции...'}
  hLibSSL := LoadLibrary(DLLSSLName);
  if hLibSSL = 0 then
    raise Exception.Create('Error loading ' + DLLSSLName);
  hLibCrypto := LoadLibrary(DLLUtilName);
  if hLibCrypto = 0 then
    raise Exception.Create('Error loading ' + DLLUtilName);
  {$ELSE}
  hLibSSL := LoadLibrary('libssl.so.1.0.2');
  if hLibSSL = 0 then
    raise Exception.Create('Error loading ' + DLLSSLName);
  hLibCrypto := LoadLibrary('libcrypto.so.1.0.2');
  if hLibCrypto = 0 then
    raise Exception.Create('Error loading ' + DLLUtilName);
  {$ENDIF Windows}

  OpenSSL_add_all_algorithms;
  OpenSSL_add_all_ciphers;
  OpenSSL_add_all_digests;
  ERR_load_crypto_strings;

  PEM_write_bio_RSAPrivateKey := TPEM_write_bio_RSAPrivateKey(LoadFunc(hLibSSL, 'PEM_write_bio_RSAPrivateKey'));
  PEM_write_bio_RSAPublicKey := TPEM_write_bio_RSAPublicKey(LoadFunc(hLibSSL, 'PEM_write_bio_RSAPublicKey'));
  PEM_read_bio_RSA_PUBKEY := TPEM_read_bio_RSA_PUBKEY(LoadFunc(hLibSSL, 'PEM_read_bio_RSA_PUBKEY'));
  PEM_read_bio_RSAPrivateKey := TPEM_read_bio_RSAPrivateKey(LoadFunc(hLibSSL, 'PEM_read_bio_RSAPrivateKey'));
  PEM_read_bio_RSAPublicKey := TPEM_read_bio_RSAPublicKey(LoadFunc(hLibSSL, 'PEM_read_bio_RSAPublicKey'));
  EVP_MD_CTX_create := TEVP_MD_CTX_create(LoadFunc(hLibCrypto, 'EVP_MD_CTX_create'));
  EVP_MD_CTX_destroy := TEVP_MD_CTX_destroy(LoadFunc(hLibCrypto, 'EVP_MD_CTX_destroy'));
  EVP_sha256 := TEVP_sha256(LoadFunc(hLibCrypto, 'EVP_sha256'));
  EVP_DigestSignInit := TEVP_DigestSignInit(LoadFunc(hLibCrypto, 'EVP_DigestSignInit'));
  EVP_DigestSignFinal := TEVP_DigestSignFinal(LoadFunc(hLibCrypto, 'EVP_DigestSignFinal'));
  CRYPTO_malloc := TCRYPTO_malloc(LoadFunc(hLibCrypto, 'CRYPTO_malloc'));
  CRYPTO_free := TCRYPTO_free(LoadFunc(hLibCrypto, 'CRYPTO_free'));
  EVP_DigestVerifyInit := TEVP_DigestVerifyInit(LoadFunc(hLibCrypto, 'EVP_DigestVerifyInit'));
  EVP_DigestVerifyFinal := TEVP_DigestVerifyFinal(LoadFunc(hLibCrypto, 'EVP_DigestVerifyFinal'));
  BN_set_word := TBN_set_word(LoadFunc(hLibCrypto, 'BN_set_word'));
  BN_new := TBN_new(LoadFunc(hLibCrypto, 'BN_new'));
end;

function GenRsaKeys(KeySize: integer; var PriKey: string; var PubKey: string): PRSA;
{const
  RSA_F4: clong = 65537;   }
var
  PriLen, PubLen: integer;
  KeyPair: PRSA;
  Pri: PBIO;
  Pub: PBIO;
 { rsa: PRSA;
  e: UInt32;
  ret: integer;
  bne: Pointer;   }
begin
 { e := RSA_F4;
  rsa := RSA_new();
  bne := BN_new();
  ret := BN_set_word(bne, e);
  KeyPair := RSA_generate_key_ex(rsa, KeySize, bne, nil);   }
  KeyPair := RsaGenerateKey(KeySize, PUB_EXP, nil, nil); //- Устарело =\
  Pri := BioNew(BioSMem);
  Pub := BioNew(BioSMem);
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

function EncryptRsa(KeyPair: PRSA; var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
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

function DecryptRsa(KeyPair: PRSA; var OrigMsg: PByte; var LenMsg: integer; var EncMsg: PByte; var EncLen: integer; var err: PChar): integer;
begin
  LenMsg := RSA_private_decrypt(EncLen, EncMsg, OrigMsg, KeyPair, RSA_PKCS1_OAEP_PADDING);
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
  KeySize := 2048;
end;

destructor TCustomRSA.Destroy;
begin
  FreeMem(ErrMsg);
  inherited;
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
function TCustomRSA.Encrypt(var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte; var EncLen: integer): integer;
begin
  Result := EncryptRsa(PubKey, OrigMsg, LenMsg, EncMsg, EncLen, ErrMsg);
end;

//******************************************************************************
// RSA расшифровка
//******************************************************************************
function TCustomRSA.Decrypt(var OrigMsg: PByte; LenMsg: integer; var EncMsg: PByte; var EncLen: integer): integer;
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
  err: PChar;
begin
  Result := nil;
  GetMem(err, MAX_PATH);
  TmpRsa := nil;
  KeyBIO := BIO_new_mem_buf(Pem, -1);
  if KeyBIO = nil then
  begin
    Err_Error_String(ErrGetError(), err);
    raise Exception.Create('Failed to create key PBIO ' + string(err));
    Freemem(err);
    abort;
  end;
  try
    case flag of
      0: Result := PEM_read_bio_RSAPublicKey(KeyBIO, @TmpRsa, nil, nil);
      1: Result := PEM_read_bio_RSAPrivateKey(KeyBIO, @TmpRsa, nil, nil);
      2: Result := PEM_read_bio_RSA_PUBKEY(KeyBIO, @TmpRsa, nil, nil);
    end;
  finally
    if Result = nil then
    begin
      Err_Error_String(ErrGetError(), err);
      ShowMessage('Failed to create PRSA ' + string(err));
      Freemem(err);
      abort;
    end;
  end;
end;

procedure TCustomRSA.SaveDer(Mem: Pointer; MSize: integer);
var
  KeyBIO: PBIO;
begin
  KeyBIO := BIO_new_mem_buf(Pchar(PrivateKey), -1);
  if KeyBIO = nil then
    raise Exception.Create('Failed to create key PBIO ' + GetCryptErrText());
    {               
  x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  i2dX509bio(KeyBIO, x509);
                                }
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
  PubKey := PemToRsa(PChar(PublicKey), 0);
  StringList.Free;
end;

procedure TCustomRSA.LoadPubKeyFromMem(PEM: string);
begin
  CloseRSA(PubKey);
  PublicKey := PEM;
  PubKey := PemToRsa(PChar(PublicKey), 0);
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
  PriKey := PemToRsa(PChar(PrivateKey), 1);
  StringList.Free;
end;

procedure TCustomRSA.LoadPriKeyFromMem(PEM: string);
begin
  CloseRSA(PriKey);
  PrivateKey := PEM;
  PriKey := PemToRsa(PChar(PrivateKey), 1);
end;

initialization
  DoLoadOpenSSL;

finalization
  DoUnloadOpenSSL;

end.
