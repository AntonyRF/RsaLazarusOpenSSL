unit Main;

{$mode objfpc}{$H+}
  {$ASMMODE INTEL}

interface

uses
  Classes, SysUtils, ctypes, FileUtil, Forms, Controls, Graphics, Dialogs,
  StdCtrls, Menus, ExtendedSSL, OpenSSL;

type

  { TForm1 }

  TForm1 = class(TForm)
    MainMenu: TMainMenu;
    Memo: TMemo;
    MenuItem1: TMenuItem;
    MenuItemSign: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem3: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure MenuItem11Click(Sender: TObject);
    procedure MenuItem12Click(Sender: TObject);
    procedure MenuItem3Click(Sender: TObject);
    procedure MenuItem4Click(Sender: TObject);
    procedure MenuItem6Click(Sender: TObject);
    procedure MenuItem7Click(Sender: TObject);
    procedure MenuItem9Click(Sender: TObject);
    procedure MenuItemSignClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1: TForm1;
  CustomRSA: TCustomRSA;

implementation

{$R *.frm}

{ TForm1 }

function GetHexTable(Buf: Pointer; iLen: integer): string;
var
  i: integer;
begin
  Result := '';
  for i := 0 to iLen do
    Result += IntToHex(integer(PByte(Buf + i)^), 2) + ', ';
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  PriKey: string;
  PubKey: string;
  RSA: PRSA;
  OrigMsg, EncMsg: PChar;
  EncLen: integer;
  err: PChar;
  OrigLen: integer;
begin
  Memo.Clear;
  // Генерируем пару ключей
  PubKey := '';
  PriKey := '';
  RSA := GenRsaKeys(512, PriKey, PubKey);

  // Отображаем это в мемо
  memo.Append(PriKey);
  memo.Append('');
  memo.Append(PubKey);
  Memo.Append('');

  // Выделяем память
  Getmem(err, MAX_PATH);
  Getmem(OrigMsg, MAX_PATH);

  // Выводим оригинальное сообщение и закидываем это в буффер
  Memo.Append('--- ORIG MSG ---');
  Memo.Append('Hello World');
  strcopy(PChar(OrigMsg), PChar('Hello World'));
  OrigLen := strlen(OrigMsg);

  // Получаем будущий размер закодированных данных
  EncLen := RSA_size(RSA);
  GetMem(EncMsg, EncLen);

  // Кодируем данные
  EncLen := EncryptRsa(RSA, PBYTE(OrigMsg), OrigLen, PByte(EncMsg), EncLen, err);
  if EncLen = 0 then
    ShowMessage(err);

  // Выводим в HEX виде закодированные данные
  Memo.Append('');
  Memo.Append('--- ENCODED MESSAGE ---');
  Memo.Append(GetHexTable(EncMsg, EncLen));
  Memo.Append('');

  // Перезаписывем буфер
  Memo.Append('--- DESTROY BUFFER ---');
  Memo.Append('Destroy data in buffer (=');
  strcopy(PChar(OrigMsg), PChar('Destroy data in buffer (='));
  Memo.Append('');

  // Расшифровываем данные
  OrigLen := DecryptRsa(RSA, PBYTE(OrigMsg), OrigLen, PByte(EncMsg), EncLen, err);
  if OrigLen = 0 then
    ShowMessage(err);

  // Выводим расшифрованные данные
  Memo.Append('--- DECODED MSG ---');
  PByte(OrigMsg + OrigLen)^ := 0;
  Memo.Append(OrigMsg);

  // Освобождаем буферы за собой
  Freemem(err);
  Freemem(OrigMsg);
  Freemem(EncMsg);

  // Закрываем rsa
  CloseRSA(RSA);
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  CustomRSA := TCustomRSA.Create;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  CustomRSA.Free;
end;

procedure TForm1.MenuItem11Click(Sender: TObject);
begin
  Memo.Append(CustomRSA.PublicKey);
  Memo.Append(CustomRSA.PrivateKey);
end;

procedure TForm1.MenuItem12Click(Sender: TObject);
begin
  Memo.Clear;
end;

procedure TForm1.MenuItem3Click(Sender: TObject);
begin
  Memo.Clear;
end;

procedure TForm1.MenuItem4Click(Sender: TObject);
begin
  CustomRSA.KeySize := 512;
  CustomRSA.GenKeys;
  Memo.Append('Ключи сгенерированы');
end;

procedure TForm1.MenuItem6Click(Sender: TObject);
begin
  CustomRSA.SaveKeyPair('Pub.Key', 'Pri.Key');
  Memo.Append('Ключи сохранены в ' + ExtractFilePath(ParamStr(0)));
end;

procedure TForm1.MenuItem7Click(Sender: TObject);
begin
  Memo.Append('Загружаем ключи');
  CustomRSA.LoadPubKeyFromFile('Pub.Key');
  Memo.Append(CustomRSA.PublicKey);
  CustomRSA.LoadPriKeyFromFile('Pri.Key');
  Memo.Append(CustomRSA.PrivateKey);
end;

procedure TForm1.MenuItem9Click(Sender: TObject);
var
  EncMsg: PByte;
  OrigMsg: PByte;
  EncLen: cint;
  OrigLen: SizeInt;
begin
  Memo.Append('Кодируем: ');
  EncLen := RSA_size(CustomRSA.PubKey);
  GetMem(EncMsg, EncLen);
  Getmem(OrigMsg, MAX_PATH);

  strcopy(PChar(OrigMsg), PChar('Hello World'));
  OrigLen := strlen(PChar(OrigMsg));
  Memo.Append(string(PChar(OrigMsg)));

  EncLen := CustomRSA.Encrypt(OrigMsg, OrigLen, EncMsg, EncLen);

  // Выводим в HEX виде закодированные данные
  Memo.Append('');
  Memo.Append('--- ENCODED MESSAGE ---');
  Memo.Append(GetHexTable(EncMsg, EncLen));
  Memo.Append('');
  // Перезаписывем буфер
  Memo.Append('--- DESTROY BUFFER ---');
  strcopy(PChar(OrigMsg), PChar('Destroy data in buffer (='));
  Memo.Append(string(PChar(OrigMsg)));
  Memo.Append('');

  OrigLen := CustomRSA.Decrypt(PBYTE(OrigMsg), OrigLen, PByte(EncMsg), EncLen);
  // Выводим расшифрованные данные
  Memo.Append('--- DECODED MSG ---');
  PByte(OrigMsg + OrigLen)^ := 0;
  Memo.Append(string(PChar(OrigMsg)));

  FreeMem(EncMsg);
  FreeMem(OrigMsg);
end;

function sign(const msg: Pointer; mlen: SizeUInt; sig: PChar; slen: PSizeUInt; pkey: PEVP_PKEY): boolean;
  // Подпись
var
  mdctx: PEVP_MD_CTX;
  HashFunc: PEVP_MD;
begin
  Result := False;

  mdctx := nil;
  sig := nil;

  try
    // Создаём цифровой контекст сообщения
    mdctx := EVP_MD_CTX_create();
    if mdctx = nil then
      raise Exception.Create('Не смог создать цифровой контекст сообщения...');

    // Инициализация DigestSign, SHA-256 выбрана для примера
    HashFunc := EVP_sha256();
    if EVP_DigestSignInit(mdctx, nil, HashFunc, nil, pkey) <> 1 then
      raise Exception.Create(GetCryptErrText());

    // Обновим для сообщения
    if EVP_DigestSignUpdate(mdctx, msg, strlen(msg)) <> 1 then
      raise Exception.Create('');

    // Завершаем операцию цифровой подписи
    // Сеачала вызовем EVP_DigestSignFinal с нулевым параметром sig, чтобы получить длину подписи. Длина будет возвращена
    // с помощью slen
    if EVP_DigestSignFinal(mdctx, nil, slen) <> 1 then
      raise Exception.Create('');

    // Выделим память для сигнатуры
    sig := OPENSSL_malloc(slen^);
    if sig = nil then
      raise Exception.Create('');

    // Ну наконец-то получим сигнатуру
    if EVP_DigestSignFinal(mdctx, sig, slen) <> 1 then
      raise Exception.Create('');

    Result := True;

  finally
    // Смываем за собой
  {  if (sig <> nil) and (not Result) then
      OPENSSL_free(sig);    }
    if (mdctx <> nil) then
      EVP_MD_CTX_destroy(mdctx);
  end;
end;

function verify(const msg: PAnsiChar; pkey: PEVP_PKEY): boolean;
var
  mdctx: PEVP_MD_CTX;
  slen: SizeUInt;
  sig: Pointer;
begin
  Result := False;
  mdctx := nil;
  try
    // Создаём цифровой контекст сообщения
    mdctx := EVP_MD_CTX_create();
    if mdctx = nil then
      raise Exception.Create('Не смог создать цифровой контекст сообщения...');

    // Инициализируем pkey как публичный ключ
    if EVP_DigestVerifyInit(mdctx, nil, EVP_sha256(), nil, pkey) <> 1 then
      raise Exception.Create('Произошла ошибка при инициализации операции проверки подписи');

    if EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg)) <> 1 then
      raise Exception.Create('Произошла ошибка при проверке подписи');

    // Заканчиваем проверку
    Result := EVP_DigestVerifyFinal(mdctx, sig, slen) = 1;

  finally
    if (mdctx <> nil) then
      EVP_MD_CTX_destroy(mdctx);
  end;
end;

procedure TForm1.MenuItemSignClick(Sender: TObject);
var
  Rsa: TCustomRSA;
  Message: PChar;
  sig: PChar;
  slen: PSizeUInt;
begin
  Rsa := TCustomRSA.Create;
  try
    Rsa.GenKeys;
    Message := 'Hello World!';
    if sign(Message, strlen(Message), sig, slen, rsa.PriKey) then
      Memo.Append('--- SIGNED MSG ---')
    else
      Memo.Append('--- SIGNED ERR ---');

  finally
    if sig <> nil then
      OPENSSL_free(sig);
    Rsa.Free;
  end;
end;


end.
