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
    MainMenu:  TMainMenu;
    Memo:      TMemo;
    MenuItem1: TMenuItem;
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
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1:     TForm1;
  CustomRSA: TCustomRSA;

implementation

{$R *.lfm}

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
  PriKey:  string;
  PubKey:  string;
  RSA:     PRSA;
  OrigMsg, EncMsg: PChar;
  EncLen:  integer;
  err:     PChar;
  OrigLen: integer;
begin
  Memo.Clear;
  // Генерируем пару ключей
  PubKey := '';
  PriKey := '';
  RSA    := GenRsaKeys(512, PriKey, PubKey);

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
  EncMsg:  PByte;
  OrigMsg: PByte;
  EncLen:  cint;
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


end.
