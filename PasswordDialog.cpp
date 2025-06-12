#include <vcl.h>
#pragma hdrstop

#include "PasswordDialog.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TPasswordForm *PasswordForm;
//---------------------------------------------------------------------------
__fastcall TPasswordForm::TPasswordForm(TComponent* Owner)
    : TForm(Owner)
{
    Confirmed = false;
    PasswordEdit->PasswordChar = '*';
    PasswordEdit->MaxLength = 16;
    Label1->Caption = "max 16 chars";
}
//---------------------------------------------------------------------------
void __fastcall TPasswordForm::OKButtonClick(TObject *Sender)
{
    Password = PasswordEdit->Text;
    Confirmed = true;
    Close();
}
//---------------------------------------------------------------------------
void __fastcall TPasswordForm::CancelButtonClick(TObject *Sender)
{
    Confirmed = false;
    Close();
}
//---------------------------------------------------------------------------
