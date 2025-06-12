#ifndef PasswordDialogH
#define PasswordDialogH
//---------------------------------------------------------------------------
#include <vcl.h>
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.Dialogs.hpp>
//---------------------------------------------------------------------------
class PACKAGE TPasswordForm : public TForm
{
__published:	// IDE-managed Components
    TEdit *PasswordEdit;  // 패스워드 입력 필드 이름을 원래대로
    TButton *OKButton;
    TButton *CancelButton;
    TLabel *Label1;
    void __fastcall OKButtonClick(TObject *Sender);
    void __fastcall CancelButtonClick(TObject *Sender);
private:	// User declarations
public:		// User declarations
    bool Confirmed;
    AnsiString Password;
    __fastcall TPasswordForm(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TPasswordForm *PasswordForm;
//---------------------------------------------------------------------------
#endif 