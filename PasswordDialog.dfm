object PasswordForm: TPasswordForm
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Password'
  ClientHeight = 111
  ClientWidth = 284
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poScreenCenter
  TextHeight = 13
  object Label1: TLabel
    Left = 24
    Top = 24
    Width = 50
    Height = 13
    Caption = 'Password:'
  end
  object PasswordEdit: TEdit
    Left = 88
    Top = 21
    Width = 169
    Height = 21
    PasswordChar = '*'
    TabOrder = 0
  end
  object OKButton: TButton
    Left = 88
    Top = 64
    Width = 75
    Height = 25
    Caption = 'OK'
    Default = True
    TabOrder = 1
    OnClick = OKButtonClick
  end
  object CancelButton: TButton
    Left = 182
    Top = 64
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    TabOrder = 2
    OnClick = CancelButtonClick
  end
end
