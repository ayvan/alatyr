' Toggle Windows autostart of alatyr for the current user:
' creates (or removes, if it already exists) a shortcut to run-hidden.vbs in
' the Startup folder (shell:startup). No admin rights needed.
Option Explicit
Dim sh, fso, dir, startup, lnkPath, lnk
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
startup = sh.SpecialFolders("Startup")
lnkPath = startup & "\alatyr.lnk"

If fso.FileExists(lnkPath) Then
  fso.DeleteFile lnkPath
  MsgBox "Autostart removed." & vbCrLf & lnkPath, vbInformation, "alatyr"
Else
  Set lnk = sh.CreateShortcut(lnkPath)
  lnk.TargetPath = "wscript.exe"
  lnk.Arguments = """" & dir & "\run-hidden.vbs"""
  lnk.WorkingDirectory = dir
  lnk.Description = "alatyr AmneziaWG relay"
  lnk.Save
  MsgBox "Autostart installed. alatyr will start at logon." & vbCrLf & lnkPath, vbInformation, "alatyr"
End If
