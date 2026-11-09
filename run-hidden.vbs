' Start alatyr without a console window (used for Windows autostart).
' Logs: set "log_file: alatyr.log" in config.yaml.
Option Explicit
Dim sh, fso, dir
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
sh.Run """" & dir & "\alatyr.exe"" --config """ & dir & "\config.yaml""", 0, False
