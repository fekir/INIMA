@echo off

:: as the machine is not connected to internet
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WPAEvents" /v OOBETimer /t REG_BINARY /d "ffd571d68b6a8d6fd53393fd" /f >NUL
echo HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WPAEvents [8]>regini.ini
regini regini.ini
del regini.ini

:: stop unused services
sc config "FastUserSwitchingCompatibility" start= disabled >NUL
sc stop "FastUserSwitchingCompatibility" >NUL
sc config "srsservice" start= disabled >NUL
sc stop "srsservice" >NUL
sc config "audiosrv" start= disabled >NUL
sc stop "audiosrv" >NUL
sc config "wzcsvc" start= disabled >NUL
sc stop "wzcsvc" >NUL

:: set theme
:: install zune before (probably it's possible to just hack the registry keys together)
sc config "themes" start= disabled >NUL
sc stop "themes" >NUL
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v WallPaper /t REG_SZ /d " " /f >NUL
reg add "HKEY_CURRENT_USER\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f >NUL
RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters


:: services that depend on internet connection (updated too)
sc config "wuauserv" start= disabled >NUL
sc stop "wuauserv" >NUL
sc config "dhcp" start= disabled >NUL
sc stop "dhcp" >NUL
sc config "ersvc" start= disabled >NUL
sc stop "ersvc" >NUL
sc config "helpsvc" start= disabled >NUL
sc stop "helpsvc" >NUL
sc config "wscsvc" start= disabled >NUL
sc stop "wscsvc" >NUL

powercfg /h off
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 1

cleanmgr /sagerun:1
del /q/f/s %TEMP%\*
del /q/f/s C:\Windows\temp\*

reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 0 /f >NUL
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v DisableLockWorkstation /t REG_DWORD /d 1 /f >NUL


if exist %windir%\microsoft.net\framework\v4.0.30319\ngen.exe (
  %windir%\microsoft.net\framework\v4.0.30319\ngen.exe update /force /queue >NUL
  %windir%\microsoft.net\framework\v4.0.30319\ngen.exe executequeueditems >NUL
)

:: security settings
::	default settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\" /v authenticodeenabled /t REG_DWORD /d 0 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\" /v DefaultLevel /t REG_DWORD /d 262144 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\" /v PolicyScope /t REG_DWORD /d 0 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\" /v TransparentEnabled /t REG_DWORD /d 1 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\" /v ExecutableTypes /t REG_MULTI_SZ /d "ade\0adp\0bas\0bat\0chm\0cmd\0com\0cpl\0crt\0diagcab\0exe\0hlp\0hta\0inf\0ins\0isp\0mdb\0mde\0msc\0msi\0msp\0mst\0ocx\0pcd\0pif\0reg\0scr\0shs\0url\0vb\0vsix\0wsc\0application\0gadget\0vbs\0vbe\0js\0jse\0ws\0wsf\0wsh\0ps1\0ps1xml\0ps2\0ps2xml\0psc1\0psc2\0msh\0msh1\0msh2\0mshxml\0msh1xml\0msh2xml\0scf\0rgs"  /f >NUL

::	sec policy, disable double extension for bat, exe and ps1 (more invasive than expected)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{82b63e32-c399-4570-aea4-861835929434}" /v Description /t REG_SZ /d "INIMA" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{82b63e32-c399-4570-aea4-861835929434}" /v SaferFlags /t REG_DWORD /d 0 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{82b63e32-c399-4570-aea4-861835929434}" /v Name /t REG_SZ /d "name"" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{82b63e32-c399-4570-aea4-861835929434}" /v ItemData /t REG_SZ /d "*.????.cmd"

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{1e1be796-be75-45f3-8bc8-96298cf2cf77}" /v Description /t REG_SZ /d "INIMA" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{1e1be796-be75-45f3-8bc8-96298cf2cf77}" /v SaferFlags /t REG_DWORD /d 0 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{1e1be796-be75-45f3-8bc8-96298cf2cf77}" /v Name /t REG_SZ /d "name"" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{1e1be796-be75-45f3-8bc8-96298cf2cf77}" /v ItemData /t REG_SZ /d "*.????.bat"

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{031b2328-848c-4a64-932e-c77e27f98f0f}" /v Description /t REG_SZ /d "INIMA" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{031b2328-848c-4a64-932e-c77e27f98f0f}" /v SaferFlags /t REG_DWORD /d 0 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{031b2328-848c-4a64-932e-c77e27f98f0f}" /v Name /t REG_SZ /d "name"" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{031b2328-848c-4a64-932e-c77e27f98f0f}" /v ItemData /t REG_SZ /d "*.????.exe"

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{372587aa-01a8-4dd7-bf5e-ac854efa4100}" /v Description /t REG_SZ /d "INIMA" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{372587aa-01a8-4dd7-bf5e-ac854efa4100}" /v SaferFlags /t REG_DWORD /d 0 /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{372587aa-01a8-4dd7-bf5e-ac854efa4100}" /v Name /t REG_SZ /d "name"" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{372587aa-01a8-4dd7-bf5e-ac854efa4100}" /v ItemData /t REG_SZ /d "*.????.ps1"

::	sec policy, hidden files, extensions, autoruns
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REF_DWORD /d 1 >NUL
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REF_DWORD /d 1 >NUL

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REF_DWORD /d 0 >NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REF_DWORD /d 0 >NUL

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xFF /f >NUL
