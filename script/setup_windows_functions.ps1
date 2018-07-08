# Copyright (c) 2018 Federico Kircheis

# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

function setup_disable_features_services {
  # Query features
  # dism /Online /Get-Features

  # disable ie
  dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-x64" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-x86" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-amd64" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"LegacyComponents" /NoRestart | Out-Null

  # disable media player
  dism /Online /Disable-Feature /FeatureName:"DirectPlay" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"MediaPlayback" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"MediaCenter" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"WindowsMediaPlayer" /NoRestart | Out-Null

  # disable xps
  dism /Online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"Xps-Foundation-Xps-Viewer" /NoRestart | Out-Null

  # disable online games
  dism /Online /Disable-Feature /FeatureName:"InboxGames" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"Internet Games" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"Internet Backgammon" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"Internet Checkers" /NoRestart | Out-Null

  dism /Online /Disable-Feature /FeatureName:"WindowsGadgetPlatform" /NoRestart | Out-Null
  dism /Online /Disable-Feature /FeatureName:"FaxServicesClientPackage" /NoRestart | Out-Null

  # xbox
  Get-Service XblAuthManager,XblGameSave,XboxNetApiSvc -ErrorAction SilentlyContinue | Stop-Service | Set-Service -StartupType Disabled

  # search
  Get-Service WSearch | Stop-Service | Set-Service -StartupType Disabled
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 | Out-Null
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 | Out-Null

  Get-Service SysMain | Stop-Service | Set-Service -StartupType Disabled

  Get-Service HomeGroupListener,HomeGroupProvider -ErrorAction SilentlyContinue | Stop-Service | Set-Service -StartupType Disabled

  Get-Service DiagTrack,Dmwappushservice -ErrorAction SilentlyContinue | Stop-Service | Set-Service -StartupType Disabled

  New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force | Out-Null
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 | Out-Null


  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 | Out-Null
}

function setup_disk {
  # removes some functionality, hopefully increases performance
  # it could break some old apps...
  # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
  fsutil behavior set disable8dot3 1
  fsutil behavior set disablelastaccess 1

  # fixed 100% disk usage on some machines
  New-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Force | New-ItemProperty -Name EnableBalloonTips -Value 0 -Force | Out-Null
}

function setup_enable_crash_dumps {
  $registryPath='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
  New-Item $registryPath -Force | New-ItemProperty -Name "DumpFolder" -Value "%%LOCALAPPDATA%%\CrashDumps" -Force | Out-Null
  New-Item $registryPath -Force | New-ItemProperty -Name "DumpCount" -Value 3 -Force | Out-Null
  New-Item $registryPath -Force | New-ItemProperty -Name "DumpType" -Value 2 -Force | Out-Null
}

function setup_remove_universal_apps {
  # 3rd party programs, and programs with no use
  Get-AppxPackage | where {$_.name -Match "officehub|skype|getstarted|zune|solitaire|twitter|candy|farmville|airborne|bing|people|phone|xbox|sway|pandora|adobe|eclipse|duolingo|speed|power|messaging|remote"} | Remove-AppxPackage -ErrorAction SilentlyContinue

  # may remove functionality from windows
  Get-AppxPackage | where {$_.name -Match "3dbuilder|windowsalarms|windowscommunication|windowscamera|onenote|soundrecorder|store|viewer|paint|help"} | Remove-AppxPackage -ErrorAction SilentlyContinue

  # not removed: photos, calculator

  if($env:SETUP_CLEAN -eq "no_universal_apps"){
    Get-AppxPackage * | Remove-AppxPackage -ErrorAction SilentlyContinue
  }

  # various ads...
  $contentdelivery = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
  If (!(Test-Path $contentdelivery)) {
    New-Item $contentdelivery -Force | Out-Null
  }
  Set-ItemProperty -Path $contentdelivery -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "SoftLandingEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "RotatingLockScreenEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0 | Out-Null

  $advanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  If (!(Test-Path $advanced)) {
    New-Item $advanced -Force | Out-Null
  }
  Set-ItemProperty -Path $advanced -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null

  # hide windows store suggestion
  $explorer = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
    If (!(Test-Path $explorer)) {
    New-Item $explorer -Force | Out-Null
  }
  Set-ItemProperty -Path $explorer -Name "NoUseStoreOpenWith" -Type DWord -Value 1 | Out-Null
}

function setup_disable_defender {
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 | Out-Null
}

function setup_i_desktop_icons {
  $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force | Out-Null
  }
  # Computer
  Set-ItemProperty -Path $registryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
  # User Files
  Set-ItemProperty -Path $registryPath -Name "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" -Type DWord -Value 0 | Out-Null
  # Control Panel
  Set-ItemProperty -Path $registryPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0 | Out-Null
  # Network
  Set-ItemProperty -Path $registryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 0 | Out-Null
  # recycle Bin
  Set-ItemProperty -Path $registryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 0 | Out-Null
}

function setup_i_sidebar {
  # FIXME: silence errors
  # Remove onedrive from sidebar
  Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

  $namespace="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"
  $namespacewow="HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"

  # Remove Documents from sidebar
  Remove-Item "$namespace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespace\{d3162b92-9365-467a-956b-92703aca08af}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{d3162b92-9365-467a-956b-92703aca08af}" -Force -ErrorAction SilentlyContinue

  # Remove Music from sidebar
  Remove-Item "$namespace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Force -ErrorAction SilentlyContinue

  # Remove Pictures from sidebar
  Remove-Item "$namespace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Force -ErrorAction SilentlyContinue

  # Remove Videos from sidebar
  Remove-Item "$namespace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Force -ErrorAction SilentlyContinue

  # Remove 3D Objects from sidebar
  Remove-Item "$namespace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction SilentlyContinue
  Remove-Item "$namespacewow\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction SilentlyContinue

  # Add home dir to My PC
  New-Item "$namespace\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Force -ErrorAction SilentlyContinue | Out-Null
  New-Item "$namespacewow\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Force -ErrorAction SilentlyContinue | Out-Null
  # FIXME: Add home dir to sidebar
}

function setup_i_sound {
  # set sound sheme to none
  New-Item 'HKCU:\AppEvents\Schemes' -Force | New-ItemProperty -Value ".None" -Force | Out-Null
  # disable changing sound (for example when new theme is selected)
  New-Item 'HKCU:\Software\Policies\Microsoft\Windows\Personalization' -Force | New-ItemProperty -Name "NoChangingSoundScheme" -Value 1 -Force | Out-Null
  # disable startup sound
  New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation' -Force | New-ItemProperty -Name "DisableStartupSound" -Value 1 -Force | Out-Null
}

function setup_i_autocompl {
  $regpath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete"
  if(!(Test-Path $regpath)){
    New-Item $regpath -Force | Out-Null
  }
  Set-ItemProperty -path $regpath -Name "Append Completion" -Value "yes" | Out-Null
}

function setup_i_explorer {
  # show hidden files
  $explorerm = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  if(!(Test-Path $explorerm)){
    New-Item $explorerm -Force | Out-Null
  }
  $exploreru = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  if(!(Test-Path $exploreru)){
    New-Item $exploreru -Force | Out-Null
  }

  # show hidden files
  New-ItemProperty -path $explorerm -Name "Hidden" -Value 1 -Force | Out-Null
  New-ItemProperty -path $exploreru -Name "Hidden" -Value 1 -Force | Out-Null
  attrib "$env:USERPROFILE\NTUSER.DAT" +s +h # except for this one

  # show file extensions
  New-ItemProperty -path $explorerm -Name "HideFileExt" -Value 0 -Force | Out-Null
  New-ItemProperty -path $exploreru -Name "HideFileExt" -Value 0 -Force | Out-Null

  # default explorer to computer
  Set-ItemProperty -path $exploreru -Name "LaunchTo" -Type DWord -Value 1 | Out-Null

  # change desktop location
  #Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop -Type ExpandString -value '%USERPROFILE%' | Out-Null
  #Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name Desktop -Type ExpandString -value '%USERPROFILE%' | Out-Null
  #Remove-Item "$env:USERPROFILE\Desktop" -Force -Recurse -ErrorAction SilentlyContinue

  # Remove never-used folders
  #Remove-Item "$env:USERPROFILE\Contacts" -Force -Recurse -ErrorAction SilentlyContinue
  #Remove-Item "$env:USERPROFILE\3D Objects" -Force -Recurse -ErrorAction SilentlyContinue
  # if it causes problems, or those folders get recreated, hide them (unfortunately we wont notice if they are used...)
  #attrib "$env:USERPROFILE\Desktop" +s +h | Out-Null
}

function setup_i_colors {
  # black for metro style
  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
  if(!(Test-Path $registryPath)){
    New-Item $registryPath -Force| Out-Null
  }
  New-ItemProperty -path $registryPath -Name "AppsUseLightTheme" -Value 0 -Force | Out-Null
  New-ItemProperty -path $registryPath -Name "SystemUsesLightTheme" -Value 0 -Force | Out-Null

  $registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
  if(!(Test-Path $registryPath)){
    New-Item $registryPath -Force| Out-Null
  }
  New-ItemProperty -path $registryPath -Name "AppsUseLightTheme" -Value 0 -Force | Out-Null
  New-ItemProperty -path $registryPath -Name "SystemUsesLightTheme" -Value 0 -Force | Out-Null

  # gray for classic style
  $registryPath = "HKCU:\Control Panel\Colors"
  if(!(Test-Path $registryPath)){
    New-Item $registryPath -Force| Out-Null
  }
  New-ItemProperty -path $registryPath -Name "Window" -Value "192 192 192" -Force | Out-Null

  $registryPath = "HKCU:\Control Panel\Desktop\Colors"
  if(!(Test-Path $registryPath)){
    New-Item $registryPath -Force| Out-Null
  }
  New-ItemProperty -path $registryPath -Name "Window" -Value "192 192 192" -Force | Out-Null
}

function setup_i_taskbar {
  $currentversion = "HKCU:\Software\Microsoft\Windows\CurrentVersion"
  # hide search button
  Set-ItemProperty -Path "$currentversion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
  # remove virtual desktops button
  Set-ItemProperty -Path "$currentversion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 | Out-Null
  # show all icons in tray
  Set-ItemProperty -Path "$currentversion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0 | Out-Null

  # FIXME: remove edge
}

function setup_i_disable_autoplay {
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 | Out-Null

  # maybe not necessary
  $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force| Out-Null
  }
  Set-ItemProperty -Path $registryPath -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 | Out-Null
}

function setup_theme {
  setup_i_taskbar
  setup_i_colors
  setup_i_explorer
  setup_i_sound
  setup_i_sidebar
  setup_i_desktop_icons
  setup_i_disable_autoplay

  # are not really part of theme...
  setup_i_autocompl
}

function setup_raise_uac {
  $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  Set-ItemProperty -Path $registryPath -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 2 | Out-Null
  Set-ItemProperty -Path $registryPath -Name "ConsentPromptBehaviorUser" -Type DWord -Value 3 | Out-Null
  Set-ItemProperty -Path $registryPath -Name "PromptOnSecureDesktop" -Type DWord -Value 1 | Out-Null
}

function setup_clean_remove_onedrive {
  # disable
  $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force| Out-Null
  }
  Set-ItemProperty -Path $registryPath -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null

  # "uninstall"
  Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
  Start-Sleep -s 3
  $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
  If (!(Test-Path $onedrive)) {
      $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
  }
  Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
  Start-Sleep -s 3
  Stop-Process -Name explorer -ErrorAction SilentlyContinue
  Start-Sleep -s 3
  Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:HOMEDRIVE\Users\*\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:USERPROFILE\Links\OneDrive.lnk" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:HOMEDRIVE\Users\*\Links\OneDrive.lnk" -Force -Recurse -ErrorAction SilentlyContinue
}

function setup_clean_path {
  $mypath = $env:path

  # declare arr as such
  $tmparr = $tmparr2 = @()

  # split on ;
  $tmparr = $mypath.split(";")

  # remove last backslash and path that do not exist
  foreach($item in $tmparr){
    if($item[-1] -eq "\"){$item = $item -replace "\\$",""}
    if( (![string]::IsNullOrEmpty($item)) -and (Test-Path $item) ){
      $tmparr2 += $item
    }
  }

  # remove duplicates
  $tmparr = $tmparr2 | Sort-Object -Unique -Descending

  # sort entries

  # save old path, just in case
  [Environment]::SetEnvironmentVariable("OldPath", $env:path, [EnvironmentVariableTarget]::Machine)
  # save new path
  $mypath = [string]::join(";", $tmparr)
  [Environment]::SetEnvironmentVariable("Path", $mypath, [EnvironmentVariableTarget]::Machine)
  $env:path = $mypath
}

function setup_vm {
  powercfg /h off
  # Monitor timeout
  powercfg -Change -monitor-timeout-ac 0
  powercfg -Change -monitor-timeout-dc 0

  powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
  powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0

  disable-computerrestore -drive "$env:HOMEDRIVE\"
  # check how to disable wifi

  Stop-Service "Power" -ErrorAction SilentlyContinue
  Set-Service  "Power" -StartupType disabled

  $registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force| Out-Null
  }
  Set-ItemProperty -Path $registryPath -Name "DisableLockWorkstation" -Type DWord -Value 1 | Out-Null

  if ($env:PACKER_BUILDER_TYPE -like "*virtualbox*") {
    # FIXME: need to find right drive
    if(test-path E:\ -Filter *.cer){
      Get-ChildItem E:\cert -Filter *.cer | ForEach-Object { certutil -addstore -f "TrustedPublisher" $_.FullName }
    }
    Start-Process -FilePath "E:\VBoxWindowsAdditions.exe" -ArgumentList "/S" -Wait
  } elseif ($env:PACKER_BUILDER_TYPE -like "*vmware*") {
    $MountResult = Mount-DiskImage -ImagePath "C:/Windows/Temp/vmwaretools.iso" -StorageType ISO -PassThru
    $MountLocation = "$(($MountResult | Get-Volume).DriveLetter):\"

    $p = Start-Process -Wait -PassThru -FilePath "$MountLocation/setup.exe" -ArgumentList "/S /l C:\Windows\temp\vmware.log /v""/qn REBOOT=R"""
    $MountResult | Dismount-DiskImage
  }
}

function setup_empty_recycle_bin {
  $objShell = New-Object -ComObject Shell.Application
  $objFolder = $objShell.Namespace(0xA)
  $objFolder.items() | %{ remove-item $_.path -Recurse -Confirm:$false}
}

function setup_rm_desktop_links
{
  # cannot add | Out-Null or result is empty
  $files = Get-ChildItem "$env:HOMEDRIVE\Users\*\Desktop\*" -filter "*.lnk" -force
  for ($i=0; $i -lt $files.Count; $i++) {
    rm $files[$i].FullName -ErrorAction SilentlyContinue
  }
}

function setup_rm_tmp_files {
  Remove-Item -Recurse "$env:temp\*" -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item -Recurse "$env:HOMEDRIVE\Windows\Temp\*" -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item -Recurse "$env:USERPROFILE\AppData\Local\Temp\*" -Force -ErrorAction SilentlyContinue
  Remove-Item -Recurse "$env:HOMEDRIVE\Users\*\AppData\Local\Temp\*" -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item -Recurse "$env:USERPROFILE\AppData\Local\Microsoft\Windows\WebCache\*" -Force -ErrorAction SilentlyContinue| Out-Null
  Remove-Item -Recurse "$env:HOMEDRIVE\Users\*\AppData\Local\Microsoft\Windows\WebCache\*" -Force -ErrorAction SilentlyContinue| Out-Null
  Remove-Item -Recurse "$env:HOMEDRIVE\cygwin\tmp\*" -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item -Recurse "$env:HOMEDRIVE\cygwin64\tmp\*" -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item -Recurse "$env:USERPROFILE\MicrosoftEdgeBackups" -Force -ErrorAction SilentlyContinue
  Remove-Item -Recurse "$env:HOMEDRIVE\Users\*\MicrosoftEdgeBackups" -Force -ErrorAction SilentlyContinue | Out-Null
}

function setup_cleanup_fast {
  setup_clean_path
  setup_empty_recycle_bin
  setup_rm_desktop_links
  setup_rm_tmp_files
}

function setup_zero_drive {
  $FilePath="$env:HOMEDRIVE\zero.tmp"
  $Volume= Get-Volume -DriveLetter C
  $ArraySize= 64kb
  $SpaceToLeave= $Volume.Size * 0.05
  $FileSize= $Volume.SizeRemaining - $SpacetoLeave
  $ZeroArray= new-object byte[]($ArraySize)

  $Stream= [io.File]::OpenWrite($FilePath)
  try {
    $CurFileSize = 0
     while($CurFileSize -lt $FileSize) {
        $Stream.Write($ZeroArray,0, $ZeroArray.Length)
        $CurFileSize +=$ZeroArray.Length
     }
  } finally {
    if($Stream) {
        $Stream.Close()
    }
    Del $FilePath
  }
}

function setup_cleanup {
  setup_clean_remove_onedrive
  setup_remove_universal_apps

  setup_cleanup_fast

  # disk cleanup
  #Write-Host "Disk cleanup..."
  #cleanmgr /sagerun:1 -ErrorAction SilentlyContinue # takes too much time...

  # remove service packs
  Write-Host "remove service packs"
  Dism.exe /online /Cleanup-Image /SPSuperseded /NoRestart

  # reduce winsxs folder
  Write-Host "reduce winsxs folder"
  Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase /NoRestart

  Write-Host "clean log"
  wevtutil el | Foreach-Object {wevtutil cl "$_"} -ErrorAction SilentlyContinue
  Remove-Item -Recurse "$env:HOMEDRIVE\Windows\Logs\*" -Force -ErrorAction SilentlyContinue | Out-Null

  Remove-Item -Recurse "$env:HOMEDRIVE\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue | Out-Null

  Write-Host "defrag"
  Optimize-Volume -DriveLetter C

  Write-Host "zero drive"
  setup_zero_drive
}

function setup_install_cygwin {
  # verify 64 or 32 bit
  $source = "https://cygwin.com/setup-x86_64.exe"
  $destination = "$env:Temp\setup-x86_64.exe"
  $mirror="http://cygwin.mirror.constant.com"

  Invoke-WebRequest $source -OutFile $destination
  # default install
  & $destination --no-desktop --local-package-dir "$env:Temp" --site $mirror --quiet-mode --packages chere,nano | Out-Null
  # add packages
  if ( $env:SETUP_CYGWIN_PACKAGES ) {
    & $destination --no-desktop --local-package-dir "$env:Temp" --site $mirror --quiet-mode --packages $env:SETUP_CYGWIN_PACKAGES | Out-Null
  }

  Add-Content "$env:HOMEDRIVE\cygwin64\etc\nsswitch.conf" "`n"
  Add-Content "$env:HOMEDRIVE\cygwin64\etc\nsswitch.conf" "db_home: /%H`n"   # change default home, prefer "/%H" to "windows" in case we are in a domain
  # Add-Content "$env:HOMEDRIVE\cygwin64\etc\nsswitch.conf" "db_shell: /bin/zsh`n" # change default shell

  # chere with default shell -> reported in nsswitch changed
  powershell {
    $env:Path += ";$env:HOMEDRIVE\cygwin64\bin;"
    & "$env:HOMEDRIVE\cygwin64\bin\bash.exe" chere -i -t mintty
  }
}

# sets npp as default app for any file with no associations
# and add shortcut for run command
# FIXME: change npp as default for txt, ini and other files already associated with notepad
function setup_i_conf_npp {
  $registryPath = "Registry::HKEY_CLASSES_ROOT\Unknown\shell"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force| Out-Null
  }
  Set-ItemProperty -Path $registryPath -name '(Default)' -Value "notepad" | Out-Null

  $registryPath = "Registry::HKEY_CLASSES_ROOT\Unknown\shell\notepad"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force| Out-Null
  }
  Set-ItemProperty -Path $registryPath -name '(Default)' -Value "Open with Notepad++" | Out-Null

  $registryPath = "Registry::HKEY_CLASSES_ROOT\Unknown\shell\notepad\command"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force| Out-Null
  }
  Set-ItemProperty -Path $registryPath  -name '(Default)' -Value "C:\Program Files\Notepad++\notepad++.exe %1" | Out-Null

  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\npp.exe"
  If (!(Test-Path $registryPath)) {
    New-Item $registryPath -Force| Out-Null
  }
  Set-ItemProperty -Path $registryPath  -name '(Default)' -Value "C:\Program Files\Notepad++\notepad++.exe" | Out-Null
}

function setup_install_choco {
  iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  choco feature enable -n allowGlobalConfirmation

  cinst $env:SETUP_CHOCO_PACKAGES.split(",") --yes --limit-output --no-progress

  if ($SETUP_CHOCO_PACKAGES -like '*notepadplusplus*') {
    setup_i_conf_npp
  }

  # FIXME: check how to change default apps (browser, mail client, ...)
}
