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


# helper functions

# create item if it does not exist
function CondNewItem([string] $item) {
  # avoid creating unconditionally with -Force, as it will delete the content
  # use -Force to create folders recursively
  If (!(Test-Path $item)) {
    New-Item -Force $item
  }
}

# list all hives
function Get-ntuserdat() {
  # https://www.pdq.com/blog/modifying-the-registry-of-another-user/
  $PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'

  # Get Username, SID, and location of ntuser.dat for all users
  $ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} |
    Select @{name="SID";expression={$_.PSChildName}},
           @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}},
           @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}

  # Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
  $LoadedHives = Get-ChildItem Registry::HKEY_USERS | ? {$_.PSChildname -match $PatternSID} | Select @{name="SID";expression={$_.PSChildName}}

  # Get all users that are not currently logged, FIXME: UserHive and UserName always empty
  $UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select @{name="SID";expression={$_.InputObject}}, UserHive, Username

  $UnloadedHives = Get-ChildItem Registry::HKEY_USERS | ? { -Not ($_.PSChildname -match $PatternSID)} |
    Select @{name="SID";expression={$_.PSChildName}},
           @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}},
           @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}


  # also add default user
  #$UnloadedHives += {{S-1-5-21-00000000-0000000000-0000000000-0000}, {}, {}} # ?????
   # dummy sid for default user

  return @($LoadedHives, $UnloadedHives) # FIXME: access is with [0] and [1] instead of .loaded and .unloaded
}






function setup_privacy {
  # settings -> privacy -> general -> let apps use my ID ...
  $advertising="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo";
  CondNewItem $advertising | Out-Null;
  New-ItemProperty -Path $advertising -Name "Enabled" -Value 0 -Force | Out-Null;
  Remove-ItemProperty -Path $advertising -Name "Id" -Force | Out-Null;

  New-Item 'HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo' -Force | New-ItemProperty -Name DisabledByGroupPolicy -Value 1 -Force | Out-Null

  # settings -> privacy -> general -> let websites provide locally ...
  New-Item 'HKCU:\Control Panel\International\User Profile' -Force | New-ItemProperty -Name HttpAcceptLanguageOptOut -Value 1 -Force | Out-Null

  # settings -> privacy -> general -> speech, inking, & typing
  $personalization="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization";
  CondNewItem $personalization | Out-Null;
  New-ItemProperty -Path $personalization -Name RestrictImplicitTextCollection -Value 1 -Force | Out-Null
  New-ItemProperty -Path $personalization -Name RestrictImplicitInkCollection -Value 1 -Force | Out-Null
  $personalization="HKCU:\SOFTWARE\Microsoft\InputPersonalization";
  New-ItemProperty -Path "$personalization\TrainedDataStore" -Name HarvestContacts -Value 0 -Force | Out-Null
  $personalization="HKCU:\SOFTWARE\Microsoft\Personalization\Settings";
  New-ItemProperty -Path "$personalization" -Name AcceptedPrivacyPolicy -Value 0 -Force | Out-Null
}

function setup_more_privacy {
#https://www.makeuseof.com/tag/things-windows-can-clear-automatically-shutdown/
  $memory = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
  CondNewItem $memory | Out-Null
  Set-ItemProperty -Path $memory -Name "ClearPageFileAtShutdown" -Value 1 | Out-Null
}

function setup_hardening {
  $policies_codeid="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\";
  New-ItemProperty -Path $policies_codeid -Name "authenticodeenabled" -Value 0 -Force | Out-Null
  New-ItemProperty -Path $policies_codeid -Name "DefaultLevel" -Value 262144 | Out-Null
  New-ItemProperty -Path $policies_codeid -Name "PolicyScope" -Value 0 | Out-Null
  New-ItemProperty -Path $policies_codeid -Name "TransparentEnabled" -Value 1 | Out-Null
  $executabletypes=@( #gpedit, Computer Configuration, Windows Settings, Security Settings, Software restriction Policies, Designated File types
    , "ade", "adp", "bas", "bat", "chm", "cmd", "com", "cpl", "crt", "diagcab"
    , "exe", "hlp", "hta", "inf", "ins", "isp", "mdb", "mde", "msc", "msi"
    , "msp", "mst", "ocx", "pcd", "pif", "reg", "scr", "shs", "url", "vb", "vsix"
    , "wsc"
    # test/check, not listed like the others, but also get "executed" on double-click
    , "application", "gadget", "vbs", "vbe", "js", "jse", "ws", "wsf"
    , "wsh", "ps1", "ps1xml", "ps2" , "ps2xml", "psc1", "psc2"
    , "msh", "msh1", "msh2", "mshxml", "msh1xml", "msh2xml", "scf", "rgs"
  )
  $commonextensions=@(
    # documents
    , "doc?", "pdf", "txt", "?htm?", "ppt?", "xls?",
    # multimedia
    , "mp?", "jp?g", "png"
    # archives
    , "zip", "rar"
  )
  New-ItemProperty -Path $policies_codeid -Name "ExecutableTypes" -PropertyType MultiString -Value $executabletypes | Out-Null
  $policies_explorer="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer";
  CondNewItem $policies_explorer | Out-Null
  #Set-ItemProperty -Path $policies_explorer -Name "AdminInfoUrl" -Value "https://github.com/fekir/INIMA" | Out-Null
  New-Item "C:\policies.txt" -ItemType File -Value "Policies created with INIMA`n`nSee https://github.com/fekir/INIMA for more information about the project.`n";
  # FIXME: add only if not already set, or copy value to our policies.txt
  Set-ItemProperty -Path $policies_explorer -Name "AdminInfoUrl" -Value "C:\policies.txt" | Out-Null

  foreach ($cex in $commonextensions) {
    foreach ($ext in $executabletypes) {
      $guid = "{"+(New-Guid).guid+"}"
      $path = "$policies_codeid\0\Paths\$guid"; # disallowed=0, Unrestricted=262144
      New-Item $path -Force | Out-Null
      New-ItemProperty -Path $path -Name "Description" -Value "INIMA" | Out-Null
      New-ItemProperty -Path $path -Name "SaferFlags" -Value 0 | Out-Null
      New-ItemProperty -Path $path -Name "Name" -Value "name" | Out-Null
      New-ItemProperty -Path $path -Name "ItemData" -Value "*.$cex.$ext" | Out-Null
    }
  }

  # while it might be interesting to disallow to execute programs outside of c:/windows and programfiles (whitelist approach)
  # it might breaks installer (might need tmp (also needed by other programs like sysinternals) or other directories)
  # portable applications (could whiteliste a bin directory under user profile)
  # breaks "native" development
}

function setup_disable_features_services {
  # FIXME: clean before disabling features, otherwise triggers "pending action" error
  #dism /online /Cleanup-Image /StartComponentCleanup /ResetBase /NoRestart

  Get-WindowsCapability -Online | where { $_.Name -match "Hello.Face|InternetExplorer|Language.Handwriting|Language.OCR|Language.Speech|Language.TextToSpeech|MathRecognizer|Media.WindowsMediaPlayer|XPS" -and $_.State -eq "Installed"} | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null

  # FIXME: seems to cause some issues during provisioning
  #Get-WindowsOptionalFeature -Online | where { $_.FeatureName -match "LegacyComponents|DirectPlay" -and $_.State -eq "Enabled" } | Disable-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Out-Null

  Get-AppxProvisionedPackage -Online | where { $_.PackageName -match "bing|getstarted|3DViewer|OfficeHub|Solitaire|MixedReality|People|Print3D|SkypeApp|Xbox|Zune" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null


  # disable media player
  Get-Service WMPNetworkSvc -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled

  #diagnostic
  Get-Service diagnosticshub.standardcollector.service,DiagTrack,dmwappushservice -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled

  # # Disable CEIP Tasks
  Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask | Out-Null
  # Blank out AutoLogger
  New-Item "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -ItemType File -Force | Out-Null
  # Don't send malware samples to Microsoft
  $spynet = "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"
  CondNewItem $spynet | Out-Null
  New-ItemProperty -Path $spynet -Name SubmitSamplesConsent -Value 2 -Force | Out-Null
  # Don't send MRT telemetry
  $mrt = "HKLM:\Software\Policies\Microsoft\MRT"
  CondNewItem $mrt | Out-Null
  New-ItemProperty -Path $mrt -Name DontReportInfectionInformation -Value 1 -Force | Out-Null
  # Set any remaining telemetry to only send security related information
  $datacollection = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
  CondNewItem $datacollection | Out-Null
  New-ItemProperty -Path $datacollection -Name AllowTelemetry -Value 0 -Force | Out-Null

  # handwriting data sharing
  $tabletpc= "HKLM:\Software\Policies\Microsoft\Windows\TabletPC"
  CondNewItem $tabletpc | Out-Null
  New-ItemProperty -Path $tabletpc -Name PreventHandwritingDataSharing -Value 0 -Force | Out-Null

  $cloudcontent = "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
  CondNewItem $cloudcontent | Out-Null
  New-ItemProperty -Path $cloudcontent -Name DisableSoftLanding -Value 1 -Force | Out-Null

  # Geo services
  Get-Service lfsvc,MapsBroker -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled | Out-Null

  # search
  Get-Service WSearch -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled | Out-Null
  $wsearchsettings = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
  CondNewItem $wsearchsettings | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "AllowCloudSearch" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "AllowCortanaAboveLock" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "AllowCortana" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "AllowCortanaInAAD" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "AllowSearchToUseLocation" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "ConnectedSearchUseWeb" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "ConnectedSearchUseWebOverMeteredCOnnections" -Value 0 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "DisableWebSearch" -Value 1 | Out-Null
  Set-ItemProperty -Path $wsearchsettings -Name "PreventIndexOnBattery" -Value 1 | Out-Null


  $wsearchsettings = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
  CondNewItem $wsearchsettings | Out-Null
  New-ItemProperty "$wsearchsettings" -Name "AllowSearchtToUseLocation " -Value 0 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null
  New-ItemProperty "$wsearchsettings" -Name "BingSearchEnabled" -Value 0 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null
  New-ItemProperty "$wsearchsettings" -Name "CortanaConstent" -Value 0 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null

  # online tips
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips -Value 0 -Force | Out-Null

  Get-Service SysMain -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled

  Get-Service HomeGroupListener,HomeGroupProvider -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled

  # diagnostic, telemetry, ....
  Get-Service Dmwappushservice -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled
  New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
  New-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null

  New-ItemProperty "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name OptIn -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null

  $people="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
  CondNewItem $people | Out-Null
  Set-ItemProperty -Path "$people" -Name "PeopleBand" -Type DWord -Value 0 | Out-Null

  # xbox, games
  Get-Service xbl*,xbox* -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled | Out-Null
  $gamedvr = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
  CondNewItem $gamedvr | Out-Null
  Set-ItemProperty -Path $gamedvr -Name "AllowgameDVR" -Type DWord -Value 0 | Out-Null
  $gamedvr = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
  CondNewItem $gamedvr | Out-Null
  Set-ItemProperty -Path $gamedvr -Name "AppCaptureEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $gamedvr -Name "HistoricalCaptureEnabled" -Type DWord -Value 0 | Out-Null
  New-Item 'HKCU:\System\GameConfigStore' -Force | New-ItemProperty -Name GameDVR_Enabled -Type DWord -Value 0 -Force | Out-Null

  # Account
  Get-Service tokenbroker -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled | Out-Null
  # onesync* cannot be disabled from service interface...
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc" -Name "Start" -Type DWord -Value 4 | Out-NUll

  # 3rd party programs, and programs with no use
  Get-AppxPackage | where {$_.name -Match "officehub|skype|getstarted|zune|solitaire|twitter|candy|farmville|airborne|advertising|bing|people|phone|xbox|sway|pandora|adobe|eclipse|duolingo|speed|power|messaging|remote"} | Remove-AppxPackage -ErrorAction SilentlyContinue

  # may remove functionality from windows
  Get-AppxPackage | where {$_.name -Match "3dbuilder|windowsalarms|windowscommunication|windowscamera|onenote|soundrecorder|store|viewer|paint|help"} | Remove-AppxPackage -ErrorAction SilentlyContinue

  # not removed: photos, calculator

  if($env:SETUP_CLEAN -eq "no_universal_apps"){
    Get-AppxPackage * | Remove-AppxPackage -ErrorAction SilentlyContinue
  }

  # various ads...
  $contentdelivery = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
  CondNewItem $contentdelivery | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "SoftLandingEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "RotatingLockScreenEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0 | Out-Null
  Set-ItemProperty -Path $contentdelivery -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0 | Out-Null

  $advanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  CondNewItem $advanced | Out-Null
  Set-ItemProperty -Path $advanced -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null

  # hide windows store suggestion
  $explorer = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
  CondNewItem $explorer | Out-Null
  Set-ItemProperty -Path $explorer -Name "NoUseStoreOpenWith" -Type DWord -Value 1 | Out-Null

}

function setup_disk {
  # removes some functionality, hopefully increases performance
  # it could break some old apps...
  # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
  fsutil behavior set disable8dot3 1
  fsutil behavior set disablelastaccess 1
  fsutil 8dot3name strip /s C:\

  # fixed 100% disk usage on some machines
  New-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Force | New-ItemProperty -Name EnableBalloonTips -Value 0 -Force | Out-Null
}

function setup_enable_crash_dumps {
  $registryPath='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
  New-Item $registryPath -Force | New-ItemProperty -Name "DumpFolder" -Value "%%LOCALAPPDATA%%\CrashDumps" -Force | Out-Null
  New-Item $registryPath -Force | New-ItemProperty -Name "DumpCount" -Value 3 -Force | Out-Null
  New-Item $registryPath -Force | New-ItemProperty -Name "DumpType" -Value 2 -Force | Out-Null
}

function setup_disable_defender_until_reboot {
  Set-MpPreference -DisableRealtimeMonitoring $true
}

function setup_disable_updates_until_reboot {
  Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction SilentlyContinue
}

function setup_disable_defender {
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 | Out-Null
}

function setup_i_desktop_icons {
  $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
  CondNewItem $registryPath | Out-Null
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
  reg load HKLM\defaultuser C:\Users\Default\NTUSER.DAT
  $hks = @(
    "HKCU:",
    "HKLM:\defaultuser"
  )
  foreach ($hk in $hks) {
    # set sound theme to none
    New-Item "$hk\AppEvents\Schemes" -Force | New-ItemProperty -Value ".None" -Force | Out-Null
    # disable changing sound (for example when new theme is selected)
    New-Item "$hk\Software\Policies\Microsoft\Windows\Personalization" -Force | New-ItemProperty -Name "NoChangingSoundScheme" -Value 1 -Force | Out-Null
  }
  [gc]::Collect()
  reg unload HKLM\defaultuser

  # disable startup sound
  New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation' -Force | New-ItemProperty -Name "DisableStartupSound" -Value 1 -Force | Out-Null
}

function setup_i_autocompl {
  $regpath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete"
  CondNewItem $regpath | Out-Null
  Set-ItemProperty -path $regpath -Name "Append Completion" -Value "yes" | Out-Null
}

function setup_i_explorer {
  reg load HKLM\defaultuser C:\Users\Default\NTUSER.DAT
  $explorer_advs = @( # FIXME: add all users
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
    "HKLM:\defaultuser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  )
  foreach ($explorer_adv in $explorer_advs) {
    Write-Host "change $explorer_adv"
    CondNewItem $explorer_adv | Out-Null
    # show hidden files
    New-ItemProperty -path $explorer_adv -Name "Hidden" -Value 1 -Force
    attrib "$env:USERPROFILE\NTUSER.DAT" +s +h # except for this one

    # show file extensions
    New-ItemProperty -path $explorer_adv -Name "HideFileExt" -Value 0 -Force

    # default explorer to computer
    Set-ItemProperty -path $explorer_adv -Name "LaunchTo" -Type DWord -Value 1
  }
  [gc]::Collect()
  reg unload HKLM\defaultuser

  # change desktop location
  #Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop -Type ExpandString -value '%USERPROFILE%' | Out-Null
  #Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name Desktop -Type ExpandString -value '%USERPROFILE%' | Out-Null
  #Remove-Item "$env:USERPROFILE\Desktop" -Force -Recurse -ErrorAction SilentlyContinue

  # Remove never-used folders
  #Remove-Item "$env:USERPROFILE\Contacts" -Force -Recurse -ErrorAction SilentlyContinue
  #Remove-Item "$env:USERPROFILE\3D Objects" -Force -Recurse -ErrorAction SilentlyContinue
  # if it causes problems, or those folders get recreated, hide them (unfortunately we wont notice if they are used...)
  #attrib "$env:USERPROFILE\Desktop" +s +h | Out-Null

  Remove-ItemProperty -Path 'HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\ModernSharing' -Recurse -Force | Out-Null; # remove share option
}

function setup_i_colors {
  reg load HKLM\defaultuser C:\Users\Default\NTUSER.DAT
  $hks = @( # FIXME: add all users
    "HKCU:",
    "HKLM:\defaultuser"
  )
  foreach ($hk in $hks) {
    # black for metro style
    $registryPath = "$hk\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    CondNewItem $registryPath | Out-Null
    New-ItemProperty -path $registryPath -Name "AppsUseLightTheme" -Value 0 -Force | Out-Null
    New-ItemProperty -path $registryPath -Name "SystemUsesLightTheme" -Value 0 -Force | Out-Null

    # gray for classic style
    $registryPath = "$hk\Control Panel\Colors"
    CondNewItem $registryPath | Out-Null
    New-ItemProperty -path $registryPath -Name "Window" -Value "192 192 192" -Force | Out-Null

    $registryPath = "$hk\Control Panel\Desktop\Colors"
    CondNewItem $registryPath | Out-Null
    New-ItemProperty -path $registryPath -Name "Window" -Value "192 192 192" -Force | Out-Null
  }
  [gc]::Collect()
  reg unload HKLM\defaultuser

  # black for metro style
  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
  CondNewItem $registryPath | Out-Null
  New-ItemProperty -path $registryPath -Name "AppsUseLightTheme" -Value 0 -Force | Out-Null
  New-ItemProperty -path $registryPath -Name "SystemUsesLightTheme" -Value 0 -Force | Out-Null
}

function setup_i_taskbar {
  reg load HKLM\defaultuser C:\Users\Default\NTUSER.DAT
  $currentversions = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion",
    "HKLM:\defaultuser\Software\Microsoft\Windows\CurrentVersion"
  )
  foreach ($currentversion in $currentversions) {
    # hide search button
    Set-ItemProperty -Path "$currentversion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
    # remove virtual desktops button
    Set-ItemProperty -Path "$currentversion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 | Out-Null
    # show all icons in tray
    Set-ItemProperty -Path "$currentversion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0 | Out-Null
    # FIXME: remove edge
  }
  [gc]::Collect()
  reg unload HKLM\defaultuser
}

function setup_i_context_menu {
  $shellprompts = @("Registry::HKEY_CLASSES_ROOT\Directory\shell\01MenuPrompt", "Registry::HKEY_CLASSES_ROOT\Directory\background\shell\01MenuPrompt");
  foreach($shellprompt in $shellprompts){
    CondNewItem $shellprompt | Out-Null;
    New-ItemProperty -path $shellprompt -Name "MUIVerb" -Value "&Command &Prompts" -Force | Out-Null;
    #New-ItemProperty -path $shellprompt -Name "Icon" -Value "???" -Force | Out-Null;
    New-ItemProperty -path $shellprompt -Name "ExtendedSubCommandsKey" -Value "Directory\ContextMenus\MenuPrompt" -Force | Out-Null;
  }

  $cmd_command = 'cmd.exe /s /k pushd "%V"'
  $entry="Registry::HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPrompt\shell\cmd";
  CondNewItem $entry | Out-Null;
  New-ItemProperty -path $entry -Name "NoWorkingDirectory" -Value "" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "MUIVerb" -Value "&Cmd" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "Icon" -Value "cmd.exe" -Force | Out-Null;
  CondNewItem "$entry\command" | Out-Null;
  New-ItemProperty -path "$entry\command" -Name '(Default)' -Value "$cmd_command" -Force | Out-Null;

  $cmd_command = 'C:\Windows\SysWOW64\cmd.exe /s /k pushd "%V"'
  $entry="Registry::HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPrompt\shell\cmd-32";
  CondNewItem $entry | Out-Null;
  New-ItemProperty -path $entry -Name "NoWorkingDirectory" -Value "" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "MUIVerb" -Value "Cmd (32 bit)" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "Icon" -Value "cmd.exe" -Force | Out-Null;
  CondNewItem "$entry\command" | Out-Null;
  New-ItemProperty -path "$entry\command" -Name '(Default)' -Value "$cmd_command" -Force | Out-Null;

  $powershell_command = "powershell.exe -noexit -command Set-Location -literalPath '%V'"
  $entry="Registry::HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPrompt\shell\powershell";
  CondNewItem $entry | Out-Null;
  New-ItemProperty -path $entry -Name "MUIVerb" -Value "&PowerShell" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "Icon" -Value "powershell.exe" -Force | Out-Null;
  CondNewItem "$entry\command" | Out-Null;
  New-ItemProperty -path "$entry\command" -Name '(Default)' -Value "$powershell_command" -Force | Out-Null;

  # FIXME: key needs to be named runas -> cannot have more than one!
  $entry="Registry::HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPrompt\shell\runas";
  CondNewItem $entry | Out-Null;
  New-ItemProperty -path $entry -Name "MUIVerb" -Value "&Elevated PowerShell" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "Icon" -Value "powershell.exe" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "HasLUAShield" -Value "" -Force | Out-Null;
  CondNewItem "$entry\command" | Out-Null;
  New-ItemProperty -path "$entry\command" -Name '(Default)' -Value "$powershell_command" -Force | Out-Null;

  $entry="Registry::HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPrompt\shell\git-shell";
  CondNewItem $entry | Out-Null;
  New-ItemProperty -path $entry -Name "MUIVerb" -Value "&Git" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "Icon" -Value "C:\Program Files\Git\git-bash.exe" -Force | Out-Null;
  CondNewItem "$entry\command" | Out-Null;
  #New-ItemProperty -path "$entry\command" -Name '(Default)' -Value '"C:\Program Files\Git\git-bash.exe" "--cd=%v."' -Force | Out-Null;
  New-ItemProperty -path "$entry\command" -Name '(Default)' -Value 'C:\Program Files\Git\usr\bin\mintty.exe --dir "%V/" -i /mingw64/share/git/git-for-windows.ico -' -Force | Out-Null;

  $entry="Registry::HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPrompt\shell\cygwin-shell";
  CondNewItem $entry | Out-Null;
  New-ItemProperty -path $entry -Name "MUIVerb" -Value "Cygwin &Shell" -Force | Out-Null;
  New-ItemProperty -path $entry -Name "Icon" -Value "C:\cygwin64\bin\mintty.exe" -Force | Out-Null;
  CondNewItem "$entry\command" | Out-Null;
  #New-ItemProperty -path "$entry\command" -Name '(Default)' -Value 'C:\cygwin64\bin\mintty.exe -i /Cygwin-Terminal.ico -e /bin/xhere /bin/zsh.exe "%V"' -Force | Out-Null;
  New-ItemProperty -path "$entry\command" -Name '(Default)' -Value 'C:\cygwin64\bin\mintty.exe --dir "%V/" -i /Cygwin-Terminal.ico -' -Force | Out-Null;
}

function setup_i_disable_autoplay {
  reg load HKLM\defaultuser C:\Users\Default\NTUSER.DAT
  $currentversions = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion",
    "HKLM:\defaultuser\Software\Microsoft\Windows\CurrentVersion"
  )
  foreach ($currentversion in $currentversions) {
    Set-ItemProperty -Path "$currentversion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 | Out-Null

    # maybe not necessary
    $registryPath = "$currentversion\Policies\Explorer"
    CondNewItem $registryPath | Out-Null
    Set-ItemProperty -Path $registryPath -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 | Out-Null
  }
  [gc]::Collect()
  reg unload HKLM\defaultuser
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
  CondNewItem $registryPath | Out-Null
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
  Remove-Item "$env:SYSTEMDRIVE\Users\*\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:USERPROFILE\Links\OneDrive.lnk" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item "$env:SYSTEMDRIVE\Users\*\Links\OneDrive.lnk" -Force -Recurse -ErrorAction SilentlyContinue

  Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
}

function setup_clean_path_i([string] $envtarget) {
  $mypath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::$envtarget).split(";") | Where { $_ -and $_.Trim() } | select -Unique
  $newpath = @()
  # remove last slash/backslash and path that do not exist
  foreach($item in $mypath){
    if($item[-1] -eq "\" -or $item[-1] -eq "/") {
      $item = $item.Substring(0, $item.Length-1)
    }
    if(Test-Path -Path $item -PathType Container) {
      $newpath += $item
    }
  }
  $mypath = [string]::join(";", $newpath)

  [Environment]::SetEnvironmentVariable("Path", $mypath, [EnvironmentVariableTarget]::$envtarget)
}

function setup_clean_path {
  setup_clean_path_i("Machine")
  setup_clean_path_i("User")
}

function setup_vm {
  powercfg /h off
  # Monitor timeout
  powercfg -Change -monitor-timeout-ac 0
  powercfg -Change -monitor-timeout-dc 0

  powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
  powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0

  disable-computerrestore -drive "$env:SYSTEMDRIVE\"

  # Power,ndu service cannot be stopped, but can be disabled!
  Get-Service WlanSvc,WbioSrvc -ErrorAction SilentlyContinue | Stop-Service -PassThru | Set-Service -StartupType Disabled
  Get-Service Power,ndu -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled

  # disable locking with <Win>+l
  $registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  CondNewItem $registryPath | Out-Null
  Set-ItemProperty -Path $registryPath -Name "DisableLockWorkstation" -Type DWord -Value 1 | Out-Null

  foreach ($user in (Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount = True")){
    Set-LocalUser -Name $user.Name -PasswordNeverExpires 1
  }

  if ($env:PACKER_BUILDER_TYPE -like "*virtualbox*") {
    # FIXME: need to find right drive
    $Drives = Get-PSDrive -PSProvider 'FileSystem'
    foreach($Drive in $drives) {
      $exec= (Join-Path $Drive.Root "VBoxWindowsAdditions.exe")
      if (!(Test-Path $exec) ) {
        continue;
      }
      Get-ChildItem (Join-Path $Drive.Root "cert") -Filter *.cer | ForEach-Object { certutil -addstore -f "TrustedPublisher" $_.FullName | Out-Null }
      Start-Process -Wait -FilePath "$exec" -ArgumentList @("/S");
      break;
    }
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

function setup_rm_desktop_links {
  # cannot add | Out-Null or result is empty
  $files = Get-ChildItem "$env:SYSTEMDRIVE\Users\*\Desktop\*" -filter "*.lnk" -force
  foreach ($link in $files) {
    Remove-Item $link.FullName -Force -ErrorAction SilentlyContinue | Out-Null
  }
}

function setup_rm_tmp_files {
  $tmps = @()
  $tmps += "$env:TEMP\*"
  $tmps += "$env:SYSTEMROOT\Temp\*"
  $tmps += "$env:SYSTEMROOT\SoftwareDistribution\*"
  $tmps += "$env:SYSTEMDRIVE\inetpub\logs\LogFiles\*"
  $tmps += "$env:SYSTEMDRIVE\cygwin\tmp\*"
  $tmps += "$env:SYSTEMDRIVE\cygwin64\tmp\*"

  $users = "$env:SYSTEMDRIVE\Users\*"

  $tmps +=    "$env:LocalAppData\Temp\*"
  $tmps += "$users\AppData\Local\Temp\*"
  $tmps +=    "$env:LocalAppData\Microsoft\Windows\WebCache\*"
  $tmps += "$users\AppData\Local\Microsoft\Windows\WebCache\*"
  $tmps +=    "$env:LocalAppData\Microsoft\Windows\Temporary Internet Files\*"
  $tmps += "$users\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
  $tmps +=    "$env:LocalAppData\Microsoft\Windows\Explorer\*cache*.db"
  $tmps += "$users\AppData\Local\Microsoft\Windows\Explorer\*cache*.db"

  $tmps += "$env:SYSTEMROOT\Logs\*"
  $tmps += "$env:SYSTEMROOT\Prefetch\*"

  $tmps += "$env:USERPROFILE\MicrosoftEdgeBackups"
  $tmps +=           "$users\MicrosoftEdgeBackups"

  $tmps += "$env:ProgramData\chocolatey\logs\*"

  foreach($tmp in $tmps) {
    Remove-Item -Recurse $tmp -Force -ErrorAction SilentlyContinue | Out-Null
  }

  # after first rm, to avoid listing files more than once
  $drives = get-wmiobject Win32_LogicalDisk | ? {$_.drivetype -eq 3} | % {get-psdrive $_.deviceid[0]}
  foreach ($drive in $drives) {
    $tmps = Get-ChildItem $drive.Root -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {
      ($_.PSIsContainer -eq $true -and ($_.Name -eq "__pycache__" -or $_.Name -eq "cache")) -or
      ($_.PSIsContainer -eq $false -and $_.Name -eq "Thumbs.db")
    } | % { $_.FullName }
    foreach($tmp in $tmps) {
      Remove-Item -Recurse $tmp -Force -ErrorAction SilentlyContinue | Out-Null
    }
  }
}

function setup_cleanup_fast {
  setup_clean_path
  setup_empty_recycle_bin
  setup_rm_desktop_links
  setup_rm_tmp_files
}

function setup_zero_drive {
  $FilePath="$env:SYSTEMDRIVE\zero.tmp"
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
  Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction SilentlyContinue
  setup_clean_remove_onedrive

  setup_cleanup_fast

  Write-Host "Disk cleanup..."
  cleanmgr /sagerun:1 -ErrorAction SilentlyContinue # takes too much time...

  Write-Host "remove service packs"
  Dism.exe /online /Cleanup-Image /SPSuperseded /NoRestart

  Write-Host "reduce winsxs folder"
  Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase /NoRestart

  Write-Host "clean log"
  wevtutil el | Foreach-Object {wevtutil cl "$_"} -ErrorAction SilentlyContinue
  Remove-Item -Recurse "$env:SYSTEMROOT\Logs\*" -Force -ErrorAction SilentlyContinue | Out-Null

  Remove-Item -Recurse "$env:SYSTEMROOT\Prefetch\*" -Force -ErrorAction SilentlyContinue | Out-Null

  Write-Host "defrag"
  Optimize-Volume -DriveLetter C

  Write-Host "zero drive"
  setup_zero_drive
}

function setup_install_cygwin {
  # FIXME: verify 64 or 32 bit
  $source = "https://cygwin.com/setup-x86_64.exe"
  $destination = "$env:TEMP\setup-x86_64.exe"
  $mirror="http://cygwin.mirror.constant.com"

  Invoke-WebRequest $source -OutFile $destination
  # default install
  & $destination --no-desktop --local-package-dir "$env:TEMP" --site $mirror --quiet-mode --packages chere,nano,vim | Out-Null
  # add packages
  if ( $env:SETUP_CYGWIN_PACKAGES ) {
    & $destination --no-desktop --local-package-dir "$env:TEMP" --site $mirror --quiet-mode --packages $env:SETUP_CYGWIN_PACKAGES | Out-Null
  }

  Add-Content "$env:SYSTEMDRIVE\cygwin64\etc\nsswitch.conf" "`n"
  Add-Content "$env:SYSTEMDRIVE\cygwin64\etc\nsswitch.conf" "db_home: /%H`n"   # change default home, prefer "/%H" to "windows" in case we are in a domain
  # Add-Content "$env:SYSTEMDRIVE\cygwin64\etc\nsswitch.conf" "db_shell: /bin/zsh`n" # change default shell

  # chere with default shell -> reported in nsswitch changed
  powershell {
    $env:Path += ";$env:SYSTEMDRIVE\cygwin64\bin;"
    & "$env:SYSTEMDRIVE\cygwin64\bin\bash.exe" chere -i -t mintty
  }
  # FIXME: make more programmatically
  Add-MpPreference -ExclusionProcess bash
  Add-MpPreference -ExclusionProcess zsh
  Add-MpPreference -ExclusionProcess tmux
  Add-MpPreference -ExclusionProcess nano
  Add-MpPreference -ExclusionProcess vim
  Add-MpPreference -ExclusionProcess mintty
  Add-MpPreference -ExclusionPath "$env:SYSTEMDRIVE\cygwin64"
  if ($env:SETUP_CYGWIN_PACKAGES -like '*git*') {
    Add-MpPreference -ExclusionProcess tig
    Add-MpPreference -ExclusionProcess git
  }
  Remove-Item $destination -Force -ErrorAction SilentlyContinue | Out-Null
}

# sets npp as default app for any file with no associations
# and add shortcut for run command
# FIXME: change npp as default for txt, ini and other files already associated with notepad
function setup_i_conf_npp {
  $editor = "`"C:\Program Files\Notepad++\notepad++.exe`""
  # $editor = "`"C:\Program Files (x86)\Vim\vim81\gvim.exe`""

  # register and set editor for unknown files
  $key = "Registry::HKEY_CLASSES_ROOT\Unknown\shell"
  CondNewItem $key | Out-Null
  Set-ItemProperty -Path "$key" -name '(Default)' -Value "editor"

  $key = "Registry::HKEY_CLASSES_ROOT\Unknown\shell\editor\command"
  CondNewItem  $key | Out-Null
  Set-ItemProperty -Path "$key" -name '(Default)' -Value "$editor `"%1`""

  # register editor for known textual files
  $key = "Registry::HKEY_CLASSES_ROOT\Unknown\shell\Open\command"
  CondNewItem $key | Out-Null
  Set-ItemProperty -Path "$key" -name '(Default)' -Value "$editor `"%1`""

  # set default editor for already known extual files
  $filetypes = @("txtfile", "inifile", "xmlfile")
  foreach ($filetype in $filetypes) {
    $key = (Join-Path (Join-Path Registry::HKEY_CLASSES_ROOT $filetype) shell\open\command)
    CondNewItem $key | Out-Null
    Set-ItemProperty -Path "$key" -name '(Default)' -Value "$editor `"%1`""
  }


  # notepad++ alreay adds an entry in explorer right click
  ## apparently "*" gets expanded, and "`*" does not escape..., thus use a different syntax
  #$key = (get-item Registry::HKEY_CLASSES_ROOT).CreateSubKey("*\shell\Open with text editor\command")
  #$key.SetValue('', "$editor `"%1`"");

  ## in case there is a nice icon
  #$key = (get-item Registry::HKEY_CLASSES_ROOT).OpenSubKey("*\shell\Open with text editor", $true)
  #$key.SetValue('Icon', "$editor");


  $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\editor.exe"
  CondNewItem $key | Out-Null
  Set-ItemProperty -Path "$key" -name '(Default)' -Value "$editor"
}

function setup_install_choco {
  If (!(Test-Path -PathType Leaf $PROFILE)) {
    New-Item $PROFILE -ItemType File -Force | Out-Null;
  }
  iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  choco feature enable -n allowGlobalConfirmation

  cinst $env:SETUP_CHOCO_PACKAGES.split(",") --yes --limit-output --no-progress

  if ($env:SETUP_CHOCO_PACKAGES -like '*notepadplusplus*') {
    setup_i_conf_npp
  }
  if ($env:SETUP_CHOCO_PACKAGES -like '*git*') {
    Add-MpPreference -ExclusionProcess tig
    Add-MpPreference -ExclusionProcess git
    # remove git gui option from context menu
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Directory\shell\git_gui" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\LibraryFolder\background\shell\git_gui" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\background\shell\git_gui" -Recurse -ErrorAction SilentlyContinue | Out-Null
  }
  Remove-Item -Recurse "$env:ProgramData\chocolatey\logs\*" -Force -ErrorAction SilentlyContinue | Out-Null

  # FIXME: check how to change default apps (browser, mail client, ...)
}
