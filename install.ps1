###########################################
#
# auto-WWE Installation Script
#
# Para ejecutar este script:
# 1) Abra la ventana de Powershell como administrador
# 2) Permitir la ejecución del script ejecutando el comando: "Set-ExecutionPolicy -Scope CurrentUser Unrestricted"
# 3) Desbloquee el script de instalación ejecutando: "Unblock-File .\install.ps1"
# 4) Ejecute el script ejecutando: ".\install.ps1"
#
###########################################

Function Banner {
    Clear-Host
    Write-Host "`n"
    Write-Host "`t                   __                 __      __ __      _____________    " -ForegroundColor Magenta
    Write-Host "`t    _____   __ ___/  |_  ____        /  \    /  \  \    /  \_   _____/    " -ForegroundColor Magenta
    Write-Host "`t    \__  \ |  |  \   __\/ __ \  ______   \/\/   /   \/\/   /|    __)_     " -ForegroundColor Magenta
    Write-Host "`t     / __ \_  |  /|  | (  \_\ )/_____/\        / \        / |        \    " -ForegroundColor Magenta
    Write-Host "`t    (____  /____/ |__|  \____/         \__/\  /   \__/\  / /_______  /    " -ForegroundColor Magenta
    Write-Host "`t         \/                                 \/         \/          \/     " -ForegroundColor Magenta
    Write-Host ""
    Write-Host "`t   A U T O M A T I C   W I N D O W S   W O R K   E N V I R O N M E N T    " -ForegroundColor Magenta
    Write-Host "`t_________________________________________________________________________" -ForegroundColor Magenta
    Write-Host "`t                                                        Create by @m4lal0"  -ForegroundColor Gray
    Write-Host ""
    Write-Host "`n[i] Iniciando la configuracion del Host...`n" -ForegroundColor Yellow
    Start-Sleep -Seconds 3
}

Function OSVersion {
    #### Compatibilidad Windows ####
    Write-Host "[+] Comprobando que el Sistema Operativo sea compatible [+]" -ForegroundColor Magenta
    if ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") {
        Write-Host "`t[ERR] Windows 7 no es compatible `n" -ForegroundColor Red
        Read-Host "Presione [ENTER] para salir"
        exit
    } else {
        $osversion = (Get-WmiObject -class Win32_OperatingSystem).BuildNumber
        Write-Host "`t Windows $osversion soportado." -ForegroundColor Cyan
    }
}

Function DiskSpace {
    #### Comprobar el host tenga suficiente espacio en disco duro ####
    Write-Host "[+] Checando que el Host tenga suficiente espacio en disco duro [+]" -ForegroundColor Magenta
    $disk = Get-PSDrive C
    Start-Sleep -Seconds 1
    if (-Not (($disk.used + $disk.free)/1GB -gt 58.8)) {
        Write-Host "`t[ERR] Esta instalación requiere un disco duro mínimo de 60 GB, aumente el espacio en el disco duro para continuar `n" -ForegroundColor Red
        Read-Host "Presione [ENTER] para salir"
        exit
    } else {
        Write-Host "`t> 60 GB Disco duro." -ForegroundColor Cyan
    }
}

Function RunAdministrator {
    #### Comprobar que el script corra como Administrador ####
    Write-Host "[+] Revisando si el script corre como Administrador [+]" -ForegroundColor Magenta
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "`t[ERR] Ejecuta el script como Administrador`n" -ForegroundColor Red
        Read-Host  "Presione [ENTER] para salir"
        exit
    } else {
        Start-Sleep -Milliseconds 500
        Write-Host "`tBien. Ejecutado como Administrador" -ForegroundColor Cyan
        Start-Sleep -Milliseconds 500
    }
}

Function CheckUpdates {
    #### Verifique para asegurarse de que el host se haya actualizado 
    Write-Host "[+] Verificando ultimas actualizaciones del sistema [+]" -ForegroundColor Magenta
    if (-Not (get-hotfix | where { (Get-Date($_.InstalledOn)) -gt (get-date).adddays(-30) })) {
        try 
        {
        Write-Host "`t[ERR] Esta maquina no se ha actualizado en los ultimos 30 dias, ¿quieres intentar instalar actualizaciones automaticamente? (Y / N): " -ForegroundColor Red -NoNewline
        $response = Read-Host
        if ($response -eq "Y"){
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            Install-Module PSWindowsUpdate -Force
            Import-Module PSWindowsUpdate
            Get-WindowsUpdate
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -IgnoreRebootRequired
        } else {
            Write-Host "Instale de manera manual las actualizaciones." -ForegroundColor Red
            exit
            }
        }
        catch 
        {
        Write-Host "`t[ERR] No se pudo actualizar automaticamente, ejecute las actualizaciones de Windows manualmente para continuar`n" -ForegroundColor Red
        Read-Host  "Presione [ENTER] para salir"
        exit
        }
    } else {
        Write-Host "`tlas actualizaciones parecen estar en orden" -ForegroundColor Green
    }
}

Function Validations {
    RunAdministrator
    OSVersion
    DiskSpace
    CheckUpdates
}

Function RenameHost {
    #### Renombrar Host ####
    Write-Host "[+] Renombrar Host por WinPentester [+]" -ForegroundColor Magenta
    (Get-WmiObject win32_computersystem).rename("WinPentester") | Out-Null
}

Function RemoveShorcuts {
    #### Eliminar Shorcuts ####
    Write-Host "[+] Quitando shorcuts del Escritorio [+]" -ForegroundColor Magenta
    ### Perfil publico
    $shortcut_path = "$Env:Public\Desktop\Google Chrome.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Firefox.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Microsoft Edge.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\VLC media player.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Visual Studio Code.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\WinSCP.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Bitwarden.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Simple DnsCrypt.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Mozilla Thunderbird.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\OpenVPN GUI.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\OWASP ZQP 2.10.0.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Fing.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Autopsy 4.18.0.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\MobaXterm.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\OWASP ZAP 2.10.0.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\Advanced IP Scanner.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\DB Browser (SQLCipher).lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\DB Browser (SQLite).lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\AdwCleaner.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:Public\Desktop\BleachBit.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
    ### Perfil principal
    $shortcut_path = "$Env:USERPROFILE\Desktop\Google Chrome.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Microsoft Edge.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\PeaZip.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Brave.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Tor Browser.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\balenaEtcher.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\NordVPN.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\VirusTotal Uploader 2.2.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Cutter.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Process Hacker 2.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Google Chrome.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Microsoft Edge.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\HTTrack Website Copier.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
    $shortcut_path = "$Env:USERPROFILE\Desktop\Regshot-x64-Unicode.exe.lnk"
    if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
}

Function DisableIPv6 {
    #### Deshabilitar IPv6 ####
    Write-Host "[+] Deshabilitando IPv6 [+]" -ForegroundColor Magenta
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}

Function DisableOneDrive {
    #### Deshabilitar OneDrive ####
    Write-Host "[+] Deshabilitando OneDrive [+]" -ForegroundColor Magenta
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}

Function HideTaskbarSearch {
    #### Ocultar barra de busqueda en la barra de tareas #####
    Write-Host "[+] Ocultar barra de busqueda [+]"-ForegroundColor Magenta
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

Function ShowThisPCOnDesktop {
    #### Agregar icono "Este equipo" en el escritorio #####
    Write-Host "[+] Mostrar atajo de Este equipo en el escritorio [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

Function ShowSmallTaskbarIcons {
    #### Mostrar iconos chicos en la barra de tarea ####
	Write-Host "[+] Mostrar iconos chicos en la barra [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}

Function ModeDark {
    #### Configurar modo Dark ####
	Write-Host "[+] Configurar modo Dark [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
}

Function EnableSmartScreen {
    #### Habilitar filtro SmartScreen ####
	Write-Host "[+] Habilitar filtro SmartScreen [+]" -ForegroundColor Magenta
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
}

Function DisableWebLangList {
    #### Deshabilitar el acceso del sitio web a la lista de idiomas ####
	Write-Host "[+] Deshabilitar el acceso del sitio web a la lista de idiomas [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1
}

Function DisableAdvertisingID {
    #### Desactivar ID de publicidad  ####
	Write-Host "[+] Desactivar ID de publicidad [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

Function DisableTailoredExperiences {
    #### Desactivar experiencias personalizadas ####
	Write-Host "[+] Desactivar experiencias personalizadas [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

Function DisableActivityHistory {
    #### Desactivar historial de actividades ####
	Write-Host "[+] Desactivar historial de actividades [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

Function DisableCortana {
    #### Desactivar Cortana ####
	Write-Host "[+] Desactivar Cortana [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
}

Function DisableBiometrics {
    #### Desactivar servicios biometricos ####
	Write-Host "[+] Desactivar servicios biometricos [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0
}

Function DisableDiagTrack {
    #### Detener y desactivar el servicio de telemetria y experiencias de usuario conectado (anteriormente denominado Servicio de seguimiento de diagnósticos ) ####
	Write-Host "[+] Detener y desactivar el servicio de telemetria y experiencias de usuario conectado [+]" -ForegroundColor Magenta
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}

Function DisableClearRecentFiles {
    #### Desactivar la eliminacion de archivos recientes al salir ####
	Write-Host "[+] Desactivar la eliminacion de archivos recientes al salir [+]" -ForegroundColor Magenta
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -ErrorAction SilentlyContinue
}

Function DisableRecentFiles {
    #### Desactivar listas de archivos recientes. ####
	Write-Host "[+] Desactivar listas de archivos recientes [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1
}

Function DisableFeedback {
    #### Desactivar el Feedback ####
	Write-Host "[+] Desactivar Feedback [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

Function DisableWebSearch {
    #### Desactivar busqueda web en menu de inicio ####
    Write-Host "[+] Desactivar busqueda web en el menu de inicio [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

Function DisableLocation {
    #### Desactivar ubicacion ####
    Write-Host "[+] Desactivar los servicios de ubicacion [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
}

Function DisableAutorun {
    #### Desactivar el AutoRun en todos los dispositivos ####
    Write-Host "[+] Desactivar el AutoRun en todos los dispositivos [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

Function ShowFileExtensions {
    #### Mostrar extensiones de archivos ####
    Write-Host "[+] Mostrar extensiones de archivos [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

Function ShowHiddenFiles {
    #### Mostrar archivos ocultos ####
    Write-Host "[+] Mostrar archivos ocultos [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

Function DisableWindowsFirewall {
    #### Deshabilitar Firewall ####
    Write-Host "[+] Desactivar Firewall..." -ForegroundColor Magenta
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}

Function DisableTelemetry {
	Write-Host "[+] Deshabilitando Telemetry [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

Function DisableActionCenter {
    #### Deshabilitar Action Center ####
    Write-Host "[+] Desactivar Notification Center [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}

Function DisableClipboardHistory {
	Write-Host "[+] Desactivar el Historial de Portapapeles [+]" -ForegroundColor Magenta
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
}

Function DisableWiFiSense {
	Write-Host "[+] Desactivar el Wi-Fi Sense [+]" -ForegroundColor Magenta
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0
}

Function DisableAppSuggestions {
	Write-Host "[+] Desactivar las sugerencias de aplicaciones y la instalacion automatica  [+]" -ForegroundColor Magenta
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0
	# Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}

Function PinToTaskbar {
    Write-Host "[+] Agregando programas a la barra de tarea [+]" -ForegroundColor Magenta
    #### Quitanto primero todos los iconos de la barra
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
    #### Microsoft Edge
    syspin "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" 5386
    #### Google Chrome
    syspin "C:\Program Files\Google\Chrome\Application\chrome.exe" 5386
    #### cmd
    syspin "C:\Windows\System32\cmd.exe" 5386
    #### Powershell
    syspin "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 5386
    #### Burp Suite
    $target_file = Join-Path ${Env:UserProfile} "AppData"
    syspin "$target_file\Roaming\Microsoft\Windows\Start Menu\Programs\Burp Suite Community Edition.lnk" 5386
    #### ZenMap
    syspin "C:\Program Files (x86)\Nmap\zenmap.exe" 5386
    #### OWASP ZAP
    syspin "C:\Program Files\OWASP\Zed Attack Proxy\ZAP.exe" 5386
    #### Wireshark
    syspin "C:\Program Files\Wireshark\Wireshark.exe" 5386
    #### Autopsy
    syspin "C:\Program Files\Autopsy-4.17.0\bin\autopsy64.exe" 5386
    #### AxCrypt
    syspin "C:\Program Files\AxCrypt\AxCrypt\AxCrypt.exe" 5386
    #### KeePass
    syspin "C:\Program Files\KeePass Password Safe 2\KeePass.exe" 5386
    #### ProcessHacker
    syspin "C:\Program Files\Process Hacker 2\ProcessHacker.exe" 5386
    #### WinSCP
    syspin "C:\Program Files (x86)\WinSCP\WinSCP.exe" 5386
    #### SimpleDNSCrypt
    syspin "C:\Program Files\bitbeans\Simple DNSCrypt x64\SimpleDnsCrypt.exe" 5386
    #### VisualStudio Code
    syspin "C:\Program Files\Microsoft VS Code\Code.exe" 5386
    #### GitBash
    syspin "C:\Program Files\Git\git-bash.exe" 5386
}

Function SetWallpaper{
    Write-Host "[+] Cambiando el wallpaper [+]" -ForegroundColor Magenta
    # Set desktop background to black
    Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name Background -Value "0 0 0" -Force | Out-Null
    # Descarga de Wallpaper
    Invoke-WebRequest -Uri 'https://www.xtrafondos.com/descargar.php?id=4466&resolucion=7680x4320' -OutFile "${Env:USERPROFILE}\Pictures\wallpaper.jpg"
    Invoke-WebRequest -Uri 'https://www.xtrafondos.com/descargar.php?id=4466&resolucion=7680x4320' -OutFile "${env:public}\Pictures\wallpaper.jpg"
    # Aplicacion de wallpaper
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper -value "${env:public}\Pictures\wallpaper.jpg"
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper -value "0" -Force
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "6" -Force
    Sleep -seconds 3
    rundll32.exe user32.dll, UpdatePerUserSystemParameters, 1, True
}

Function Shorcuts{
    #### Creacion de directorios de herramientas en el Desktop del usuario
    Write-Host "[+] Creando directorio de accesos directos a las herramientas [+]" -ForegroundColor Magenta
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools" -ItemType Directory
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools\BD Tools" -ItemType Directory
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools\Developer Tools" -ItemType Directory
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -ItemType Directory
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools\Reverser Enginnering" -ItemType Directory
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -ItemType Directory
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools\Web Applications" -ItemType Directory
    New-Item -Path "$Env:USERPROFILE\Desktop\Tools\Web Browsers" -ItemType Directory

    Write-Host "[+] Creando los accesos directorios de las herramientas [+]" -ForegroundColor Magenta
    #### Accesos directos para BD tools
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\BD Tools" -Name "DB Browser (SQLite)" -Value "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\BD Tools" -Name "SQL Server Managment Studio" -Value "C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\IDE\Ssms.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\BD Tools" -Name "MySQL Workbench" -Value "C:\Program Files\MySQL\MySQL Workbench 8.0 CE\MySQLWorkbench.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\BD Tools" -Name "pgAdmin" -Value "C:\Program Files\pgAdmin 4\v5\runtime\pgAdmin4.exe"
    #### Accesos directos para Developer tools
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Developer Tools" -Name "VisualStudio" -Value "C:\Program Files\Microsoft VS Code\Code.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Developer Tools" -Name "Git-Bash" -Value "C:\Program Files\Git\git-bash.exe"
    #### Accesos directos para Networking tools
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "Nmap" -Value "C:\Program Files (x86)\Nmap\zenmap.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "Wireshark" -Value "C:\Program Files\Wireshark\Wireshark.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "WinSCP" -Value "C:\Program Files (x86)\WinSCP\WinSCP.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "Advanced IP Scanner" -Value "C:\Program Files (x86)\Advanced IP Scanner\advanced_ip_scanner.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "Angry IP Scanner" -Value "C:\Program Files\Angry IP Scanner\ipscan.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "Fingr" -Value "C:\Program Files\Fing\Fing.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "OpenVPN" -Value "C:\Program Files\OpenVPN\bin\openvpn-gui.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "VNC Viewer" -Value "C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Networking Tools" -Name "netcat" -Value "C:\ProgramData\chocolatey\lib\netcat\tools\nc.exe"
    #### Accesos directos para Reverser Enginnering
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Reverser Enginnering" -Name "Cutter" -Value "C:\ProgramData\chocolatey\lib\cutter\cutter.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Reverser Enginnering" -Name "Ghidra" -Value "C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_9.2.3_PUBLIC\ghidraRun.bat"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Reverser Enginnering" -Name "Floss" -Value "C:\ProgramData\chocolatey\lib\floss\tools\floss.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Reverser Enginnering" -Name "PPEE" -Value "C:\ProgramData\chocolatey\lib\ppee\tools\PPEE(puppy) 1.12\PPEE.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Reverser Enginnering" -Name "Resource Hacker" -Value "C:\Program Files (x86)\Resource Hacker\ResourceHacker.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Reverser Enginnering" -Name "Dependency Walker" -Value "C:\ProgramData\chocolatey\lib\dependencywalker\content\depends.exe"
    #### Accesos directos para Web Applications
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Web Applications" -Name "BurpSuite" -Value "$Env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Burp Suite Community Edition.lnk"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Web Applications" -Name "OWASP-Zap" -Value "C:\Program Files\OWASP\Zed Attack Proxy\ZAP.exe"
    #### Accesos directos para Utilities
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Autopsy" -Value "C:\Program Files\Autopsy-4.18.0\bin\autopsy64.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "AxCrypt" -Value "C:\Program Files\AxCrypt\AxCrypt\AxCrypt.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "KeePass" -Value "C:\Program Files\KeePass Password Safe 2\KeePass.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "SimpleDNSCrypt" -Value "C:\Program Files\bitbeans\Simple DNSCrypt x64\SimpleDnsCrypt.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "7-Zip" -Value "C:\Program Files\7-Zip\7zFM.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Acrobat Reader" -Value "C:\Program Files (x86)\adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Bitwarden" -Value "C:\Program Files\Bitwarden\Bitwarden.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "BalenaEtcher" -Value "$Env:USERPROFILE\AppData\Local\Programs\balena-etcher\balenaEtcher.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Crystal Disk Info" -Value "C:\ProgramData\chocolatey\lib\crystaldiskinfo.portable\tools\DiskInfo64.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "GIMP" -Value "C:\Program Files\GIMP 2\bin\gimp-2.10.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "HashTools" -Value "C:\Program Files (x86)\HashTools\HashTools.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "HxD" -Value "C:\Program Files\HxD\HxD.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "MobaXterm" -Value "C:\Program Files (x86)\Mobatek\MobaXterm\MobaXterm.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Mozilla Thunderbird" -Value "C:\Program Files\Mozilla Thunderbird\thunderbird.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "NordVPN" -Value "C:\Program Files\NordVPN\NordVPN.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "PeaZip" -Value "C:\Program Files\PeaZip\peazip.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Process Hacker 2" -Value "C:\Program Files\Process Hacker 2\ProcessHacker.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "ScreenToGif" -Value "C:\ProgramData\chocolatey\lib\screentogif\content\ScreenToGif.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "VLC" -Value "C:\Program Files\VideoLAN\VLC\vlc.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "HTTrack" -Value "C:\Program Files\WinHTTrack\WinHTTrack.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "AdwCleaner" -Value "C:\ProgramData\chocolatey\lib\adwcleaner\tools\adwcleaner_8.2.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Volatility" -Value "C:\ProgramData\chocolatey\lib\volatility\tools\volatility_2.6_win64_standalone\volatility_2.6_win64_standalone.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "BleachBit" -Value "C:\Program Files (x86)\BleachBit\bleachbit.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "ExifTool" -Value "C:\ProgramData\chocolatey\lib\exiftool\tools\exiftool.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "Procmon" -Value "C:\ProgramData\chocolatey\lib\procmon\tools\Procmon.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "cports" -Value "C:\ProgramData\chocolatey\lib\cports\tools\cports.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Utilities" -Name "RegShot" -Value "C:\ProgramData\chocolatey\lib\RegShot\tools\Regshot-x86-Unicode.exe"
    #### Accesos directos para Web Browsers
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Web Browsers" -Name "Microsoft-Edge" -Value "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Web Browsers" -Name "Google-Chrome" -Value "C:\Program Files\Google\Chrome\Application\chrome.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Web Browsers" -Name "Brave" -Value "$Env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe"
    New-Item -ItemType SymbolicLink -Path "$Env:USERPROFILE\Desktop\Tools\Web Browsers" -Name "Firefox" -Value "C:\Program Files\Mozilla Firefox\firefox.exe"
}

Function Configurations {
    RenameHost
    RemoveShorcuts
    ModeDark
    DisableIPv6
    DisableOneDrive
    HideTaskbarSearch
    ShowThisPCOnDesktop
    ShowSmallTaskbarIcons
    EnableSmartScreen
    DisableWebLangList
    DisableAdvertisingID
    DisableTailoredExperiences
    DisableActivityHistory
    DisableCortana
    DisableBiometrics
    DisableDiagTrack
    DisableClearRecentFiles
    DisableRecentFiles
    DisableFeedback
    DisableWebSearch
    DisableLocation
    DisableAutorun
    DisableClipboardHistory
    DisableWiFiSense
    DisableAppSuggestions
    ShowFileExtensions
    ShowHiddenFiles
    DisableTelemetry
    PinToTaskbar
    SetWallpaper
    Shorcuts
}

Function InstallChoco {
    Write-Host "[+] Instalando Chocolatey [+]" -ForegroundColor Magenta
    Set-ExecutionPolicy Allsigned

    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

Function InstallPackages {
    Write-Host "[+] Instalacion de Herramientas [+]" -ForegroundColor Magenta
    $array = @("googlechrome", "firefox", "microsoft-edge", "brave", "tor-browser", "adobereader", "jre8", "7zip", "peazip", "vlc", "git", "python3", "python2", "golang", "dotnetfx", "putty", "gimp", "vscode", "winscp", "wireshark", "virtualbox", "microsoft-windows-terminal", "pandoc", "crystaldiskinfo", "rufus", "etcher", "vnc-viewer", "nmap", "axcrypt", "logitech-options", "unifying", "screentogif", "greenshot", "keepass", "nordvpn", "bitwarden", "simplednscrypt", "thunderbird", "burp-suite-free-edition", "virustotaluploader", "foca", "openvpn", "zap", "fing", "pgadmin4", "mysql.workbench", "cutter", "ghidra", "autopsy", "exiftool", "systemninja", "hfs", "processhacker", "lockhunter", "x64dbg.portable", "mobaxterm", "syspin", "httrack", "angryip", "advanced-ip-scanner", "sql-server-management-studio", "mysql", "adwcleaner", "volatility", "netcat", "sqlitebrowser", "hxd", "hashcheck", "hashtools", "openstego", "bleachbit", "floss", "ppee", "reshack", "dependencywalker", "cports", "procmon", "regshot", "googlechrome")
    foreach ($programs in $array){ 
        Write-Host "`n`t[*] Instalando $programs" -ForegroundColor Yellow -BackgroundColor DarkGreen
        choco install $programs -y
    }
}

Function InstallLinuxSubSystem {
    Write-Host "`t[*] Instalando Linux Subsystem" -ForegroundColor Yellow -BackgroundColor DarkGreen
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Windows-Subsystem-Linux" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function InstallSSHClient {
    Write-Host "`t[*] Instalando OpenSSH Cliente" -ForegroundColor Yellow -BackgroundColor DarkGreen
    Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Client*" } | Add-WindowsCapability -Online | Out-Null
}

Function InstallSSHServer {
    Write-Host "`t[*] Instalando OpenSSH Server" -ForegroundColor Yellow -BackgroundColor DarkGreen
    Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" } | Add-WindowsCapability -Online | Out-Null
}

Function InstallTelnetClient {
    Write-Host "`t[*] Instalando Telnet Cliente" -ForegroundColor Yellow -BackgroundColor DarkGreen
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "TelnetClient" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "Telnet-Client" -WarningAction SilentlyContinue | Out-Null
	}
}

Function InstallPDFPrint {
    Write-Host "`t[*] Instalando Microsoft Print to PDF..." -ForegroundColor Yellow -BackgroundColor DarkGreen
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function Installations {
    InstallChoco
    InstallPackages
    InstallLinuxSubSystem
    InstallSSHClient
    InstallSSHServer
    InstallTelnetClient
    InstallPDFPrint
}

Function ConfigPSTerminal {
    Write-Host "[+] Personalizando PowerShell [+]" -ForegroundColor Magenta
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Start-Sleep -Seconds 3
    Install-Module oh-my-posh -Force
    Start-Sleep -Seconds 3
    Install-Module posh-git -Force
    Start-Sleep -Seconds 3
    # Descarga de fuentes
    Invoke-WebRequest -Uri 'https://github.com/powerline/fonts/archive/master.zip' -OutFile .\powerlinefonts.zip
    Invoke-WebRequest -Uri 'https://github.com/ryanoasis/nerd-fonts/releases/download/v2.1.0/Hack.zip' -OutFile .\Hack.zip
    # Instalacion de fuentes
    Expand-Archive .\powerlinefonts.zip
    .\powerlinefonts\fonts-master\install.ps1
    Expand-Archive .\Hack.zip
    $arrayFonts = @("Hack Bold Nerd Font Complete.ttf", "Hack Bold Nerd Font Complete Mono.ttf", "Hack Regular Nerd Font Complete Mono.ttf", "Hack Regular Nerd Font Complete.ttf")
    foreach ($fonts in $arrayFonts){ 
        Copy-Item -Path ".\Hack\$fonts" -Destination "C:\Windows\Fonts\$fonts" -Force
        New-ItemProperty -Name $fonts -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -PropertyType string -Value $fonts
    }
    # Eliminar archivos descargados de fuentes
    Remove-Item .\powerlinefonts.zip
    Remove-Item .\powerlinefonts -Recurse
    Remove-Item .\Hack.zip
    Remove-Item .\Hack -Recurse
    Import-Module oh-my-posh
    Import-Module posh-git
    # Establecer tema
    Set-PoshPrompt -Theme paradox
    # Configurando archivo de perfil
    if (!(Test-Path -Path $PROFILE )){ 
        New-Item -Type File -Path $PROFILE -Force
        Write-Output "Import-Module oh-my-posh" > $PROFILE
        Write-Output "Import-Module posh-git" >> $PROFILE
        Write-Output "Set-PoshPrompt -Theme paradox" >> $PROFILE
        Write-Output '."${Env:USERPROFILE}\Documents\WindowsPowerShell\Scripts\SetConsoleFont.ps1"' >> $PROFILE
        Write-Output '[ProfileUtility.FontSetter]::SetConsoleFont("Hack Nerd Font Mono", 14)' >> $PROFILE
    } else {
        Write-Output "Import-Module oh-my-posh" > $PROFILE
        Write-Output "Import-Module posh-git" >> $PROFILE
        Write-Output "Set-PoshPrompt -Theme paradox" >> $PROFILE
        Write-Output '."${Env:USERPROFILE}\Documents\WindowsPowerShell\Scripts\SetConsoleFont.ps1"' >> $PROFILE
        Write-Output '[ProfileUtility.FontSetter]::SetConsoleFont("Hack Nerd Font Mono", 14)' >> $PROFILE
    }
    # Configurando Fuente y tamano
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SeeminglyScience/dotfiles/c4fa75ceddbdb5d9b6d16b90428969cc1c37fbe7/PowerShell/SetConsoleFont.ps1' -OutFile "${Env:USERPROFILE}\Documents\WindowsPowerShell\Scripts\SetConsoleFont.ps1"
    ."${Env:USERPROFILE}\Documents\WindowsPowerShell\Scripts\SetConsoleFont.ps1"
    [ProfileUtility.FontSetter]::SetConsoleFont("Hack Nerd Font Mono", 15)
    # Instalación de scoop
    Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
    scoop install lsd
    scoop install bat
    scoop install fzf
    scoop install grep
    scoop install file
    scoop install hashcat
    scoop install gobuster
    scoop install cowsay
    scoop install duf
    scoop install less
    scoop install simple-http-server
    scoop install sslscan
    scoop install tar
}

Function Restart {
    Write-Host "`n`n"
    Read-Host "Presione [ENTER] para reiniciar el equipo..."
	Write-Warning " Se reiniciara el equipo..."
    Start-Sleep -Seconds 10
    #Set-ExecutionPolicy Default
	Restart-Computer
}

Function DoneInstallation {
    Write-Host @"
[+]                      Finalizado la instalacion.                       [+]
[+]       Disfrute de su nueva maquina y esperando sea de su agrado,      [+]
[+] con el paso del tiempo se ira agregando mas utilidades y herramientas [+]
"@ -ForegroundColor White -BackgroundColor DarkGreen
    Restart
}

Function Main {
    Banner
    Validations
    Installations
    Configurations
    ConfigPSTerminal
    DoneInstallation
}

Main