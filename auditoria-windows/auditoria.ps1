<#
.SYNOPSIS
    Auditoría básica de seguridad de un equipo Windows. SOLO LECTURA.

.DESCRIPTION
    Revisa sistema y actualizaciones, cuentas, cifrado, antivirus y firewall,
    red, permisos de la carpeta de clientes, programas, copias y bloqueo de
    pantalla. Guarda todo en la carpeta "resultados" junto al script (el USB).

    El script NO cambia ninguna configuración, NO abre ni lista archivos de
    clientes y NO guarda la clave de recuperación de BitLocker.
    La única acción opcional es el análisis rápido de Defender (si encuentra
    una amenaza, Defender puede ponerla en cuarentena).

.PARAMETER CarpetaClientes
    Ruta(s) de las carpetas con archivos de clientes para revisar sus permisos.

.PARAMETER AnalisisRapido
    Lanza un análisis rápido de Microsoft Defender al final (5-15 minutos).

.PARAMETER SinPreguntas
    No hace preguntas al empezar.

.EXAMPLE
    .\auditoria.ps1
    .\auditoria.ps1 -CarpetaClientes 'D:\Clientes' -AnalisisRapido
#>
[CmdletBinding()]
param(
    [string[]]$CarpetaClientes,
    [switch]$AnalisisRapido,
    [switch]$SinPreguntas
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Comprobaciones previas
# ---------------------------------------------------------------------------
$identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$esAdmin   = ([Security.Principal.WindowsPrincipal]$identidad).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) {
    Write-Host 'ERROR: hay que ejecutar el script como administrador.' -ForegroundColor Red
    Write-Host 'Usa EJECUTAR-AUDITORIA.bat o abre PowerShell con "Ejecutar como administrador".'
    exit 1
}

$Base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$UnidadScript = $null
try { $UnidadScript = Split-Path -Qualifier $Base } catch { }

$Fecha  = Get-Date -Format 'yyyy-MM-dd_HHmm'
$Salida = Join-Path (Join-Path $Base 'resultados') "$($env:COMPUTERNAME)_$Fecha"
New-Item -ItemType Directory -Path $Salida -Force | Out-Null

Write-Host ''
Write-Host '=============================================' -ForegroundColor Cyan
Write-Host '  AUDITORIA DE SEGURIDAD (solo lectura)'      -ForegroundColor Cyan
Write-Host '=============================================' -ForegroundColor Cyan
Write-Host "Equipo    : $env:COMPUTERNAME"
Write-Host "Resultados: $Salida"
Write-Host ''

if (-not $SinPreguntas) {
    if (-not $CarpetaClientes) {
        Write-Host 'Ruta de la carpeta con archivos de clientes (para revisar QUIEN tiene acceso).'
        Write-Host 'Puedes poner varias separadas por ;   Ejemplo: C:\Users\Ana\Documents\Clientes'
        $r = Read-Host 'Ruta (Enter para omitir)'
        if ($r) { $CarpetaClientes = $r -split ';' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ } }
    }
    if (-not $AnalisisRapido) {
        $r = Read-Host 'Lanzar al final un analisis rapido de Defender? Tarda 5-15 min (s/N)'
        if ($r -match '^(s|si|sí|y)') { $AnalisisRapido = $true }
    }
    Write-Host ''
}

try { Start-Transcript -Path (Join-Path $Salida '99-consola-completa.txt') | Out-Null } catch { }

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
$Resumen = New-Object System.Collections.Generic.List[object]

function Add-Hallazgo {
    param([string]$Estado, [string]$Area, [string]$Detalle)
    $Resumen.Add([pscustomobject]@{ Estado = $Estado; Area = $Area; Detalle = $Detalle })
}

function Save-Section {
    param([string]$Nombre, [scriptblock]$Bloque)
    $ruta = Join-Path $Salida $Nombre
    Write-Host "[*] $Nombre" -ForegroundColor Cyan
    try {
        & $Bloque *>&1 | Out-String -Width 250 | Out-File -FilePath $ruta -Encoding utf8
    } catch {
        "ERROR en la seccion: $($_.Exception.Message)" | Out-File -FilePath $ruta -Encoding utf8 -Append
        Add-Hallazgo 'ERROR' $Nombre $_.Exception.Message
    }
}

function Get-SidSeguro {
    param([string]$Cuenta)
    try {
        return ([System.Security.Principal.NTAccount]$Cuenta).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return $Cuenta }
}

# Grupos "demasiado amplios": si tienen acceso, cualquiera del equipo/red lo tiene
$SidsAmplios = @{
    'S-1-1-0'      = 'Todos (Everyone)'
    'S-1-5-7'      = 'Anonimo'
    'S-1-5-11'     = 'Usuarios autenticados'
    'S-1-5-32-545' = 'Usuarios'
    'S-1-5-32-546' = 'Invitados'
}

# Programas de control remoto: no son malos, pero hay que confirmar que se usan
$RegexRemoto = 'AnyDesk|TeamViewer|RustDesk|UltraViewer|ScreenConnect|ConnectWise|Splashtop|LogMeIn|Remote Utilities|Supremo|AeroAdmin|VNC|Atera|NinjaRMM|Chrome Remote Desktop|DWService|MeshAgent'

# ---------------------------------------------------------------------------
# 1. Sistema y actualizaciones
# ---------------------------------------------------------------------------
Save-Section '01-sistema-actualizaciones.txt' {
    '=== SISTEMA OPERATIVO ==='
    $os = Get-CimInstance Win32_OperatingSystem
    $os | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime | Format-List

    '=== EQUIPO ==='
    Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Domain, PartOfDomain | Format-List

    $build = [int]$os.BuildNumber
    if ($build -lt 22000) {
        Add-Hallazgo 'MAL' 'Sistema' "$($os.Caption) (build $build): Windows 10 o anterior ya no recibe parches de seguridad. Actualizar a Windows 11."
    } elseif ($build -lt 26100) {
        Add-Hallazgo 'REVISAR' 'Sistema' "$($os.Caption) (build $build): version de Windows 11 antigua, actualizar a la ultima."
    } else {
        Add-Hallazgo 'OK' 'Sistema' "$($os.Caption) (build $build)"
    }

    '=== ULTIMAS ACTUALIZACIONES INSTALADAS ==='
    $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending
    $hf | Select-Object -First 15 HotFixID, Description, InstalledOn | Format-Table -AutoSize

    $ultimaFecha = $null
    if ($hf) { $ultimaFecha = ($hf | Select-Object -First 1).InstalledOn }
    try {
        $wu = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
        "Ultima instalacion correcta segun Windows Update: $wu"
        if ($wu -and (-not $ultimaFecha -or $wu -gt $ultimaFecha)) { $ultimaFecha = $wu }
    } catch { }

    if ($ultimaFecha) {
        $dias = ((Get-Date) - $ultimaFecha).Days
        if ($dias -gt 45) { Add-Hallazgo 'MAL' 'Actualizaciones' "La ultima actualizacion se instalo hace $dias dias." }
        else              { Add-Hallazgo 'OK'  'Actualizaciones' "Ultima actualizacion hace $dias dias." }
    } else {
        Add-Hallazgo 'MANUAL' 'Actualizaciones' 'No se pudo saber la fecha; mirar Configuracion > Windows Update.'
    }

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        Add-Hallazgo 'REVISAR' 'Actualizaciones' 'Hay actualizaciones esperando un reinicio.'
    }
}

# ---------------------------------------------------------------------------
# 2. Cuentas de usuario y contraseñas
# ---------------------------------------------------------------------------
Save-Section '02-cuentas-contrasenas.txt' {
    '=== USUARIOS LOCALES ==='
    $usuarios = Get-LocalUser
    $usuarios | Select-Object Name, Enabled, PrincipalSource, LastLogon, PasswordRequired, PasswordLastSet | Format-Table -AutoSize

    $invitado = $usuarios | Where-Object { $_.SID.Value -like '*-501' }
    if ($invitado -and $invitado.Enabled) { Add-Hallazgo 'MAL' 'Cuentas' 'La cuenta Invitado esta activada.' }

    $adminIntegrado = $usuarios | Where-Object { $_.SID.Value -like '*-500' }
    if ($adminIntegrado -and $adminIntegrado.Enabled) { Add-Hallazgo 'REVISAR' 'Cuentas' "La cuenta Administrador integrada ($($adminIntegrado.Name)) esta activada." }

    foreach ($u in ($usuarios | Where-Object { $_.Enabled -and -not $_.PasswordRequired })) {
        Add-Hallazgo 'REVISAR' 'Cuentas' "La cuenta $($u.Name) puede no tener contrasena (PasswordRequired = False)."
    }

    foreach ($u in ($usuarios | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-180) })) {
        Add-Hallazgo 'REVISAR' 'Cuentas' "La cuenta $($u.Name) esta activa pero no se usa desde $($u.LastLogon.ToString('dd/MM/yyyy'))."
    }

    '=== MIEMBROS DEL GRUPO ADMINISTRADORES ==='
    $nombresAdmin = @()
    try {
        $admins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop
        $admins | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize
        $nombresAdmin = $admins | ForEach-Object { ($_.Name -split '\\')[-1] }
    } catch {
        # Get-LocalGroupMember falla si hay cuentas huerfanas: usamos "net localgroup"
        $grupo  = (Get-LocalGroup -SID 'S-1-5-32-544').Name
        $lineas = net localgroup "$grupo"
        $lineas
        $guion  = ($lineas | Select-String -Pattern '^-{5,}' | Select-Object -First 1).LineNumber
        if ($guion) {
            $miembros = $lineas[$guion..($lineas.Count - 1)] | Where-Object { $_.Trim() }
            if ($miembros.Count -gt 1) { $miembros = $miembros[0..($miembros.Count - 2)] }  # quita "comando completado"
            $nombresAdmin = $miembros | ForEach-Object { ($_.Trim() -split '\\')[-1] }
        }
    }

    $usuarioConsola = (Get-CimInstance Win32_ComputerSystem).UserName
    "Usuario con la sesion abierta en pantalla: $usuarioConsola"
    if ($usuarioConsola) {
        $corto = ($usuarioConsola -split '\\')[-1]
        if ($nombresAdmin -contains $corto) {
            Add-Hallazgo 'REVISAR' 'Cuentas' "El usuario del dia a dia ($corto) es ADMINISTRADOR. Mejor usar una cuenta estandar y otra admin aparte."
        } else {
            Add-Hallazgo 'OK' 'Cuentas' "El usuario del dia a dia ($corto) no es administrador."
        }
    }

    '=== POLITICA DE CONTRASENAS Y BLOQUEO ==='
    net accounts

    $tmp = Join-Path $env:TEMP ("secpol_{0}.inf" -f (Get-Random))
    try {
        secedit /export /cfg "$tmp" /areas SECURITYPOLICY | Out-Null
        $pol = @{}
        Get-Content $tmp | ForEach-Object {
            if ($_ -match '^\s*(\w+)\s*=\s*(.+)$') { $pol[$matches[1]] = $matches[2].Trim() }
        }
        "MinimumPasswordLength = $($pol['MinimumPasswordLength'])"
        "PasswordComplexity    = $($pol['PasswordComplexity'])"
        "LockoutBadCount       = $($pol['LockoutBadCount'])"

        if ([int]$pol['MinimumPasswordLength'] -lt 12) {
            Add-Hallazgo 'REVISAR' 'Contrasenas' "Longitud minima de contrasena local: $($pol['MinimumPasswordLength']) (recomendado 12 o mas). Si entra con cuenta Microsoft, lo importante es que esa cuenta tenga 2FA."
        }
        if ([int]$pol['LockoutBadCount'] -eq 0) {
            Add-Hallazgo 'REVISAR' 'Contrasenas' 'No hay bloqueo de cuenta tras intentos fallidos.'
        }
    } catch {
        "No se pudo leer la politica con secedit: $($_.Exception.Message)"
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }

    '=== INICIO DE SESION AUTOMATICO ==='
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    "AutoAdminLogon = $($wl.AutoAdminLogon)"
    if ($wl.AutoAdminLogon -eq '1') { Add-Hallazgo 'MAL' 'Cuentas' 'El equipo inicia sesion solo, sin pedir contrasena.' }
    if ($wl.DefaultPassword) {
        # No se escribe el valor: solo se avisa de que existe
        Add-Hallazgo 'MAL' 'Cuentas' 'Hay una contrasena guardada en claro en el registro (Winlogon\DefaultPassword).'
    }
}

# ---------------------------------------------------------------------------
# 3. Cifrado del disco, TPM y arranque seguro
# ---------------------------------------------------------------------------
Save-Section '03-cifrado-disco.txt' {
    # IMPORTANTE: nunca se muestra KeyProtector, porque contiene la clave de recuperacion.
    $fijas = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object -ExpandProperty DeviceID
    "Unidades fijas: $($fijas -join ', ')"
    "Unidad del USB (se ignora): $UnidadScript"
    ''

    $hecho = $false
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $vols = Get-BitLockerVolume -ErrorAction Stop
            '=== BITLOCKER ==='
            $vols | Select-Object MountPoint, VolumeType, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod | Format-Table -AutoSize
            foreach ($d in $fijas) {
                if ($d -eq $UnidadScript) { continue }
                $v = $vols | Where-Object { $_.MountPoint -eq $d }
                if ($v -and "$($v.ProtectionStatus)" -eq 'On') {
                    Add-Hallazgo 'OK' 'Cifrado' "Unidad $d cifrada con BitLocker."
                } else {
                    Add-Hallazgo 'MAL' 'Cifrado' "Unidad $d SIN cifrar (o proteccion suspendida). Si roban el equipo, se leen los datos."
                }
            }
            $hecho = $true
        } catch {
            "Get-BitLockerVolume fallo: $($_.Exception.Message)"
        }
    }
    if (-not $hecho) {
        '=== MANAGE-BDE ==='
        manage-bde -status
        Add-Hallazgo 'MANUAL' 'Cifrado' 'Revisar 03-cifrado-disco.txt. En Windows Home: Configuracion > Privacidad y seguridad > Cifrado del dispositivo.'
    }

    '=== TPM ==='
    try { Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled | Format-List } catch { "TPM: $($_.Exception.Message)" }

    '=== ARRANQUE SEGURO (Secure Boot) ==='
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        "Secure Boot activado: $sb"
        if (-not $sb) { Add-Hallazgo 'REVISAR' 'Arranque' 'Secure Boot esta desactivado en la BIOS/UEFI.' }
    } catch {
        "Secure Boot: no compatible o arranque en modo BIOS heredado ($($_.Exception.Message))"
        Add-Hallazgo 'REVISAR' 'Arranque' 'Secure Boot no disponible (equipo antiguo o modo BIOS heredado).'
    }
}

# ---------------------------------------------------------------------------
# 4. Antivirus, firewall y UAC
# ---------------------------------------------------------------------------
Save-Section '04-antivirus-firewall.txt' {
    '=== ANTIVIRUS REGISTRADOS EN EL CENTRO DE SEGURIDAD ==='
    $avs = @()
    try { $avs = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop) } catch { }
    $avs | Select-Object displayName, productState, timestamp | Format-Table -AutoSize
    $otroAV = $avs | Where-Object { $_.displayName -notmatch 'Defender' }

    '=== MICROSOFT DEFENDER ==='
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $mp | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                            IsTamperProtected, AntivirusSignatureLastUpdated, AntivirusSignatureAge, QuickScanAge, FullScanAge |
              Format-List

        if ($mp.RealTimeProtectionEnabled) {
            Add-Hallazgo 'OK' 'Antivirus' 'Defender con proteccion en tiempo real activa.'
            if ($mp.AntivirusSignatureAge -gt 3) {
                Add-Hallazgo 'REVISAR' 'Antivirus' "Las firmas de Defender tienen $($mp.AntivirusSignatureAge) dias."
            }
            if (-not $mp.IsTamperProtected) {
                Add-Hallazgo 'REVISAR' 'Antivirus' 'Proteccion contra alteraciones desactivada (Seguridad de Windows > Proteccion antivirus).'
            }
        } elseif ($otroAV) {
            Add-Hallazgo 'MANUAL' 'Antivirus' "Defender desactivado; hay otro antivirus ($(($otroAV.displayName) -join ', ')). Comprobar que esta activo y actualizado."
        } else {
            Add-Hallazgo 'MAL' 'Antivirus' 'Proteccion en tiempo real DESACTIVADA y no hay otro antivirus.'
        }
    } catch {
        "No se pudo consultar Defender: $($_.Exception.Message)"
        if ($otroAV) { Add-Hallazgo 'MANUAL' 'Antivirus' "Antivirus de terceros: $(($otroAV.displayName) -join ', '). Comprobar que esta activo." }
        else         { Add-Hallazgo 'MAL' 'Antivirus' 'No se pudo comprobar ningun antivirus activo.' }
    }

    '=== AMENAZAS EN EL HISTORIAL DE DEFENDER ==='
    try {
        $am = Get-MpThreat -ErrorAction Stop
        $am | Select-Object ThreatName, SeverityID, IsActive, DidThreatExecute | Format-Table -AutoSize
        if ($am | Where-Object { $_.IsActive }) { Add-Hallazgo 'MAL' 'Antivirus' 'Hay amenazas ACTIVAS detectadas por Defender.' }
        elseif ($am)                            { Add-Hallazgo 'REVISAR' 'Antivirus' 'Hay amenazas en el historial de Defender (ya tratadas). Revisar cuales.' }
    } catch { 'Sin datos de amenazas.' }

    '=== FIREWALL ==='
    $fw = Get-NetFirewallProfile
    $fw | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize
    $apagados = $fw | Where-Object { "$($_.Enabled)" -eq 'False' }
    if ($apagados) { Add-Hallazgo 'MAL' 'Firewall' "Firewall DESACTIVADO en: $(($apagados.Name) -join ', ')." }
    else           { Add-Hallazgo 'OK'  'Firewall' 'Firewall activo en todos los perfiles.' }

    '=== CONTROL DE CUENTAS DE USUARIO (UAC) ==='
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    "EnableLUA                  = $($uac.EnableLUA)"
    "ConsentPromptBehaviorAdmin = $($uac.ConsentPromptBehaviorAdmin)"
    if ($uac.EnableLUA -eq 0)                  { Add-Hallazgo 'MAL'     'UAC' 'El Control de cuentas de usuario (UAC) esta desactivado.' }
    elseif ($uac.ConsentPromptBehaviorAdmin -eq 0) { Add-Hallazgo 'REVISAR' 'UAC' 'UAC eleva permisos sin preguntar.' }
}

# ---------------------------------------------------------------------------
# 5. Red: puertos, carpetas compartidas, escritorio remoto, SMBv1
# ---------------------------------------------------------------------------
Save-Section '05-red.txt' {
    '=== DIRECCIONES IP (usa esta IP para nmap desde TU equipo) ==='
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize

    '=== TIPO DE RED (Publica es lo mas seguro fuera de casa/oficina) ==='
    Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory | Format-Table -AutoSize

    $procs = @{}
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }

    '=== PUERTOS TCP ESCUCHANDO ==='
    $tcp = Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{ n = 'Proceso'; e = { $procs[[int]$_.OwningProcess] } } |
        Sort-Object LocalPort
    $tcp | Format-Table -AutoSize

    $peligrosos = @{ 21 = 'FTP'; 23 = 'Telnet'; 3389 = 'Escritorio remoto'; 5800 = 'VNC'; 5900 = 'VNC'; 5938 = 'TeamViewer'; 7070 = 'AnyDesk' }
    foreach ($c in $tcp) {
        $p = [int]$c.LocalPort
        if ($peligrosos.ContainsKey($p) -and $c.LocalAddress -notin @('127.0.0.1', '::1')) {
            Add-Hallazgo 'REVISAR' 'Red' "Puerto $p ($($peligrosos[$p])) abierto a la red, proceso $($c.Proceso)."
        }
    }

    '=== PUERTOS UDP ==='
    Get-NetUDPEndpoint |
        Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') } |
        Select-Object LocalAddress, LocalPort, @{ n = 'Proceso'; e = { $procs[[int]$_.OwningProcess] } } |
        Sort-Object LocalPort -Unique | Format-Table -AutoSize

    '=== CARPETAS COMPARTIDAS ==='
    $shares = Get-SmbShare
    $shares | Select-Object Name, Path, Description, Special | Format-Table -AutoSize
    foreach ($s in ($shares | Where-Object { -not $_.Special -and $_.Name -notmatch '\$$' })) {
        "--- Permisos de la carpeta compartida '$($s.Name)' ---"
        $acc = Get-SmbShareAccess -Name $s.Name
        $acc | Select-Object AccountName, AccessControlType, AccessRight | Format-Table -AutoSize
        Add-Hallazgo 'REVISAR' 'Red' "Carpeta compartida '$($s.Name)' ($($s.Path)). Confirmar que se necesita."
        foreach ($a in $acc) {
            $sid = Get-SidSeguro $a.AccountName
            if ($SidsAmplios.ContainsKey($sid) -and "$($a.AccessControlType)" -eq 'Allow') {
                Add-Hallazgo 'MAL' 'Red' "La carpeta compartida '$($s.Name)' da acceso '$($a.AccessRight)' a $($SidsAmplios[$sid])."
            }
        }
    }

    '=== SMBv1 (protocolo antiguo, usado por WannaCry) ==='
    try {
        $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
        "EnableSMB1Protocol = $smb1"
        if ($smb1) { Add-Hallazgo 'MAL' 'Red' 'SMBv1 esta activado. Desactivarlo.' }
    } catch { "No se pudo comprobar SMBv1: $($_.Exception.Message)" }

    '=== ESCRITORIO REMOTO (RDP) ==='
    $ts  = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
    "fDenyTSConnections = $($ts.fDenyTSConnections)  (0 = activado, 1 = desactivado)"
    "UserAuthentication (NLA) = $nla"
    if ($ts.fDenyTSConnections -eq 0) {
        Add-Hallazgo 'REVISAR' 'Red' 'Escritorio remoto ACTIVADO. Desactivarlo si no se usa.'
        if ($nla -eq 0) { Add-Hallazgo 'MAL' 'Red' 'Escritorio remoto sin autenticacion a nivel de red (NLA).' }
    } else {
        Add-Hallazgo 'OK' 'Red' 'Escritorio remoto desactivado.'
    }
}

# ---------------------------------------------------------------------------
# 6. Permisos de las carpetas de clientes (NO se listan ni abren archivos)
# ---------------------------------------------------------------------------
Save-Section '06-permisos-carpetas-clientes.txt' {
    if (-not $CarpetaClientes) {
        'No se indico ninguna carpeta de clientes.'
        Add-Hallazgo 'MANUAL' 'Permisos' 'No se revisaron permisos de la carpeta de clientes. Usar: icacls "RUTA"'
        return
    }
    foreach ($carpeta in $CarpetaClientes) {
        "=== $carpeta ==="
        if (-not (Test-Path -LiteralPath $carpeta -PathType Container)) {
            'La carpeta no existe o no es una carpeta.'
            Add-Hallazgo 'ERROR' 'Permisos' "No se encontro la carpeta $carpeta"
            continue
        }
        $acl = Get-Acl -LiteralPath $carpeta
        "Propietario: $($acl.Owner)"
        $acl.Access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited | Format-Table -AutoSize -Wrap

        $hayAmplio = $false
        foreach ($regla in $acl.Access) {
            $sid = Get-SidSeguro $regla.IdentityReference.Value
            if ($SidsAmplios.ContainsKey($sid) -and "$($regla.AccessControlType)" -eq 'Allow') {
                $hayAmplio = $true
                $derechos = "$($regla.FileSystemRights)"
                $estado = if ($derechos -match 'FullControl|Modify|Write') { 'MAL' } else { 'REVISAR' }
                Add-Hallazgo $estado 'Permisos' "La carpeta de clientes '$carpeta' da '$derechos' a $($SidsAmplios[$sid])."
            }
        }
        if (-not $hayAmplio) { Add-Hallazgo 'OK' 'Permisos' "La carpeta '$carpeta' no da acceso a grupos amplios." }

        if ($carpeta -match 'OneDrive|Dropbox|Google Drive|My Drive|Mi unidad|iCloud|Box') {
            Add-Hallazgo 'MANUAL' 'Permisos' "La carpeta '$carpeta' se sincroniza con la nube: comprobar 2FA de esa cuenta y los enlaces compartidos."
        }
    }
}

# ---------------------------------------------------------------------------
# 7. Programas al inicio, tareas programadas y software instalado
# ---------------------------------------------------------------------------
Save-Section '07-programas.txt' {
    '=== PROGRAMAS QUE ARRANCAN CON WINDOWS ==='
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize -Wrap

    '=== TAREAS PROGRAMADAS (no de Microsoft) ==='
    Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and "$($_.State)" -ne 'Disabled' } |
        Select-Object TaskName, TaskPath, State,
                      @{ n = 'Accion'; e = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' } } |
        Format-Table -AutoSize -Wrap

    '=== SOFTWARE INSTALADO ==='
    $rutas = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $sw = Get-ItemProperty $rutas -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName } |
          Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
          Sort-Object DisplayName -Unique
    $sw | Format-Table -AutoSize
    "Total: $(@($sw).Count) programas"

    foreach ($p in ($sw | Where-Object { $_.DisplayName -match $RegexRemoto })) {
        Add-Hallazgo 'REVISAR' 'Programas' "Programa de control remoto instalado: $($p.DisplayName). Confirmar que lo instalo el y que lo usa."
    }
    foreach ($p in ($sw | Where-Object { $_.DisplayName -match 'Adobe Flash|QuickTime|Silverlight|Java\(TM\) [67]|Java 7|Java 6' })) {
        Add-Hallazgo 'MAL' 'Programas' "Software obsoleto e inseguro: $($p.DisplayName). Desinstalar."
    }

    '=== SERVICIOS DE CONTROL REMOTO ==='
    Get-Service | Where-Object { $_.DisplayName -match $RegexRemoto -or $_.Name -match $RegexRemoto } |
        Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

    '=== PROGRAMAS CON ACTUALIZACION PENDIENTE (winget, solo consulta) ==='
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget upgrade --accept-source-agreements 2>&1
        Add-Hallazgo 'MANUAL' 'Programas' 'Revisar la lista de winget en 07-programas.txt y actualizar con: winget upgrade --all'
    } else {
        'winget no esta disponible para este usuario.'
    }
}

# ---------------------------------------------------------------------------
# 8. Copias de seguridad
# ---------------------------------------------------------------------------
Save-Section '08-copias-seguridad.txt' {
    '=== PUNTOS DE RESTAURACION (NO son una copia de seguridad) ==='
    try {
        Get-ComputerRestorePoint -ErrorAction Stop |
            Select-Object @{ n = 'Fecha'; e = { $_.ConvertToDateTime($_.CreationTime) } }, Description | Format-Table -AutoSize
    } catch { 'Sin puntos de restauracion o desactivados.' }

    '=== INSTANTANEAS DE VOLUMEN ==='
    Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Select-Object InstallDate, VolumeName | Format-Table -AutoSize

    '=== HISTORIAL DE ARCHIVOS (del usuario que ejecuta el script) ==='
    $fh = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\FileHistory\Configuration'
    "Configurado: $(Test-Path $fh)"

    '=== SINCRONIZACION CON LA NUBE ==='
    Get-Process -Name OneDrive, Dropbox, GoogleDriveFS -ErrorAction SilentlyContinue | Select-Object ProcessName -Unique | Format-Table -AutoSize

    Add-Hallazgo 'MANUAL' 'Copias' 'Preguntar donde y cada cuanto se hace la copia, si hay una desconectada del equipo, y PROBAR a restaurar un archivo.'
}

# ---------------------------------------------------------------------------
# 9. Bloqueo de pantalla
# ---------------------------------------------------------------------------
Save-Section '09-bloqueo-pantalla.txt' {
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $ss  = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
    "InactivityTimeoutSecs (politica) = $($pol.InactivityTimeoutSecs)"
    "Protector de pantalla activo     = $($ss.ScreenSaveActive)"
    "Pide contrasena al volver        = $($ss.ScreenSaverIsSecure)"
    "Tiempo del protector (segundos)  = $($ss.ScreenSaveTimeOut)"
    ''
    'Nota: si el script se ejecuto con otra cuenta de administrador, los datos del protector de pantalla son los de esa cuenta.'

    $ok = ($pol.InactivityTimeoutSecs -gt 0 -and $pol.InactivityTimeoutSecs -le 900) -or
          ($ss.ScreenSaveActive -eq '1' -and $ss.ScreenSaverIsSecure -eq '1' -and [int]$ss.ScreenSaveTimeOut -le 900)
    if ($ok) { Add-Hallazgo 'OK' 'Bloqueo' 'Hay bloqueo automatico de pantalla en 15 minutos o menos.' }
    else     { Add-Hallazgo 'REVISAR' 'Bloqueo' 'No se detecta bloqueo automatico. Comprobar en Configuracion > Cuentas > Opciones de inicio de sesion y en el protector de pantalla.' }
}

# ---------------------------------------------------------------------------
# 10. Análisis rápido de Defender (opcional)
# ---------------------------------------------------------------------------
if ($AnalisisRapido) {
    Write-Host '    (el analisis rapido puede tardar 5-15 minutos, no cierres la ventana)' -ForegroundColor Yellow
    Save-Section '10-analisis-antivirus.txt' {
        "Inicio: $(Get-Date)"
        Start-MpScan -ScanType QuickScan
        "Fin: $(Get-Date)"
        Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Sort-Object InitialDetectionTime -Descending |
            Select-Object -First 20 InitialDetectionTime, ThreatID, ActionSuccess | Format-Table -AutoSize
        Add-Hallazgo 'OK' 'Antivirus' 'Analisis rapido de Defender completado (ver 10-analisis-antivirus.txt).'
    }
}

# ---------------------------------------------------------------------------
# Comprobaciones que hay que hacer a mano
# ---------------------------------------------------------------------------
Add-Hallazgo 'MANUAL' 'Cuentas online' 'Comprobar que el correo y la nube tienen verificacion en dos pasos (2FA).'
Add-Hallazgo 'MANUAL' 'Cuentas online' 'Comprobar el correo en https://haveibeenpwned.com'
Add-Hallazgo 'MANUAL' 'Contrasenas' 'Preguntar si usa contrasenas distintas en cada sitio y si tiene gestor de contrasenas.'
Add-Hallazgo 'MANUAL' 'USB' 'Preguntar si guarda datos de clientes en USB y si estan cifrados (BitLocker To Go).'

# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------
$orden    = @{ 'MAL' = 0; 'REVISAR' = 1; 'MANUAL' = 2; 'ERROR' = 3; 'OK' = 4 }
$ordenado = $Resumen | Sort-Object @{ e = { $orden[$_.Estado] } }, Area
$conteo   = $Resumen | Group-Object Estado | ForEach-Object { "$($_.Name): $($_.Count)" }

$cabecera = @"
=====================================================================
 AUDITORIA DE SEGURIDAD - RESUMEN
=====================================================================
 Equipo        : $env:COMPUTERNAME
 Fecha         : $(Get-Date -Format 'dd/MM/yyyy HH:mm')
 Ejecutado por : $env:USERNAME
 Totales       : $($conteo -join ' | ')

 Leyenda:
   MAL     = arreglar cuanto antes
   REVISAR = comprobar si es intencionado o mejorable
   MANUAL  = hay que comprobarlo a mano / preguntando
   ERROR   = el script no pudo comprobarlo
   OK      = correcto
=====================================================================

"@

$cabecera + ($ordenado | Format-Table Estado, Area, Detalle -AutoSize -Wrap | Out-String -Width 250) |
    Out-File -FilePath (Join-Path $Salida '00-RESUMEN.txt') -Encoding utf8
$ordenado | Export-Csv -Path (Join-Path $Salida '00-resumen.csv') -Delimiter ';' -NoTypeInformation -Encoding UTF8

try { Stop-Transcript | Out-Null } catch { }

Write-Host ''
Write-Host '=============================================' -ForegroundColor Cyan
Write-Host '  RESUMEN'                                     -ForegroundColor Cyan
Write-Host '=============================================' -ForegroundColor Cyan
$colores = @{ 'MAL' = 'Red'; 'REVISAR' = 'Yellow'; 'MANUAL' = 'Gray'; 'ERROR' = 'Magenta'; 'OK' = 'Green' }
foreach ($h in $ordenado) {
    Write-Host ('[{0,-7}] {1,-15} {2}' -f $h.Estado, $h.Area, $h.Detalle) -ForegroundColor $colores[$h.Estado]
}
Write-Host ''
Write-Host "Resultados guardados en: $Salida" -ForegroundColor Green
Write-Host 'Empieza leyendo 00-RESUMEN.txt. Expulsa el USB de forma segura antes de quitarlo.'
