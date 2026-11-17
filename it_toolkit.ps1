<#
.SYNOPSIS
  IT Toolkit para Windows (PowerShell) - v2.5
  1) Informe visual del sistema (CPU, GPU, RAM, discos, red...) -> guarda un .txt numerado por equipo
  2) Diagnóstico de red paso a paso (IP local/pública, DHCP vs estática, Wi-Fi, gateway, internet, DNS, proxy, puertos, latencia) -> guarda un .txt numerado por equipo
  3) Reparación rápida de red (Liberar/Renovar IP + Limpiar DNS)
  4) Reparación profunda de red (Reset Winsock y TCP/IP - requiere Admin)
  5) Ver contraseñas Wi-Fi guardadas (Requiere Admin)

.EXAMPLE
  .\it_toolkit.ps1            # menú interactivo continuo
  .\it_toolkit.ps1 -Sistema   # solo informe del sistema
  .\it_toolkit.ps1 -Red       # solo diagnóstico de red
  .\it_toolkit.ps1 -Todo      # informe + diagnóstico
#>
param(
    [switch]$Sistema,
    [switch]$Red,
    [switch]$Todo
)

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$NA = 'No disponible'
$script:Lines = New-Object System.Collections.Generic.List[string]
$BaseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ========================= UTILIDADES =========================
function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Out-Line {
    param([string]$Text = '', [string]$Color = '')
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
    $script:Lines.Add($Text)
}

function Get-Center([string]$Text, [int]$Width) {
    $pad = [Math]::Max(0, [int](($Width - $Text.Length) / 2))
    return (' ' * $pad) + $Text
}

function Out-Section([string]$Title) {
    Out-Line ''
    Out-Line "[$Title]" 'Cyan'
}

function Out-Bar {
    param([string]$Label, [double]$Percent)
    $len = 30
    $p = [Math]::Max(0, [Math]::Min($Percent, 100))
    $filled = [int][Math]::Floor($p / 100 * $len)
    $bar = '[' + ('#' * $filled) + ('-' * ($len - $filled)) + ('] {0:N1}%' -f $Percent)
    $color = if ($Percent -lt 70) { 'Green' } elseif ($Percent -lt 90) { 'Yellow' } else { 'Red' }
    Write-Host $Label -NoNewline
    Write-Host $bar -ForegroundColor $color
    $script:Lines.Add($Label + $bar)
}

function Get-CleanValue($Value) {
    $v = ([string]$Value).Trim()
    if (-not $v -or $v -match '^(none|not specified|not applicable|to be filled by o\.?.e\.?.m\.?|default string|system serial number|0|n/a)$') { return $NA }
    return $v
}

function Format-Bytes([double]$Bytes) {
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    return ('{0:N0} MB' -f ($Bytes / 1MB))
}

function Save-Report([string]$Prefix) {
    $pcName = ($env:COMPUTERNAME -replace '[\\/:*?"<>|]', '_').Trim()
    if (-not $pcName) { $pcName = 'EQUIPO' }

    # Buscar el siguiente número consecutivo (#1, #2, #3...) para este tipo de informe y equipo
    $num = 1
    while (Test-Path (Join-Path $BaseDir ('{0}_{1}_#{2}.txt' -f $Prefix, $pcName, $num))) {
        $num++
    }

    $file = Join-Path $BaseDir ('{0}_{1}_#{2}.txt' -f $Prefix, $pcName, $num)
    try {
        $script:Lines | Set-Content -Path $file -Encoding UTF8 -ErrorAction Stop
        Write-Host ''
        Write-Host "[OK] Informe guardado en: $file" -ForegroundColor Green
    } catch {
        Write-Host ''
        Write-Host "[X] No se pudo guardar el informe en $BaseDir (¿carpeta sin permisos?)" -ForegroundColor Red
    }
}

function Get-LocalIp {
    try {
        $u = New-Object System.Net.Sockets.UdpClient
        $u.Connect('8.8.8.8', 80)
        $ip = $u.Client.LocalEndPoint.Address.ToString()
        $u.Close()
        return $ip
    } catch { return $null }
}

function Get-PublicIp {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
    foreach ($url in @('https://api.ipify.org', 'https://icanhazip.com', 'https://ifconfig.me/ip')) {
        try {
            $r = ([string](Invoke-RestMethod -Uri $url -TimeoutSec 4 -UseBasicParsing)).Trim()
            $parsed = $null
            if ([System.Net.IPAddress]::TryParse($r, [ref]$parsed)) { return $r }
        } catch {}
    }
    return $null
}

# Clasifica una IP: Privada, Publica, CGNAT, APIPA, Loopback, Reservada, Desconocida
function Get-IpType([string]$Ip) {
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return 'Desconocida' }
    $b = $addr.GetAddressBytes()
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($addr.Equals([System.Net.IPAddress]::IPv6Loopback)) { return 'Loopback' }
        if ($b[0] -eq 254 -and ($b[1] -band 192) -eq 128) { return 'Reservada' }   # fe80::/10 (link-local)
        if (($b[0] -band 254) -eq 252) { return 'Privada' }                        # fc00::/7 (ULA)
        return 'Publica'
    }
    if ($b[0] -eq 0)   { return 'Reservada' }
    if ($b[0] -eq 127) { return 'Loopback' }
    if ($b[0] -eq 10)  { return 'Privada' }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return 'Privada' }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return 'Privada' }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return 'APIPA' }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return 'CGNAT' }
    if ($b[0] -ge 224) { return 'Reservada' }
    return 'Publica'
}

function Format-IpType([string]$Type) {
    switch ($Type) {
        'Privada'  { return 'PRIVADA (RFC 1918, solo red local)' }
        'Publica'  { return 'PÚBLICA (enrutable en Internet)' }
        'CGNAT'    { return 'CGNAT (rango compartido del ISP, 100.64.0.0/10)' }
        'APIPA'    { return 'APIPA (autoasignada, sin servidor DHCP)' }
        'Loopback' { return 'LOOPBACK (este mismo equipo)' }
        'Reservada' { return 'RESERVADA / especial' }
        default    { return 'Desconocida' }
    }
}

function Format-IpMode([string]$Mode) {
    switch ($Mode) {
        'DHCP'     { return 'DHCP (automática)' }
        'Estatica' { return 'IP ESTÁTICA (manual)' }
        'APIPA'    { return 'APIPA (el DHCP no respondió, IP autoasignada)' }
        default    { return $NA }
    }
}

function Get-IpModeColor([string]$Mode) {
    switch ($Mode) {
        'DHCP'     { return 'Green' }
        'Estatica' { return 'Yellow' }
        'APIPA'    { return 'Red' }
        default    { return '' }
    }
}

function ConvertTo-Mask([int]$Prefix) {
    $bits = ('1' * $Prefix).PadRight(32, '0')
    return ((0..3 | ForEach-Object { [Convert]::ToInt32($bits.Substring($_ * 8, 8), 2) }) -join '.')
}

# Devuelve un objeto por cada IPv4 activa: tipo (privada/pública), asignación (DHCP/estática), gateway, DNS, etc.
function Get-AdapterIpInfo {
    $result = @()
    $addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.AddressState -eq 'Preferred' }
    foreach ($a in $addrs) {
        $ifc = Get-NetIPInterface -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ("InterfaceIndex={0}" -f $a.InterfaceIndex) -ErrorAction SilentlyContinue
        $dns = Get-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue

        $type = Get-IpType $a.IPAddress
        if ($type -eq 'APIPA')                  { $mode = 'APIPA' }
        elseif ($a.PrefixOrigin -eq 'Dhcp')     { $mode = 'DHCP' }
        elseif ($a.PrefixOrigin -eq 'Manual')   { $mode = 'Estatica' }
        elseif ($ifc -and $ifc.Dhcp -eq 'Enabled') { $mode = 'DHCP' }
        else                                    { $mode = 'Estatica' }

        $dnsList = @()
        if ($dns -and $dns.ServerAddresses) { $dnsList = @($dns.ServerAddresses) }

        # DNS manual o automático (si hay NameServer en el registro de la interfaz, es manual)
        $dnsMode = 'automático'
        if ($cfg -and $cfg.SettingID) {
            $reg = Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0}" -f $cfg.SettingID) -ErrorAction SilentlyContinue
            if ($reg -and $reg.NameServer) { $dnsMode = 'manual' }
        }

        $gw = $null
        if ($cfg -and $cfg.DefaultIPGateway) { $gw = $cfg.DefaultIPGateway[0] }

        $result += [pscustomobject]@{
            Alias         = $a.InterfaceAlias
            IP            = $a.IPAddress
            Prefix        = $a.PrefixLength
            Mask          = (ConvertTo-Mask ([int]$a.PrefixLength))
            Type          = $type
            Mode          = $mode
            Virtual       = [bool]($a.InterfaceAlias -match 'vEthernet|WSL|Hyper-V|VirtualBox|VMware|Loopback|Bluetooth|TAP|VPN')
            Gateway       = $gw
            DhcpServer    = $(if ($cfg) { $cfg.DHCPServer } else { $null })
            LeaseObtained = $(if ($cfg -and $cfg.DHCPLeaseObtained) { $cfg.DHCPLeaseObtained.ToString('yyyy-MM-dd HH:mm') } else { $null })
            LeaseExpires  = $(if ($cfg -and $cfg.DHCPLeaseExpires) { $cfg.DHCPLeaseExpires.ToString('yyyy-MM-dd HH:mm') } else { $null })
            Dns           = $dnsList
            DnsMode       = $dnsMode
        }
    }
    return $result
}

function Show-AdapterIpInfo($Infos) {
    $Infos = @($Infos)
    if ($Infos.Count -eq 0) { Out-Line '   (Ningún adaptador con IPv4 activa)' 'Yellow'; return }
    foreach ($i in $Infos) {
        $virt = if ($i.Virtual) { ' [virtual]' } else { '' }
        Out-Line ''
        Out-Line ("{0}{1}" -f $i.Alias, $virt) 'Cyan'
        Out-Line ("   IP: {0}/{1} (máscara {2})" -f $i.IP, $i.Prefix, $i.Mask)
        Out-Line ("   Tipo de IP: {0}" -f (Format-IpType $i.Type))
        Out-Line ("   Asignación: {0}" -f (Format-IpMode $i.Mode)) (Get-IpModeColor $i.Mode)
        if ($i.Gateway) { Out-Line ("   Gateway: {0}" -f $i.Gateway) }
        if ($i.Mode -eq 'DHCP' -and $i.DhcpServer) {
            Out-Line ("   Servidor DHCP: {0}" -f $i.DhcpServer)
            if ($i.LeaseObtained) { Out-Line ("   Concesión: {0} -> {1}" -f $i.LeaseObtained, $i.LeaseExpires) }
        }
        if ($i.Dns.Count -gt 0) { Out-Line ("   DNS ({0}): {1}" -f $i.DnsMode, ($i.Dns -join ', ')) }
    }
    $phys = @($Infos | Where-Object { -not $_.Virtual -and $_.Gateway })
    if ($phys.Count -gt 1) {
        Out-Line ''
        Out-Line ("[i] Hay {0} adaptadores físicos con gateway activos a la vez ({1})." -f $phys.Count, (($phys | ForEach-Object { $_.Alias }) -join ', ')) 'Yellow'
        Out-Line '    Windows usa el de menor métrica; si hay fallos intermitentes, desactiva el que no uses.' 'Yellow'
    }
}

# Si no es admin, ofrece reabrir el toolkit con elevación (UAC). Si acepta, cierra esta ventana.
function Request-Admin([string]$Reason) {
    if (Test-IsAdmin) { return $true }
    Write-Host "[!] $Reason" -ForegroundColor Yellow
    $resp = Read-Host '¿Reabrir el toolkit como Administrador? (S/N)'
    if ($resp -match '^[sS]') {
        try {
            $psExe = (Get-Process -Id $PID).Path
            $argList = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
            Start-Process -FilePath $psExe -ArgumentList $argList -Verb RunAs -ErrorAction Stop
            exit
        } catch {
            Write-Host '[X] Elevación cancelada o no permitida.' -ForegroundColor Red
        }
    }
    return $false
}

function Get-WifiDetails {
    $info = [pscustomobject]@{ Connected = $false; SSID = $NA; Signal = $NA; Radio = $NA; Channel = $NA; AdapterUp = $false }

    # Respaldo: ¿hay un adaptador Wi-Fi activo aunque netsh no entregue datos?
    $wl = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and ($_.PhysicalMediaType -match '802\.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN') }
    if ($wl) { $info.AdapterUp = $true }

    $raw = netsh wlan show interfaces 2>$null
    if (-not $raw) { return $info }
    foreach ($line in $raw) {
        if ($line -match '^\s*Estado\s*:\s*conectado|^\s*State\s*:\s*connected') { $info.Connected = $true }
        elseif ($line -match '^\s*SSID\s*:\s*(.+)$') { $info.SSID = $Matches[1].Trim() }
        elseif ($line -match '^\s*(Señal|Signal)\s*:\s*(.+)$') { $info.Signal = $Matches[2].Trim() }
        elseif ($line -match '^\s*(Tipo de radio|Radio type)\s*:\s*(.+)$') { $info.Radio = $Matches[2].Trim() }
        elseif ($line -match '^\s*(Canal|Channel)\s*:\s*(.+)$') { $info.Channel = $Matches[2].Trim() }
    }
    return $info
}

# ========================= INFORME DEL SISTEMA =========================
function Get-RealVram {
    $map = @{}
    $key = 'HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*'
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
        $v = $_.'HardwareInformation.qwMemorySize'
        if ($null -ne $v -and $_.DriverDesc) {
            if ($v -is [byte[]] -and $v.Length -ge 8) { $v = [BitConverter]::ToInt64($v, 0) }
            if ($v -is [ValueType]) { $map[[string]$_.DriverDesc] = [double]$v }
        }
    }
    return $map
}

function Invoke-SystemReport {
    $script:Lines.Clear()
    $os  = Get-CimInstance Win32_OperatingSystem
    $cpu = @(Get-CimInstance Win32_Processor)

    Out-Line ('=' * 70) 'Magenta'
    Out-Line (Get-Center 'INFORME DEL SISTEMA' 70) 'Magenta'
    Out-Line (Get-Center (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 70) 'Magenta'
    Out-Line ('=' * 70) 'Magenta'

    Out-Section 'SISTEMA OPERATIVO'
    Out-Line ("OS: {0}" -f $os.Caption)
    Out-Line ("Versión: {0} (compilación {1})" -f $os.Version, $os.BuildNumber)
    Out-Line ("Arquitectura: {0}" -f $os.OSArchitecture)
    Out-Line ("Hostname: {0}" -f $env:COMPUTERNAME)
    Out-Line ("Usuario: {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs) {
        if ($cs.PartOfDomain) {
            $fqdn = if ($cs.DNSHostName) { '{0}.{1}' -f $cs.DNSHostName, $cs.Domain } else { $cs.Name }
            Out-Line 'Pertenece a: Dominio'
            Out-Line ("Nombre del dominio: {0}" -f $cs.Domain)
            Out-Line ("Nombre del equipo en el dominio: {0}" -f $fqdn)
        } else {
            Out-Line 'Pertenece a: Grupo de trabajo (no está en un dominio)'
            Out-Line ("Nombre del grupo de trabajo: {0}" -f $cs.Domain)
            Out-Line ("Nombre del equipo: {0}" -f $cs.Name)
        }
    } else {
        Out-Line "Dominio/Grupo de trabajo: $NA"
    }
    Out-Line ("PowerShell: {0}" -f $PSVersionTable.PSVersion)

    Out-Section 'PROCESADOR'
    $cores   = ($cpu | Measure-Object NumberOfCores -Sum).Sum
    $threads = ($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum
    $load    = ($cpu | Measure-Object LoadPercentage -Average).Average
    Out-Line ("CPU: {0}" -f (($cpu | ForEach-Object { $_.Name.Trim() }) -join ', '))
    Out-Line ("Núcleos físicos: {0}" -f $cores)
    Out-Line ("Núcleos lógicos: {0}" -f $threads)
    Out-Bar 'Uso CPU: ' ([double]$load)

    Out-Section 'GRÁFICOS'
    $real = Get-RealVram
    $gpus = @(Get-CimInstance Win32_VideoController)
    if ($gpus.Count -eq 0) { Out-Line "GPU: $NA" }
    $i = 0
    foreach ($g in $gpus) {
        $i++
        $vram = $null; $approx = $false
        if ($real.ContainsKey([string]$g.Name)) { $vram = $real[[string]$g.Name] }
        elseif ($g.AdapterRAM) { $vram = [double]$g.AdapterRAM; $approx = $true }
        Out-Line ("GPU {0}: {1}" -f $i, $g.Name)
        if ($vram) {
            $note = if ($approx) { ' (aproximado: WMI limita a 4 GB)' } else { '' }
            Out-Line ("   VRAM: {0}{1}" -f (Format-Bytes $vram), $note)
        } else {
            Out-Line "   VRAM: $NA"
        }
    }

    Out-Section 'MEMORIA RAM'
    $total = [double]$os.TotalVisibleMemorySize * 1KB
    $free  = [double]$os.FreePhysicalMemory * 1KB
    Out-Line ("Total: {0}" -f (Format-Bytes $total))
    Out-Line ("Disponible: {0}" -f (Format-Bytes $free))
    Out-Bar 'Usado: ' (($total - $free) / $total * 100)

    $ramSticks = Get-CimInstance Win32_PhysicalMemory
    if ($ramSticks) {
        $stickIndex = 1
        foreach ($stick in $ramSticks) {
            $ddr = "Desconocido"
            switch ($stick.SMBIOSMemoryType) {
                20 { $ddr = "DDR" } 21 { $ddr = "DDR2" } 24 { $ddr = "DDR3" }
                26 { $ddr = "DDR4" } 27 { $ddr = "LPDDR" } 28 { $ddr = "LPDDR2" } 29 { $ddr = "LPDDR3" } 30 { $ddr = "LPDDR4" } 34 { $ddr = "DDR5" } 35 { $ddr = "LPDDR5" }
                default {
                    switch ($stick.MemoryType) {
                        20 { $ddr = "DDR" } 21 { $ddr = "DDR2" } 24 { $ddr = "DDR3" }
                        default { $ddr = "Gen Desconocida" }
                    }
                }
            }
            $mhz = if ($stick.ConfiguredClockSpeed) { $stick.ConfiguredClockSpeed } else { $stick.Speed }
            $speed = if ($mhz) { "$mhz MHz" } else { "Frecuencia desconocida" }
            $cap = if ($stick.Capacity) { (Format-Bytes ([double]$stick.Capacity)) + ' ' } else { '' }
            Out-Line ("  -> Módulo {0}: {1}{2} a {3}" -f $stickIndex, $cap, $ddr, $speed)
            $stickIndex++
        }
    }

    Out-Section 'ALMACENAMIENTO'
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        $driveLetter = $_.DeviceID.Substring(0,1)
        $used = [double]$_.Size - [double]$_.FreeSpace
        $pct  = if ($_.Size) { $used / [double]$_.Size * 100 } else { 0 }
        $diskTypeInfo = ""
        try {
            $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction SilentlyContinue
            if ($partition) {
                $physDisk = Get-PhysicalDisk | Where-Object { [int]$_.DeviceId -eq $partition.DiskNumber } | Select-Object -First 1
                if ($physDisk) {
                    $media = if ($physDisk.MediaType -eq 'Unspecified') { 'Disco' } else { $physDisk.MediaType }
                    $diskTypeInfo = " [$media $($physDisk.BusType)]"
                }
            }
        } catch {}

        Out-Line ''
        Out-Line ("{0} ({1}) {2}{3}" -f $_.DeviceID, $_.FileSystem, $_.VolumeName, $diskTypeInfo)
        Out-Line ("  Total: {0}" -f (Format-Bytes $_.Size))
        Out-Bar ("  Usado: {0} " -f (Format-Bytes $used)) $pct
        Out-Line ("  Libre: {0}" -f (Format-Bytes $_.FreeSpace))
    }

    Out-Section 'RED'
    $ip = Get-LocalIp
    $adapterName = $NA; $speed = $NA
    if ($ip) {
        $idx = (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceIndex
        if ($idx) {
            $ad = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
            if ($ad) {
                $adapterName = "{0} ({1})" -f $ad.Name, $ad.InterfaceDescription
                $speed = $ad.LinkSpeed
            }
        }
    }
    $wifi = Get-WifiDetails
    Out-Line ("Adaptador activo: {0}" -f $adapterName)
    Out-Line ("IP Local: {0}" -f $(if ($ip) { $ip } else { $NA }))
    if ($ip) {
        $mainInfo = Get-AdapterIpInfo | Where-Object { $_.IP -eq $ip } | Select-Object -First 1
        Out-Line ("Tipo de IP local: {0}" -f (Format-IpType (Get-IpType $ip)))
        if ($mainInfo) { Out-Line ("Asignación de IP: {0}" -f (Format-IpMode $mainInfo.Mode)) }
    }
    Out-Line ("Red (SSID): {0} (Señal: {1})" -f $wifi.SSID, $wifi.Signal)
    Out-Line ("Velocidad del enlace: {0}" -f $speed)

    $bat = Get-CimInstance Win32_Battery | Select-Object -First 1
    if ($bat) {
        Out-Section 'BATERÍA'
        Out-Bar 'Nivel: ' ([double]$bat.EstimatedChargeRemaining)
        $plugged = @(2, 3, 6, 7, 8, 9) -contains [int]$bat.BatteryStatus
        Out-Line ("Enchufado: {0}" -f $(if ($plugged) { 'Sí' } else { 'No' }))
    }

    Out-Section 'PLACA BASE'
    $bb = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
    if ($bb) {
        Out-Line ("Fabricante: {0}" -f $bb.Manufacturer)
        Out-Line ("Modelo: {0}" -f $bb.Product)
        Out-Line ("Número de serie (placa): {0}" -f (Get-CleanValue $bb.SerialNumber))
    } else { Out-Line $NA }
    Out-Line ("Número de serie (equipo/BIOS): {0}" -f $(if ($bios) { Get-CleanValue $bios.SerialNumber } else { $NA }))

    Out-Section 'TIEMPO DE ACTIVIDAD'
    $up = (Get-Date) - $os.LastBootUpTime
    Out-Line ("Uptime: {0}d {1}h {2}m" -f $up.Days, $up.Hours, $up.Minutes)

    Out-Line ''
    Out-Line ('=' * 70) 'Magenta'
    Out-Line 'Informe generado con it_toolkit.ps1' 'Magenta'
    Out-Line ('=' * 70) 'Magenta'

    Save-Report 'informe_sistema'
}

# ========================= DIAGNÓSTICO DE RED =========================
function Out-Header([string]$Title) {
    Out-Line ''
    Out-Line ('=' * 60)
    Out-Line "   $Title"
    Out-Line ('=' * 60)
}

function Test-PingHost {
    param([string]$Target, [int]$Count = 4)
    $ping = New-Object System.Net.NetworkInformation.Ping
    $times = @()
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $r = $ping.Send($Target, 2000)
            if ($r.Status -eq 'Success') { $times += [double]$r.RoundtripTime }
        } catch {}
        Start-Sleep -Milliseconds 200
    }
    $ping.Dispose()
    return [pscustomobject]@{ Ok = ($times.Count -gt 0); Times = $times; Sent = $Count }
}

function Test-Ping {
    param([string]$Target, [string]$Name = '')
    $label = if ($Name) { $Name } else { $Target }
    Out-Line ''
    Out-Line "Probando $label..."
    $r = Test-PingHost $Target
    if ($r.Ok) {
        $avg = ($r.Times | Measure-Object -Average).Average
        Out-Line ("   [OK] {0} - RESPONDE ({1}/{2} respuestas, media {3:N1} ms)" -f $label, $r.Times.Count, $r.Sent, $avg) 'Green'
        return $true
    }
    Out-Line "   [X] $label - NO RESPONDE" 'Red'
    return $false
}

function Get-Gateway {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object { $_.RouteMetric + $_.InterfaceMetric } |
        Select-Object -First 1
    if ($route) { return $route.NextHop }
    $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
        Where-Object { $_.DefaultIPGateway } | Select-Object -First 1
    if ($cfg) { return $cfg.DefaultIPGateway[0] }
    return $null
}

function Test-Dns([string]$Domain) {
    Out-Line ''
    Out-Line "Resolviendo DNS: $Domain"
    try {
        $ips = @([System.Net.Dns]::GetHostAddresses($Domain) | Where-Object { $_.AddressFamily -eq 'InterNetwork' })
        if ($ips.Count -gt 0) {
            Out-Line ("   [OK] {0} -> {1}" -f $Domain, $ips[0].IPAddressToString) 'Green'
            return $true
        }
    } catch {}
    Out-Line "   [X] No se pudo resolver $Domain" 'Red'
    return $false
}

function Test-Port {
    param([string]$TargetHost, [int]$Port, [string]$Service)
    $client = New-Object System.Net.Sockets.TcpClient
    $ok = $false
    try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(3000, $false) -and $client.Connected
        if ($ok) { $client.EndConnect($iar) }
    } catch { $ok = $false } finally { $client.Close() }
    if ($ok) {
        Out-Line ("   [OK] {0}:{1} ({2}) ABIERTO" -f $TargetHost, $Port, $Service) 'Green'
    } else {
        Out-Line ("   [X] {0}:{1} ({2}) CERRADO/BLOQUEADO" -f $TargetHost, $Port, $Service) 'Red'
    }
    return [bool]$ok
}

function Show-Latency([string]$Ip, [string]$Name) {
    Out-Line ''
    Out-Line ("Latencia {0} ({1}):" -f $Name, $Ip)
    $r = Test-PingHost $Ip 5
    if (-not $r.Ok) { Out-Line '   [X] Sin respuesta' 'Red'; return }
    $m = $r.Times | Measure-Object -Minimum -Maximum -Average
    $lost = $r.Sent - $r.Times.Count
    Out-Line ("   Mínimo: {0:N0} ms | Media: {1:N1} ms | Máximo: {2:N0} ms" -f $m.Minimum, $m.Average, $m.Maximum)
    Out-Line ("   Paquetes perdidos: {0}/{1} ({2:N0}%)" -f $lost, $r.Sent, ($lost / $r.Sent * 100))
}

function Invoke-NetworkDiagnostic {
    $script:Lines.Clear()
    Out-Line ('=' * 60) 'Magenta'
    Out-Line (Get-Center 'DIAGNÓSTICO DE RED' 60) 'Magenta'
    Out-Line ('=' * 60) 'Magenta'
    Out-Line ("Fecha: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

    # --- Información local ---
    Out-Header 'INFORMACIÓN LOCAL'
    $ip = Get-LocalIp
    $infos = @(Get-AdapterIpInfo)
    $mainInfo = $null
    if ($ip) { $mainInfo = $infos | Where-Object { $_.IP -eq $ip } | Select-Object -First 1 }

    Out-Line ("Hostname: {0}" -f $env:COMPUTERNAME)
    Out-Line ("IP Local Detectada: {0}" -f $(if ($ip) { $ip } else { 'No detectada' }))
    if ($ip) { Out-Line ("   Tipo: {0}" -f (Format-IpType (Get-IpType $ip))) }
    if ($mainInfo) { Out-Line ("   Asignación: {0}" -f (Format-IpMode $mainInfo.Mode)) (Get-IpModeColor $mainInfo.Mode) }

    # IP Pública
    $pubIp = Get-PublicIp
    if ($pubIp) {
        Out-Line ("IP Pública: {0}" -f $pubIp)
        Out-Line ("   Tipo: {0}" -f (Format-IpType (Get-IpType $pubIp)))
        if ($ip -and $ip -eq $pubIp) {
            Out-Line '   Conexión directa a Internet (sin NAT).'
        } elseif ($ip -and (Get-IpType $ip) -eq 'Privada') {
            Out-Line '   Sales a Internet mediante NAT (IP local privada -> IP pública del router).'
        }
    } else {
        Out-Line 'IP Pública: No disponible (sin salida web)' 'Yellow'
    }

    # Detección de Proxy
    $inetSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($inetSettings.ProxyEnable -eq 1) {
        Out-Line ("Proxy del Sistema: ACTIVADO ({0})" -f $inetSettings.ProxyServer) 'Yellow'
    } else {
        Out-Line "Proxy del Sistema: Desactivado"
    }

    # Detalles Wi-Fi si aplica
    $wifi = Get-WifiDetails
    if ($wifi.Connected) {
        Out-Line ''
        Out-Line 'Estado Wi-Fi:'
        Out-Line ("   SSID: {0} | Señal: {1} | Canal: {2} | Tipo: {3}" -f $wifi.SSID, $wifi.Signal, $wifi.Channel, $wifi.Radio)
    } elseif ($wifi.AdapterUp) {
        Out-Line ''
        Out-Line 'Estado Wi-Fi: adaptador activo, pero Windows no entrega SSID/señal.' 'Yellow'
        Out-Line '   Activa Configuración > Privacidad y seguridad > Ubicación (Windows 11 24H2 lo exige para leer datos del Wi-Fi).' 'Yellow'
    }

    Out-Line ''
    Out-Line 'Adaptadores con IP:'
    Show-AdapterIpInfo $infos

    # --- Test 1 ---
    Out-Header 'TEST 1: CONECTIVIDAD LOCAL'
    $loopOk = Test-Ping '127.0.0.1' 'Loopback (Interno)'
    $gw = Get-Gateway
    $gwOk = $false
    if ($gw) {
        Out-Line ''
        Out-Line "Gateway detectado: $gw"
        $gwOk = Test-Ping $gw "Gateway ($gw)"
    } else {
        Out-Line ''
        Out-Line '[!] No se detectó Gateway (¿sin red o sin ruta por defecto?).' 'Yellow'
    }

    # --- Test 2 ---
    Out-Header 'TEST 2: INTERNET Y DNS'
    $netOk = Test-Ping '8.8.8.8' 'Google DNS'
    $dnsOk = Test-Dns 'google.com'

    # --- Test 3 ---
    Out-Header 'TEST 3: PUERTOS CRÍTICOS'
    $httpOk  = Test-Port 'google.com' 80  'HTTP'
    $httpsOk = Test-Port 'google.com' 443 'HTTPS'
    $dnsPOk  = Test-Port '8.8.8.8'    53  'DNS'

    # --- Test 4 ---
    Out-Header 'TEST 4: ESTADÍSTICAS DE LATENCIA'
    Show-Latency '8.8.8.8' 'Google'
    Show-Latency '1.1.1.1' 'Cloudflare'

    # --- Resultado ---
    Out-Header 'RESULTADO FINAL'
    $checks = @(
        @{ N = 'Loopback';                Ok = $loopOk },
        @{ N = 'Gateway';                 Ok = $gwOk },
        @{ N = 'Internet (ping 8.8.8.8)'; Ok = $netOk },
        @{ N = 'DNS (google.com)';        Ok = $dnsOk },
        @{ N = 'Puerto 443 HTTPS';        Ok = $httpsOk }
    )
    $passed = @($checks | Where-Object { $_.Ok }).Count
    $failed = @($checks | Where-Object { -not $_.Ok } | ForEach-Object { $_.N })

    if ($passed -eq $checks.Count)  { $status = 'TODO OK';          $color = 'Green' }
    elseif ($passed -eq 0)          { $status = 'SIN CONEXIÓN';     $color = 'Red' }
    else                            { $status = 'PROBLEMA PARCIAL'; $color = 'Yellow' }

    Out-Line "Estado General: $status" $color
    Out-Line ("Puntuación: {0}/{1} tests principales superados." -f $passed, $checks.Count)
    if ($failed.Count -gt 0) {
        Out-Line ''
        Out-Line ('Tests fallidos: ' + ($failed -join ', ')) 'Red'
    }

    Out-Line ''
    Out-Line 'Resumen de direccionamiento:'
    if ($ip) {
        $modeTxt = if ($mainInfo) { Format-IpMode $mainInfo.Mode } else { $NA }
        Out-Line ('   IP local   : {0} -> {1} | {2}' -f $ip, (Format-IpType (Get-IpType $ip)), $modeTxt)
    }
    if ($pubIp) { Out-Line ('   IP pública : {0} -> {1}' -f $pubIp, (Format-IpType (Get-IpType $pubIp))) }

    Out-Line ''
    Out-Line 'Posible causa:'
    if (-not $loopOk)                      { Out-Line '   La pila de red del propio equipo falla (usa Opción 4 para resetear Winsock/TCP-IP).' }
    elseif (-not $gw)                      { Out-Line '   No hay ruta por defecto: revisa cable/WiFi o usa Opción 3 para renovar IP.' }
    elseif (-not $gwOk)                    { Out-Line '   El equipo no llega al router: revisa cable, WiFi o el router.' }
    elseif (-not $netOk -and -not $dnsOk)  { Out-Line '   Hay red local pero no salida a Internet: probable problema del proveedor (ISP) o del router.' }
    elseif ($netOk -and -not $dnsOk)       { Out-Line '   Internet responde pero el DNS no: prueba limpiar caché DNS (Opción 3) o usar DNS 8.8.8.8.' }
    elseif (-not ($httpOk -and $httpsOk -and $dnsPOk)) { Out-Line '   Algún puerto está bloqueado: revisa firewall, proxy o restricciones de la red.' }
    else                                   { Out-Line '   No se detectaron problemas.' }

    if ($mainInfo) {
        if ($mainInfo.Mode -eq 'APIPA') {
            Out-Line '   Nota: la IP es APIPA (169.254.x.x): el equipo NO recibió IP del DHCP. Revisa cable/WiFi/router o usa Opción 3.' 'Yellow'
        } elseif ($mainInfo.Mode -eq 'Estatica' -and -not $mainInfo.Virtual -and $failed.Count -gt 0) {
            Out-Line '   Nota: la IP es ESTÁTICA: verifica que IP, máscara, gateway y DNS manuales correspondan a esta red (o cambia a DHCP).' 'Yellow'
        }
    }

    Out-Line ''
    Out-Line ('=' * 60)
    Out-Line 'Diagnóstico completado'
    Out-Line ('=' * 60)

    Save-Report 'diagnostico_red'
}

# ========================= REPARACIONES DE RED =========================
function Invoke-QuickNetRepair {
    Out-Header 'REPARACIÓN RÁPIDA DE RED (IP / DNS)'
    if (-not (Test-IsAdmin)) {
        Write-Host '[!] Aviso: No estás como Administrador. /release y /renew pueden requerir elevación.' -ForegroundColor Yellow
    }
    $estaticas = @(Get-AdapterIpInfo | Where-Object { $_.Mode -eq 'Estatica' -and -not $_.Virtual })
    if ($estaticas.Count -gt 0) {
        Write-Host ('[i] IP ESTÁTICA en: {0}. Liberar/renovar no les afecta; solo se limpiará la caché DNS.' -f (($estaticas | ForEach-Object { $_.Alias }) -join ', ')) -ForegroundColor Cyan
    }
    Write-Host '[1/3] Liberando dirección IP actual...' -ForegroundColor Yellow
    ipconfig /release | Out-Null
    Write-Host '[2/3] Vaciando caché de DNS...' -ForegroundColor Yellow
    ipconfig /flushdns
    Write-Host '[3/3] Solicitando nueva dirección IP al router...' -ForegroundColor Yellow
    ipconfig /renew | Out-Null
    Start-Sleep -Seconds 4
    Write-Host ''
    Write-Host '[OK] Proceso terminado. Verificando salida a internet...' -ForegroundColor Green
    Test-Ping '8.8.8.8' 'Google DNS' | Out-Null
}

function Invoke-DeepNetRepair {
    Out-Header 'REPARACIÓN PROFUNDA (WINSOCK / TCP-IP)'
    if (-not (Test-IsAdmin)) {
        Write-Host '[ERROR] Esta opción requiere ejecutar PowerShell como ADMINISTRADOR.' -ForegroundColor Red
        $null = Request-Admin 'Se necesita elevación para resetear Winsock y TCP/IP.'
        return
    }
    Write-Host '[1/2] Restableciendo catálogo Winsock...' -ForegroundColor Yellow
    netsh winsock reset
    Write-Host '[2/2] Restableciendo pila TCP/IP...' -ForegroundColor Yellow
    netsh int ip reset
    Write-Host ''
    Write-Host '[!] ES NECESARIO REINICIAR LA PC PARA APLICAR LOS CAMBIOS.' -ForegroundColor Red
    $resp = Read-Host '¿Deseas reiniciar el equipo ahora? (S/N)'
    if ($resp -match '^[sS]$') {
        Restart-Computer -Force
    } else {
        Write-Host '[i] Reinicio pospuesto. Volviendo al menú principal...' -ForegroundColor Cyan
    }
}

# ========================= CONTRASEÑAS WI-FI =========================
function Invoke-WifiPasswords {
    Out-Header 'CONTRASEÑAS WI-FI GUARDADAS'
    if (-not (Test-IsAdmin)) {
        $null = Request-Admin 'Sin privilegios de Administrador podrías no ver las contraseñas en texto plano.'
    }
    Write-Host 'Buscando perfiles de red (puede tardar unos segundos)...' -ForegroundColor Cyan
    Write-Host ''
    
    $redes = netsh wlan show profiles | Select-String -Pattern "Perfil de todos los usuarios|All User Profile" | ForEach-Object { ($_.Line -split ':', 2)[1].Trim() }
    
    if (-not $redes) {
        Write-Host 'No se encontraron perfiles Wi-Fi guardados en este equipo.' -ForegroundColor Yellow
        return
    }

    foreach ($red in $redes) {
        $clave = netsh wlan show profile name="$red" key=clear | Select-String -Pattern "Contenido de la clave|Key Content"
        if ($clave) {
            $password = ($clave.Line -split ':', 2)[1].Trim()
            Write-Host "Red: $red  =>  Contraseña: $password" -ForegroundColor Cyan
        } else {
            Write-Host "Red: $red  =>  Contraseña: [Sin contraseña, red abierta o empresarial]" -ForegroundColor Yellow
        }
    }
}

# ========================= MENÚ PRINCIPAL =========================
function Show-Menu {
    $adminTag = if (Test-IsAdmin) { '[ADMIN]' } else { '[USUARIO NORMAL]' }
    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor Magenta
    Write-Host (Get-Center "IT TOOLKIT v2.5 $adminTag" 60) -ForegroundColor Magenta
    Write-Host ('=' * 60) -ForegroundColor Magenta
    Write-Host ''
    Write-Host '  1) Informe del sistema (Hardware / OS -> .txt)'
    Write-Host '  2) Diagnóstico de red completo (Wi-Fi / DNS / Puertos -> .txt)'
    Write-Host '  3) Reparación rápida de red (Renovar IP + Limpiar DNS)'
    Write-Host '  4) Reparación profunda de red (Reset Winsock/TCP-IP - Requiere Admin)'
    Write-Host '  5) Ver contraseñas Wi-Fi guardadas (Requiere Admin)'
    Write-Host '  6) Ejecutar Informe + Diagnóstico (1 y 2)'
    Write-Host '  0) Salir'
    Write-Host ''
    return (Read-Host 'Elige una opción').Trim()
}

# Ejecución directa si se pasan parámetros por consola (-Sistema, -Red, -Todo)
if ($Todo)         { Invoke-SystemReport; Invoke-NetworkDiagnostic; exit }
elseif ($Sistema)  { Invoke-SystemReport; exit }
elseif ($Red)      { Invoke-NetworkDiagnostic; exit }

# Bucle interactivo: siempre regresa al menú tras terminar cualquier opción (hasta elegir 0)
while ($true) {
    $choice = Show-Menu
    switch ($choice) {
        '1' { Invoke-SystemReport }
        '2' { Invoke-NetworkDiagnostic }
        '3' { Invoke-QuickNetRepair }
        '4' { Invoke-DeepNetRepair }
        '5' { Invoke-WifiPasswords }
        '6' { Invoke-SystemReport; Invoke-NetworkDiagnostic }
        '0' { exit }
        default { Write-Host 'Opción no válida.' -ForegroundColor Red }
    }
    Write-Host ''
    Read-Host 'Presiona Enter para volver al menú principal'
}
