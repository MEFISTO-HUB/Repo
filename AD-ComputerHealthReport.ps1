<#
.SYNOPSIS
    Generates an HTML report for Active Directory computers with online state, uptime, pending reboot state, and core inventory data.

.DESCRIPTION
    The script queries computer objects from AD (whole domain or a specific OU), checks host availability,
    collects runtime information from reachable hosts, and exports a self-contained HTML report with sorting,
    searching, and status highlighting.

.NOTES
    Compatible target: Windows PowerShell 5.1
    Requires: ActiveDirectory module (RSAT / AD DS tools)

.EXAMPLE
    .\AD-ComputerHealthReport.ps1 -OutputPath "C:\Reports\AD-ComputerReport.html" -VerboseLogging -OpenReport

.EXAMPLE
    .\AD-ComputerHealthReport.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=com" -OutputPath "C:\Reports\Workstations.html" -PingTimeout 1500 -IncludeOffline
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath ("AD-ComputerReport_{0:yyyyMMdd_HHmmss}.html" -f (Get-Date))),

    [Parameter(Mandatory = $false)]
    [ValidateRange(200, 10000)]
    [int]$PingTimeout = 1000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(3, 120)]
    [int]$RemoteQueryTimeoutSec = 15,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeOffline,

    [Parameter(Mandatory = $false)]
    [switch]$VerboseLogging,

    [Parameter(Mandatory = $false)]
    [switch]$OpenReport
)

if ($VerboseLogging) {
    $VerbosePreference = 'Continue'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ADComputerList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SearchBase
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $adParams = @{
            Filter      = '*'
            Properties  = @('DNSHostName', 'OperatingSystem', 'LastLogonDate')
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $adParams['SearchBase'] = $SearchBase
            Write-Verbose "Query AD computers in OU: $SearchBase"
        }
        else {
            Write-Verbose 'Query AD computers in entire domain.'
        }

        $computers = @(Get-ADComputer @adParams | Sort-Object -Property Name)
        Write-Verbose ("Retrieved computers from AD: {0}" -f $computers.Count)
        return $computers
    }
    catch {
        throw "Failed to query Active Directory computers. $_"
    }
}

function Test-ComputerOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMs
    )

    try {
        # Use .NET Ping directly so timeout is always enforced.
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ComputerName, $TimeoutMs)
        return ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    }
    catch {
        Write-Verbose "Ping check failed for ${ComputerName}: $($_.Exception.Message)"
        return $false
    }
}

function Get-ComputerUptimeHours {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [ValidateRange(3, 120)]
        [int]$OperationTimeoutSec = 15
    )

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop
        $lastBoot = $null
        if ($os.LastBootUpTime -is [datetime]) {
            $lastBoot = $os.LastBootUpTime
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$os.LastBootUpTime)) {
            $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime([string]$os.LastBootUpTime)
        }

        if (-not $lastBoot) {
            throw 'LastBootUpTime is empty or has unsupported format.'
        }

        $uptime = (Get-Date) - $lastBoot
        $uptimeHours = [math]::Floor($uptime.TotalHours)

        return [pscustomobject]@{
            UptimeHours     = [int]$uptimeHours
            LastBootUpTime  = $lastBoot
        }
    }
    catch {
        Write-Verbose "Failed to get uptime for ${ComputerName}: $($_.Exception.Message)"
        return [pscustomobject]@{
            UptimeHours     = $null
            LastBootUpTime  = $null
        }
    }
}

function Get-PendingRebootStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName
    )

    $result = [pscustomobject]@{
        RebootRequired = 'Unknown'
        Reason         = @()
    }

    $isPending = $false
    $regReadSucceeded = $false

    try {
        $regHive = [Microsoft.Win32.RegistryHive]::LocalMachine
        $remoteBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($regHive, $ComputerName)

        $cbsKey = $remoteBase.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        if ($cbsKey) {
            $isPending = $true
            $result.Reason += 'CBS:RebootPending'
            $cbsKey.Close()
        }

        $wuKey = $remoteBase.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        if ($wuKey) {
            $isPending = $true
            $result.Reason += 'WUAU:RebootRequired'
            $wuKey.Close()
        }

        $sessionMgrKey = $remoteBase.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager')
        $pendingFileRename = if ($sessionMgrKey) { $sessionMgrKey.GetValue('PendingFileRenameOperations', $null) } else { $null }
        if ($null -ne $pendingFileRename) {
            $isPending = $true
            $result.Reason += 'SessionManager:PendingFileRenameOperations'
        }

        if ($sessionMgrKey) { $sessionMgrKey.Close() }
        $remoteBase.Close()
        $regReadSucceeded = $true
    }
    catch {
        Write-Verbose "Remote Registry check failed for ${ComputerName}: $($_.Exception.Message). Trying CIM StdRegProv fallback."
    }

    if (-not $regReadSucceeded) {
        try {
            $hklm = [uint32]2147483650
            $stdReg = Get-CimInstance -ClassName StdRegProv -Namespace root/default -ComputerName $ComputerName -ErrorAction Stop

            $pathsToCheck = @(
                @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; Reason = 'CBS:RebootPending' },
                @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; Reason = 'WUAU:RebootRequired' }
            )

            foreach ($pathInfo in $pathsToCheck) {
                $enumResult = Invoke-CimMethod -InputObject $stdReg -MethodName EnumKey -Arguments @{ hDefKey = $hklm; sSubKeyName = $pathInfo.Path } -ErrorAction Stop
                if ($enumResult.ReturnValue -eq 0) {
                    $isPending = $true
                    $result.Reason += $pathInfo.Reason
                }
            }

            $pfroResult = Invoke-CimMethod -InputObject $stdReg -MethodName GetMultiStringValue -Arguments @{
                hDefKey     = $hklm
                sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager'
                sValueName  = 'PendingFileRenameOperations'
            } -ErrorAction Stop

            if ($pfroResult.ReturnValue -eq 0 -and $null -ne $pfroResult.sValue) {
                $isPending = $true
                $result.Reason += 'SessionManager:PendingFileRenameOperations'
            }

            $regReadSucceeded = $true
        }
        catch {
            Write-Verbose "CIM StdRegProv fallback failed for ${ComputerName}: $($_.Exception.Message)"
        }
    }

    if ($regReadSucceeded) {
        $result.RebootRequired = if ($isPending) { 'Yes' } else { 'No' }
    }

    return $result
}

function New-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$SearchBase
    )

    $generatedAt = Get-Date
    $total = $Data.Count
    $onlineCount = @($Data | Where-Object { $_.Status -eq 'Online' }).Count
    $offlineCount = @($Data | Where-Object { $_.Status -eq 'Offline' }).Count
    $rebootCount = @($Data | Where-Object { $_.RebootRequired -eq 'Yes' }).Count

    $safeScope = if ([string]::IsNullOrWhiteSpace($SearchBase)) { 'Весь домен' } else { $SearchBase }

    $statusMap = @{
        Online  = 'В сети'
        Offline = 'Не в сети'
    }

    $rebootMap = @{
        Yes     = 'Да'
        No      = 'Нет'
        Unknown = 'Неизвестно'
    }

    $rows = foreach ($item in $Data) {
        $statusClass = if ($item.Status -eq 'Online') { 'status-online' } else { 'status-offline' }
        $rebootClass = switch ($item.RebootRequired) {
            'Yes' { 'reboot-yes' }
            'No' { 'reboot-no' }
            default { 'reboot-unknown' }
        }

        @"
<tr>
    <td>$($item.ComputerName)</td>
    <td>$($item.FQDN)</td>
    <td class="$statusClass">$($statusMap[$item.Status])</td>
    <td class="$rebootClass">$($rebootMap[$item.RebootRequired])</td>
    <td data-value="$($item.UptimeHoursSort)">$($item.UptimeHoursDisplay)</td>
    <td>$($item.LastBootUpTime)</td>
    <td>$($item.OperatingSystem)</td>
    <td>$($item.LastLogonDate)</td>
    <td>$($item.IPAddress)</td>
</tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Отчёт по состоянию компьютеров AD</title>
<style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f7fb; color: #1d2630; }
    h1 { margin-bottom: 6px; }
    .meta { margin-bottom: 15px; color: #475467; }
    .cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 12px 0 18px; }
    .card { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(16,24,40,.1); padding: 10px 14px; min-width: 170px; }
    .card .label { font-size: 12px; color: #667085; }
    .card .value { font-size: 20px; font-weight: 700; }
    .toolbar { margin: 12px 0; }
    .toolbar input { width: 320px; max-width: 100%; padding: 8px 10px; border-radius: 8px; border: 1px solid #cbd5e1; }
    table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; }
    th, td { border-bottom: 1px solid #eaecf0; padding: 10px; text-align: left; font-size: 13px; }
    th { background: #eff3f8; cursor: pointer; user-select: none; }
    tr:hover { background: #f9fafb; }
    .status-online { color: #067647; font-weight: 700; }
    .status-offline { color: #b42318; font-weight: 700; }
    .reboot-yes { background: #fef0c7; color: #93370d; font-weight: 700; }
    .reboot-no { color: #027a48; font-weight: 700; }
    .reboot-unknown { color: #6941c6; font-weight: 700; }
    .hint { font-size: 12px; color: #667085; margin-top: 8px; }
</style>
</head>
<body>
    <h1>Отчёт по состоянию компьютеров Active Directory</h1>
    <div class="meta">Сформирован: $($generatedAt.ToString('yyyy-MM-dd HH:mm:ss')) | Область: $safeScope</div>

    <div class="cards">
        <div class="card"><div class="label">Всего компьютеров</div><div class="value">$total</div></div>
        <div class="card"><div class="label">В сети</div><div class="value">$onlineCount</div></div>
        <div class="card"><div class="label">Не в сети</div><div class="value">$offlineCount</div></div>
        <div class="card"><div class="label">Требуется перезагрузка</div><div class="value">$rebootCount</div></div>
    </div>

    <div class="toolbar">
        <input type="text" id="searchInput" placeholder="Поиск по отчёту..." onkeyup="filterTable()" />
    </div>

    <table id="reportTable">
        <thead>
            <tr>
                <th onclick="sortTable(0)">Имя компьютера</th>
                <th onclick="sortTable(1)">FQDN</th>
                <th onclick="sortTable(2)">Статус</th>
                <th onclick="sortTable(3)">Перезагрузка</th>
                <th onclick="sortTable(4)">Время работы (ч)</th>
                <th onclick="sortTable(5)">Последняя загрузка</th>
                <th onclick="sortTable(6)">OS</th>
                <th onclick="sortTable(7)">Последний вход</th>
                <th onclick="sortTable(8)">IP-адрес</th>
            </tr>
        </thead>
        <tbody>
            $($rows -join [Environment]::NewLine)
        </tbody>
    </table>

    <div class="hint">Подсказка: нажмите на заголовок столбца для сортировки. Время работы сортируется численно.</div>

<script>
let sortDirections = {};

function getCellValue(row, idx) {
    const cell = row.cells[idx];
    if (idx === 4) {
        const numeric = cell.getAttribute('data-value');
        return numeric === '' || numeric === null ? Number.NEGATIVE_INFINITY : Number(numeric);
    }
    return (cell.textContent || cell.innerText).trim().toLowerCase();
}

function sortTable(colIndex) {
    const table = document.getElementById('reportTable');
    const tbody = table.tBodies[0];
    const rows = Array.from(tbody.rows);

    sortDirections[colIndex] = !sortDirections[colIndex];
    const asc = sortDirections[colIndex];

    rows.sort((a, b) => {
        const valA = getCellValue(a, colIndex);
        const valB = getCellValue(b, colIndex);

        if (typeof valA === 'number' && typeof valB === 'number') {
            return asc ? valA - valB : valB - valA;
        }
        return asc ? String(valA).localeCompare(String(valB)) : String(valB).localeCompare(String(valA));
    });

    rows.forEach(r => tbody.appendChild(r));
}

function filterTable() {
    const query = document.getElementById('searchInput').value.toLowerCase();
    const table = document.getElementById('reportTable');
    const rows = table.tBodies[0].rows;

    for (let i = 0; i < rows.length; i++) {
        const rowText = rows[i].textContent.toLowerCase();
        rows[i].style.display = rowText.indexOf(query) > -1 ? '' : 'none';
    }
}
</script>
</body>
</html>
"@

    try {
        $targetDir = Split-Path -Path $OutputPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($targetDir) -and -not (Test-Path -Path $targetDir)) {
            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
        }

        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Verbose "Report saved to: $OutputPath"
    }
    catch {
        throw "Failed to write HTML report to '$OutputPath'. $_"
    }
}

# Main workflow
try {
    $adComputers = Get-ADComputerList -SearchBase $SearchBase
    Write-Host ("Найдено компьютеров в выбранной области: {0}" -f $adComputers.Count) -ForegroundColor Cyan

    $reportItems = New-Object 'System.Collections.Generic.List[object]'
    $processed = 0
    $total = [Math]::Max(1, $adComputers.Count)

    foreach ($computer in $adComputers) {
        $processed++
        $computerName = $computer.Name
        $fqdn = if ([string]::IsNullOrWhiteSpace($computer.DNSHostName)) { $computerName } else { $computer.DNSHostName }

        Write-Progress -Activity 'Collecting AD computer health data' -Status ("{0}/{1}: {2}" -f $processed, $total, $computerName) -PercentComplete (($processed / $total) * 100)

        Write-Verbose "Processing computer: $computerName"

        $isOnline = Test-ComputerOnline -ComputerName $fqdn -TimeoutMs $PingTimeout
        $status = if ($isOnline) { 'Online' } else { 'Offline' }

        if (-not $isOnline -and -not $IncludeOffline) {
            Write-Verbose "Skipping offline host due to IncludeOffline switch not set: $computerName"
            continue
        }

        $uptimeInfo = [pscustomobject]@{ UptimeHours = $null; LastBootUpTime = $null }
        $rebootInfo = [pscustomobject]@{ RebootRequired = 'Unknown'; Reason = @() }
        $ipAddress = 'Не в сети'

        if ($isOnline) {
            try {
                $uptimeInfo = Get-ComputerUptimeHours -ComputerName $fqdn -OperationTimeoutSec $RemoteQueryTimeoutSec
            }
            catch {
                Write-Verbose "Uptime retrieval failed for ${computerName}: $($_.Exception.Message)"
            }

            try {
                # Use FQDN for remote reboot checks because many environments do not resolve
                # short hostnames consistently for Remote Registry/CIM providers.
                $rebootInfo = Get-PendingRebootStatus -ComputerName $fqdn
            }
            catch {
                Write-Verbose "Pending reboot check failed for ${computerName}: $($_.Exception.Message)"
            }

            try {
                $ipRecord = [System.Net.Dns]::GetHostAddresses($fqdn) |
                    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                    Select-Object -First 1
                if ($ipRecord) { $ipAddress = $ipRecord.IPAddressToString } else { $ipAddress = 'Неизвестно' }
            }
            catch {
                Write-Verbose "IP resolve failed for ${computerName}: $($_.Exception.Message)"
                $ipAddress = 'Неизвестно'
            }
        }

        $reportItems.Add([pscustomobject]@{
            ComputerName      = $computerName
            FQDN              = $fqdn
            Status            = $status
            RebootRequired    = $rebootInfo.RebootRequired
            UptimeHoursDisplay = if ($null -ne $uptimeInfo.UptimeHours) { "{0} ч" -f $uptimeInfo.UptimeHours } elseif ($isOnline) { 'Неизвестно' } else { 'Не в сети' }
            UptimeHoursSort   = if ($null -ne $uptimeInfo.UptimeHours) { [int]$uptimeInfo.UptimeHours } else { '' }
            LastBootUpTime    = if ($uptimeInfo.LastBootUpTime) { $uptimeInfo.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss') } elseif ($isOnline) { 'Неизвестно' } else { 'Не в сети' }
            OperatingSystem   = if ($computer.OperatingSystem) { $computer.OperatingSystem } else { 'Неизвестно' }
            LastLogonDate     = if ($computer.LastLogonDate) { $computer.LastLogonDate.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Неизвестно' }
            IPAddress         = $ipAddress
        }) | Out-Null
    }

    Write-Progress -Activity 'Collecting AD computer health data' -Completed

    New-HtmlReport -Data $reportItems -OutputPath $OutputPath -SearchBase $SearchBase

    Write-Host "Отчёт успешно сформирован: $OutputPath" -ForegroundColor Green

    if ($OpenReport) {
        try {
            Start-Process -FilePath $OutputPath -ErrorAction Stop
        }
        catch {
            Write-Warning "Не удалось автоматически открыть отчёт: $($_.Exception.Message)"
        }
    }

    Write-Host "Необходимые права и зависимости:" -ForegroundColor Cyan
    Write-Host " - Доступ на чтение объектов компьютеров в AD (обычно достаточно прав доменного пользователя)." -ForegroundColor Cyan
    Write-Host " - Удалённый доступ WMI/CIM для сбора времени работы (WinRM/DCOM и правила брандмауэра)." -ForegroundColor Cyan
    Write-Host " - Удалённый доступ к реестру для проверки перезагрузки (служба Remote Registry и ACL)." -ForegroundColor Cyan
    Write-Host " - Установленный модуль: ActiveDirectory (RSAT / AD DS tools)." -ForegroundColor Cyan
}
catch {
    Write-Error "Ошибка выполнения скрипта: $($_.Exception.Message)"
    exit 1
}
