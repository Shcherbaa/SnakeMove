#Requires -Version 5.1

# =============================================================================
# PRIVATE FUNCTIONS — internal workers, not exported
# =============================================================================

function Test-RdpStatus {

    $results = [PSCustomObject]@{

        Technique = "Remote Desktop Protocol (RDP)"
        MITRE_ID = "T1021.001"
        Status = "UNKNOWN"
        Risk = "High"
        Detail = ""

    }

    try {

        $regkey = Get-ItemProperty `
        -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" `
        -ErrorAction Stop

        $rdpEnabled = ($regkey.fDenyTSConnections -eq 0)
        $portListening = Get-NetTCPConnection -LocalPort 3389 -State listen `
        -ErrorAction SilentlyContinue

        if ($rdpEnabled -and $portListening) {

            $results.Status = "OPEN"
            $results.Detail = "RDP is enabled in registry (fDenyTSConnections=0) and port 3389 is listening. " +
                             "Remote login is possible with valid credentials."


        }

        elseif ($rdpEnabled -and -not $portListening) {

            $results.Status = "PARTIAL"
            $results.Risk = "Medium"
            $results.Detail = "RDP is enabled in registry but port 3389 is not listening. " +
                             "A firewall rule is likely blocking it."

        }

        else {

            $results.Status = "CLOSED"
            $results.Risk = "Low"
            $results.Detail = "RDP is disabled in Registry (fDenyTSConnections=1)"

        }

    }

    catch {

        $results.Status = "ERROR"
        $results.Detail = "Failed to read registry: $($_.Exception.Message)"

    }

    return $results

}

function Test-SMBSigningStatus {
    # Checks RequireSecuritySignature via Get-SmbServerConfiguration
    # If not required, NTLM relay attacks are feasible
    # MITRE T1021.002

    $results = [PSCustomObject]@{

    Technique = "SMB Signing / NTLM Relay Risk"
    MITRE_ID = "T1021.002"
    Status = "UNKNOWN"
    Risk = "High"
    Detail = ""

    }

    try {
        $smbConfig = Get-SMBServerConfiguration `
        -ErrorAction Stop

        if ($smbConfig.RequireSecuritySignature) {

            $results.Status = "CLOSED"
            $results.Risk = "Low"
            $results.Detail = "SMB signing is enabled and required. NTLM relay is mitigated"

        }

        elseif ($smbConfig.EnableSecuritySignature) {

            $results.Status = "PARTIAL"
            $results.Risk = "Medium"
            $results.Detail = "SMB signing is enabled, but not required. " `
                            + "Relay may succeed if the client does not negotiate signing"
        }

        else {

            $results.Status = "OPEN"
            $results.Detail = "SMB signing is not enabled and not required. " `
                            + "NTLM relay attack is feasible via Responder + ntlmrelayx"

        }

    }

    catch {

        $results.Status = "ERROR"
        $results.Detail = "Failed to retrieve SMB configuration: $($_.Exception.Message)"

    }

    return $results
}

function Test-WinRMStatus {
    # Checks WinRM service state and whether ports 5985 / 5986 are listening
    # MITRE T1021.006

    $results = [PSCustomObject]@{

        Technique = "WinRM / PowerShell Remoting"
        MITRE_ID = "T1021.006"
        Status = "UNKNOWN"
        Risk = "High"
        Detail = ""

    }

    try {

        $service = Get-Service -Name "WinRM" `
        -ErrorAction Stop
        $port5985 = Get-NetTCPConnection -LocalPort 5985 -State Listen `
        -ErrorAction SilentlyContinue
        $port5986 = Get-NetTCPConnection -LocalPort 5986 -State Listen `
        -ErrorAction SilentlyContinue

        if ($service.Status -eq "Running" -and ($port5985 -or $port5986)) {

            $openPorts = @()
            if ($port5985) {$openPorts += "5985 (HTTP)"}
            if ($port5986) {$openPorts += "5986 (HTTPS)"}

            $results.Status = "OPEN"
            $results.Detail = "WinRM is running. Listening on: $($openPorts -join ', ' ). " `
                            + "Remote PowerShell sessions are possible with valid credentials."

        }

        elseif ($service.Status -eq "Running") {

            $results.Status = "PARTIAL"
            $results.Risk = "Medium"
            $results.Detail = "WinRM is running, but ports 5985/5986 are not listening. " `
                            + "Firewall is likely blocking remote access."
        }
        else {

            $results.Status = "CLOSED"
            $results.Risk = "Low"
            $results.Detail = "WinRM service is Stopped. PowerShell remoting is unavailable."

        }

    }

    catch {

        $results.Status = "ERROR"
        $results.Detail = "Failed to check WinRM: $($_.Exception.Message)"

    }

    return $results

}

function Test-WMIStatus {
    # Checks Winmgmt service state and whether DCOM port 135 is listening
    # MITRE T1021.003

    $results = [PSCustomObject]@{

        Technique = "WMI / DCOM Remote Execution"
        MITRE_ID = "T1021.003"
        Status = "UNKNOWN"
        Risk = "High"
        Detail = ""

    }

    try {

        $service = Get-Service -Name "Winmgmt" `
        -ErrorAction Stop
        $dcomPort = Get-NetTCPConnection -LocalPort 135 -State Listen `
        -ErrorAction SilentlyContinue

        if ($service.Status -eq "Running" -and $dcomPort) {

            $results.Status = "OPEN"
            $results.Detail = "WMI service is running and DCOM port 135 is listening. " `
                            + "Remote execution via Invoke-WmiMethod or wmiexec is possible with valid credentials."

        }

        elseif ($service.Status -eq "Running") {

            $results.Status = "PARTIAL"
            $results.Risk = "Medium"
            $results.Detail = "WMI service is running but DCOM port 135 is not reachable. " `
                            + "Firewall may be blocking remote WMI."
                    
        }

        else {

            $results.Status = "CLOSED"
            $results.Risk = "Low"
            $results.Detail = "WMI service (Winmgmt) is stopped. Remote WMI execution unavailable."

        }

    }        
    catch {

            $results.Status = "ERROR"
            $results.Detail = "Failed to check WMI: $($_.Exception.Message)"
        }

    return $results

}

function Test-AdminShareStatus {
    # Enumerates whether default admin shares C$, ADMIN$, IPC$ are present
    # MITRE T1021.002

    $results = [PSCustomObject]@{

        Technique = "Default Admin Shares (C$, ADMIN$, IPC$)"
        MITRE_ID = "T1021.002"
        Status = "UNKNOWN"
        Risk = "High"
        Detail = ""

    }

    try {
        $adminShares = Get-SMBShare `
        -ErrorAction Stop | 
                        Where-Object {$_.Name -match "^(C\$|ADMIN\$|IPC\$)$"}

        if ($adminShares) {

            $shareList = ($adminShares.Name) -join ', '
            $results.Status = "OPEN"
            $results.Detail = "Admin shares present: $shareList. " `
                        + "With administrator credentials, full remote filesystem access is possible via net use or PsExec."

        }

        else {

            $results.Status = "CLOSED"
            $results.Risk = "Low"
            $results.Detail = "No default admin shares found. " `
                            + "Likely disabled via registry (AutoShareServer=0)."

        }
    }
    catch {

        $results.Status = "ERROR"
        $results.Detail = "Failed to enumerate SMB shares: $($_.Exception.Message)"

    }

    return $results

}

# =============================================================================
# PUBLIC FUNCTION 
# =============================================================================

function Get-SnakeMove {
<#
.SYNOPSIS
    Enumerates lateral movement opportunities on the current Windows host.

.DESCRIPTION
    Get-SnakeMove runs the following checks against the target host to identify
    which lateral movement techniques are currently viable. Each check reads
    actual registry keys, service states, and port bindings — no hardcoded
    values or simulations.
 
    Checks performed:
        [1] RDP availability               (T1021.001)
        [2] SMB signing / NTLM relay risk  (T1021.002)
        [3] WinRM / PowerShell Remoting    (T1021.006)
        [4] WMI / DCOM remote execution    (T1021.003)
        [5] Default admin shares           (T1021.002)

.PARAMETER ExportCSV
    Optional. Specifies the full target filesystem path where the raw audit results 
    will be saved as a flat CSV file. This format is optimized for SIEM ingestion or automated parsing scripts.

.PARAMETER ExportHTML
    Optional. Specifies the full target filesystem path where a standalone, styled HTML report 
    will be generated. This file includes an embedded CSS layout, an Executive Summary block, 
    and a detailed findings table.

.PARAMETER Quiet
    Suppresses all console output including the banner, live check results,
    and summary. Recommended for scripted or OpSec-sensitive use cases.

.EXAMPLE
    Get-SnakeMove

    Runs all checks and displays results in the console.
 
.EXAMPLE
    Get-SnakeMove -Quiet -ExportCSV "C:\Windows\Diagnostics\system_audit.csv"

    Runs silently and saves results without producing any console output.
 
.EXAMPLE
    $Data = Get-SnakeMove -Quiet | Where-Object { $_.Status -eq "OPEN" -or $_.Status -eq "PARTIAL" }

    Isolates both immediate vulnerabilities and conditionally viable attack paths in memory, 
    streamlining data collection for tactical pivot planning 
    while ignoring fully mitigated systems.

.OUTPUTS
    [PSCustomObject[]]
    Each object contains: Technique, MITRE_ID, Status, Risk, Detail,
    ComputerName, ScanUser, ScanTime.

.NOTES
    Author   : Ihar Shcharbitski
    GitHub   : https://github.com/Shcherbaa/SnakeMove
    Version  : 1.0.0
    Requires : PowerShell 5.1+, Administrator privileges recommended
 
    For authorized penetration testing and educational use only.

.LINK
    https://attack.mitre.org/techniques/T1021/

.LINK
    https://github.com/Shcherbaa/SnakeMove
#>

    [CmdletBinding()]
    param (

        [Parameter (Mandatory = $false)]
        [ValidateScript({

            $parent = Split-Path $_ -Parent
            $parentExist = Test-Path $parent -PathType Container

            # Checking whether a folder exists
            if (-not $parentExist) {

                throw "Directory does not exist: $parent"

            }

            # Checking write permissions individually
            try {

                $testFile = Join-Path $parent ([System.IO.Path]::GetRandomFileName())
                [System.IO.File]::Create($testFile).Close()
                Remove-Item $testFile -ErrorAction Stop

            }

            catch {

                throw "Access denied or cannot write to directory: $parent"

            }

            $true

        })]
        [string]$ExportCSV,

        [Parameter (Mandatory = $false)]
        [ValidateScript ({

            
            $parent = Split-Path $_ -Parent
            $parentExist = Test-Path $parent -PathType Container

            if (-not $parentExist) {

                throw "Directory does not exist: $parent"

            }

            try {

                $testFile = Join-Path $parent ([System.IO.Path]::GetRandomFileName())
                [System.IO.File]::Create($testFile).Close()
                Remove-Item $testFile -ErrorAction Stop

            }

            catch {

                throw "Access denied or cannot write to directory: $parent"

            }

            $true

        })]
        [string]$ExportHTML,
        

        [Parameter (Mandatory = $false)]
        [switch]$Quiet

    )

    $moduleVersion = (Get-Module SnakeMove).Version.ToString()

    if (-not $Quiet) {

        # Banner
        Write-Host ""
        Write-Host "  ============================================================" -ForegroundColor DarkCyan
        Write-Host "   SNAKEMOVE  |  v$moduleVersion  |  MITRE ATT&CK T1021" -ForegroundColor Cyan
        Write-Host "   https://github.com/Shcherbaa/SnakeMove" -ForegroundColor DarkGray
        Write-Host "   For authorized penetration testing use only." -ForegroundColor DarkGray
        Write-Host "  ============================================================" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  Target   : " -NoNewline -ForegroundColor DarkGray
        Write-Host $env:COMPUTERNAME -ForegroundColor Yellow
        Write-Host "  User     : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$env:USERDOMAIN\$env:USERNAME" -ForegroundColor Yellow
        Write-Host "  DateTime : " -NoNewline -ForegroundColor DarkGray
        Write-Host (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Running checks..." -ForegroundColor DarkGray
        Write-Host ("  " + ("─" * 62)) -ForegroundColor DarkGray
        Write-Host ""

    }

    # Elevation check
    $isAdmin = ([Security.Principal.WindowsPrincipal]
                [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

               if (-not $isAdmin -and -not $Quiet) {

                Write-Host "  [!] Not running as Administrator. Some checks may return incomplete results." -ForegroundColor Yellow
                Write-Host ""

               }

    $results = @(

        Test-RdpStatus
        Test-SMBSigningStatus
        Test-WinRMStatus
        Test-WMIStatus
        Test-AdminShareStatus

    )

    # Enrich collected objects with environmental metadata for export context
    foreach ($report in $results) {

        $report | Add-Member -NotePropertyMembers @{

            ComputerName = $env:ComputerName
            ScanUser = "$env:USERDOMAIN\$env:USERNAME"
            ScanTime = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")

        }
    }

    if (-not $Quiet) {
        # Display results
        foreach ($item in $results) {

            switch ($item.Status) {

                "OPEN" { $statusColor = "Red" $statusLabel = "[ OPEN    ]" }
                "PARTIAL" { $statusColor = "Yellow" $statusLabel = "[ PARTIAL ]" }
                "CLOSED" { $statusColor = "Green" $statusLabel = "[ CLOSED  ]" }
                "ERROR" { $statusColor = "Magenta" $statusLabel = "[ ERROR   ]" }
                default { $statusColor = "White" $statusLabel = "[ UNKNOWN ]" }

            }

            $riskColor = switch ($item.Risk) {

                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }

            }

                Write-Host "  Technique : " -NoNewline -ForegroundColor DarkGray
                Write-Host $item.Technique -ForegroundColor White
                Write-Host "  MITRE ID  : " -NoNewline -ForegroundColor DarkGray
                Write-Host $item.MITRE_ID -ForegroundColor DarkCyan
                Write-Host "  Status    : " -NoNewline -ForegroundColor DarkGray
                Write-Host $statusLabel -ForegroundColor $statusColor
                Write-Host "  Risk      : " -NoNewline -ForegroundColor DarkGray
                Write-Host $item.Risk -ForegroundColor $riskColor
                Write-Host "  Detail    : " -NoNewline -ForegroundColor DarkGray
                Write-Host $item.Detail -ForegroundColor Gray
                Write-Host ("  " + ("─" * 62)) -ForegroundColor DarkGray
                Write-Host ""
        
        }

    }
    
    # Summary 
    $openCount = @($results | Where-Object {$_.Status -eq "OPEN"} ).Count
    $partialCount = @($results | Where-Object {$_.Status -eq "PARTIAL"} ).Count
    $closedCount = @($results | Where-Object {$_.Status -eq "CLOSED"} ).Count
    $errorCount = @($results | Where-Object {$_.Status -eq "ERROR"} ).Count

    if (-not $Quiet) {

    Write-Host "  SUMMARY" -ForegroundColor White
    Write-Host ("  " + ("─" * 30)) -ForegroundColor DarkGray
    Write-Host "  OPEN     : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$openCount" -NoNewline -ForegroundColor Red
    Write-Host "  (active attack paths)" -ForegroundColor DarkGray
    Write-Host "  PARTIAL  : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$partialCount" -NoNewline -ForegroundColor Yellow
    Write-Host "  (conditionally accessible)" -ForegroundColor DarkGray
    Write-Host "  CLOSED   : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$closedCount" -NoNewline -ForegroundColor Green
    Write-Host "  (mitigated)" -ForegroundColor DarkGray

    if ($errorCount -gt 0) {

        Write-Host "  ERROR    : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$errorCount" -NoNewline -ForegroundColor Magenta
        Write-Host "  (try running as Administrator)" -ForegroundColor DarkGray

    }
 
    Write-Host ""

    }

    # Optional CSV Export
    if ($ExportCSV) {

        try {

            $results | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8 `
            -ErrorAction Stop

            if (-not $Quiet) {

                Write-Host "  [+] CSV results exported to: $ExportCSV" -ForegroundColor Green

            }

        }

        catch {

            Write-Host "  [!] CSV Export failed: $($_.Exception.Message)" -ForegroundColor Red

        }

        Write-Host ""

    }

    # Optional HTML Export
    if ($ExportHTML) {

        $reportHeader = "SnakeMove — Lateral Movement Audit | $($env:COMPUTERNAME) | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

        $cssStyle = @"
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Consolas, monospace; padding: 2rem; }
    h1 { color: #58a6ff; font-size: 1.4rem; margin-bottom: 0.4rem; letter-spacing: 1px; }
    .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 2rem; }
    .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem 1.5rem; min-width: 110px; }
    .card .label { font-size: 0.7rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
    .card .value { font-size: 2rem; font-weight: bold; margin-top: 0.2rem; }
    .c-open    { color: #f85149; }
    .c-partial { color: #e3b341; }
    .c-closed  { color: #3fb950; }
    .c-error   { color: #bc8cff; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }
    th { background: #21262d; color: #8b949e; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #30363d; }
    td { padding: 0.75rem 1rem; border-bottom: 1px solid #21262d; font-size: 0.85rem; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.72rem; font-weight: bold; letter-spacing: 0.5px; }
    .badge-open    { background: rgba(248,81,73,0.15);   color: #f85149; border: 1px solid rgba(248,81,73,0.4); }
    .badge-partial { background: rgba(227,179,65,0.15);  color: #e3b341; border: 1px solid rgba(227,179,65,0.4); }
    .badge-closed  { background: rgba(63,185,80,0.15);   color: #3fb950; border: 1px solid rgba(63,185,80,0.4); }
    .badge-error   { background: rgba(188,140,255,0.15); color: #bc8cff; border: 1px solid rgba(188,140,255,0.4); }
    .risk-high   { color: #f85149; font-weight: bold; }
    .risk-medium { color: #e3b341; font-weight: bold; }
    .risk-low    { color: #3fb950; }
    .mitre { color: #58a6ff; font-family: Consolas, monospace; font-size: 0.8rem; }
    footer { margin-top: 2rem; color: #484f58; font-size: 0.75rem; text-align: center; }
</style>
"@

        $tableRows = foreach ($r in $results) {

             $statusBadge = switch ($r.Status) {

                "OPEN"    { '<span class="badge badge-open">OPEN</span>' }
                "PARTIAL" { '<span class="badge badge-partial">PARTIAL</span>' }
                "CLOSED"  { '<span class="badge badge-closed">CLOSED</span>' }
                "ERROR"   { '<span class="badge badge-error">ERROR</span>' }
                default   { $r.Status }

            }

            $riskClass = switch ($r.Risk) {

                "High"   { "risk-high" }
                "Medium" { "risk-medium" }
                "Low"    { "risk-low" }
                default  { "" }

            }

            "<tr><td class='mitre'>$($r.MITRE_ID)</td><td>$($r.Technique)</td><td>$statusBadge</td><td class='$riskClass'>$($r.Risk)</td><td>$($r.Detail)</td></tr>"

        }

        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SnakeMove Report</title>
    $cssStyle
</head>
<body>
    <h1>&#128013; SNAKEMOVE — Lateral Movement Audit</h1>
    <p class="meta">
        Target: $($env:COMPUTERNAME) &nbsp;|&nbsp;
        User: $("$env:USERDOMAIN\$env:USERNAME") &nbsp;|&nbsp;
        Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    </p>

    <div class="summary">
        <div class="card"><div class="label">Open</div><div class="value c-open">$openCount</div></div>
        <div class="card"><div class="label">Partial</div><div class="value c-partial">$partialCount</div></div>
        <div class="card"><div class="label">Closed</div><div class="value c-closed">$closedCount</div></div>
        <div class="card"><div class="label">Error</div><div class="value c-error">$errorCount</div></div>
    </div>

    <table>
        <thead>
            <tr>
                <th>MITRE ID</th>
                <th>Technique</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Detail</th>
            </tr>
        </thead>
        <tbody>
            $($tableRows -join "`n            ")
        </tbody>
    </table>

    <footer>Generated by SnakeMove v1.0.0 — For authorized penetration testing and educational use only.</footer>
</body>
</html>
"@

        try {

            $htmlContent | Out-File -FilePath $ExportHTML -Encoding UTF8 -ErrorAction Stop

            if (-not $Quiet) {

                Write-Host "  [+] HTML results exported to: $ExportHTML" -ForegroundColor Green
            }
        }

        catch {

            Write-Host "  [!] HTML Export failed: $($_.Exception.Message)" -ForegroundColor Red
        }

    }

    return $results

}

Export-ModuleMember -Function Get-SnakeMove