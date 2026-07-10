# 🐍 SnakeMove

> **PowerShell lateral movement enumeration module for Windows.**  
> Checks five attack vectors, maps findings to MITRE ATT&CK T1021,  
> and delivers structured output — ready for the console, CSV, or a styled HTML report.

<br>

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1021-E4002B?style=flat-square)
![PSGallery](https://img.shields.io/powershellgallery/v/SnakeMove?style=flat-square&label=PSGallery&color=0078D6)
![License](https://img.shields.io/badge/License-MIT-3fb950?style=flat-square)

<br>

---

## Table of Contents

- [Overview](#overview)
- [Checks Performed](#checks-performed)
- [Installation](#installation)
- [Usage](#usage)
- [Parameters](#parameters)
- [Output](#output)
- [Export Formats](#export-formats)
- [Requirements](#requirements)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## Overview

SnakeMove is a single-function PowerShell module designed for penetration testers and security engineers who need a fast, structured picture of lateral movement exposure on a Windows host.

Every check queries **real system state** — registry keys, service statuses, and active port bindings. There are no hardcoded assumptions, no simulated results. What SnakeMove reports is what the system is actually exposing at the moment of the scan.

Results are returned as structured objects, making them trivially composable with the rest of the PowerShell pipeline or any downstream reporting workflow.

---

## Checks Performed

| # | Technique | MITRE ID | What Is Checked |
|---|-----------|----------|-----------------|
| 1 | Remote Desktop Protocol | T1021.001 | `fDenyTSConnections` registry key + port 3389 listener |
| 2 | SMB Signing / NTLM Relay Risk | T1021.002 | `RequireSecuritySignature` via `Get-SmbServerConfiguration` |
| 3 | WinRM / PowerShell Remoting | T1021.006 | WinRM service state + ports 5985 / 5986 listeners |
| 4 | WMI / DCOM Remote Execution | T1021.003 | Winmgmt service state + DCOM port 135 listener |
| 5 | Default Admin Shares | T1021.002 | Presence of `C$`, `ADMIN$`, `IPC$` via `Get-SmbShare` |

Each check independently returns one of four statuses:

| Status | Meaning |
|--------|---------|
| `OPEN` | Technique is viable with valid credentials |
| `PARTIAL` | Partially configured — conditionally accessible |
| `CLOSED` | Mitigated — technique is not viable |
| `ERROR` | Check failed, likely due to insufficient privileges |

---

## Installation

**From PowerShell Gallery (recommended)**

```powershell
Install-Module -Name SnakeMove -Scope CurrentUser
```

**From source**

```powershell
git clone https://github.com/Shcherbaa/SnakeMove.git
$dest = "$HOME\Documents\PowerShell\Modules\SnakeMove"
New-Item -ItemType Directory -Path $dest -Force
Copy-Item .\SnakeMove\SnakeMove.psm1, .\SnakeMove\SnakeMove.psd1 -Destination $dest
Import-Module SnakeMove
```

---

## Usage

```powershell
# Run all checks — display results in the console
Get-SnakeMove

# Export a styled HTML report
Get-SnakeMove -ExportHTML "C:\Reports\snakemove.html"

# Export raw results to CSV
Get-SnakeMove -ExportCSV "C:\Reports\snakemove.csv"

# Both exports at once
Get-SnakeMove -ExportHTML "C:\Reports\snakemove.html" -ExportCSV "C:\Reports\snakemove.csv"

# Silent mode — no console output, results stored in variable
$data = Get-SnakeMove -Quiet

# Filter for active attack paths only
$data | Where-Object { $_.Status -eq "OPEN" }

# Filter for anything worth investigating
$data | Where-Object { $_.Status -eq "OPEN" -or $_.Status -eq "PARTIAL" }

# Select specific fields for a clean summary
Get-SnakeMove -Quiet | Select-Object Technique, Status, Risk | Format-Table -AutoSize
```

---

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ExportCSV` | `[string]` | No | Full path to a `.csv` output file. Parent directory must exist. Optimized for SIEM ingestion or automated parsing. |
| `-ExportHTML` | `[string]` | No | Full path to a `.html` output file. Parent directory must exist. Generates an embedded, dark-themed report with executive summary and findings table. |
| `-Quiet` | `[switch]` | No | Suppresses all console output including the banner, live results, and summary. Recommended for scripted or OpSec-sensitive use. |

---

## Output

`Get-SnakeMove` returns `[PSCustomObject[]]` — one object per check. Each object carries the following fields:

| Field | Type | Example |
|-------|------|---------|
| `Technique` | `string` | `Remote Desktop Protocol (RDP)` |
| `MITRE_ID` | `string` | `T1021.001` |
| `Status` | `string` | `OPEN` |
| `Risk` | `string` | `High` |
| `Detail` | `string` | `RDP is enabled and port 3389 is listening.` |
| `ComputerName` | `string` | `DESKTOP-ABC123` |
| `ScanUser` | `string` | `DOMAIN\username` |
| `ScanTime` | `string` | `2025-06-01 14:32:11` |

Because results are standard PowerShell objects, they integrate naturally with `Where-Object`, `Select-Object`, `Export-Csv`, `ConvertTo-Json`, and any other cmdlet in the pipeline.

```powershell
# Convert to JSON for API or log forwarding
Get-SnakeMove -Quiet | ConvertTo-Json

# Send only OPEN findings to a JSON file
Get-SnakeMove -Quiet |
    Where-Object { $_.Status -eq "OPEN" } |
    ConvertTo-Json |
    Out-File "open_findings.json"
```

---

## Export Formats

### CSV

Flat structured output. Every finding becomes one row with all eight fields as columns. Suitable for import into Excel, Splunk, ELK, Wazuh, or any SIEM that accepts CSV.

```powershell
Get-SnakeMove -ExportCSV "C:\Reports\snakemove.csv"
```

### HTML

Standalone dark-themed report. No external dependencies — CSS is fully embedded. Opens in any browser without an internet connection. Includes:

- Scan metadata header (target, user, timestamp)
- Executive summary cards (count of OPEN / PARTIAL / CLOSED / ERROR)
- Color-coded findings table (red for OPEN, yellow for PARTIAL, green for CLOSED)

```powershell
Get-SnakeMove -ExportHTML "C:\Reports\snakemove.html"
```

---

## Requirements

- **OS:** Windows (any version with PowerShell 5.1+)
- **PowerShell:** 5.1 or higher
- **Privileges:** Standard user for most checks. Administrator recommended — some checks (`Get-SmbServerConfiguration`, `Get-NetTCPConnection`) may return incomplete data without elevation.

---

## Disclaimer

SnakeMove is developed for **authorized penetration testing, security auditing, and educational purposes only**.

Running this tool against systems you do not own or do not have explicit written permission to test is illegal and unethical. The author assumes no liability for any misuse or damage caused by this software.

---

## Author

**Ihar Shcharbitski**

[![GitHub](https://img.shields.io/badge/GitHub-Shcherbaa-181717?style=flat-square&logo=github)](https://github.com/Shcherbaa)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ihar%20Shcharbitski-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/ihar-shcharbitski-4184813a6)
