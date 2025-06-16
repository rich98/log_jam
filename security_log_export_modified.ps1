<#
.SYNOPSIS
    Exports all entries from the Security event log to a CSV file.
.DESCRIPTION
    Uses Get-WinEvent for performance. Filters and formats events for compliance use.
.NOTES
    Run as Administrator to access the Security log.
#>

# ------------- Configuration -------------
$LogName      = "Security"
$Hostname = $env:COMPUTERNAME
$OutputPath   = "C:\Logs\SecurityLogExport.csv"
$MaxEvents    = 1000000  # Adjust as needed for size control

# -------- Privilege Check --------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator to access the Security log."
    exit 1
}

# -------- Create Log Folder --------
$logDir = Split-Path $OutputPath
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# -------- Extract Security Log --------
Write-Host "Exporting security events to CSV. Please wait..." -ForegroundColor Cyan

try {
    Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction Stop |
        Select-Object -Property @{Name='Hostname';Expression={$Hostname}},  TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "Export complete: $OutputPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to export log: $_"
}
