# Configuration
$SyslogServer = "192.168.0.172"  # Set to your syslog server IP or hostname
$SyslogPort = 514                # UDP port used by the syslog server
$LogName = "Security"            # Options: Application, System, Security
$facility = 4                    # Syslog facility: 4 = auth (for security logs)
$PollInterval = 5                # Polling interval in seconds

# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator to access Security logs."
    exit
}

# Map Windows Event Levels to syslog severity
function Get-SyslogPriority {
    param([string]$EntryType)
    
    switch ($EntryType) {
        "Critical"      { return 2 }  # Critical
        "Error"         { return 3 }  # Error
        "Warning"       { return 4 }  # Warning
        "Information"   { return 6 }  # Informational
        "Audit Failure" { return 3 }  # Security Audit Failure
        "Audit Success" { return 5 }  # Security Audit Success
        default         { return 5 }  # Notice (default)
    }
}

# Format syslog message
function Format-SyslogMessage {
    param ([pscustomobject]$LogEvent)

    $hostname = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "MMM dd HH:mm:ss"
    $priority = ($facility * 8) + (Get-SyslogPriority -EntryType $LogEvent.EntryType)
    $sanitizedMessage = ($LogEvent.Message -replace '[\r\n]+', ' ') -replace '[^\x20-\x7E]', ''

    $message = "<$priority>$timestamp $hostname ${LogName}: EventID=$($LogEvent.EventID); Source=$($LogEvent.Source); $sanitizedMessage"

    if ($message.Length -gt 1024) {
        $message = $message.Substring(0, 1020) + "..."
    }

    return $message
}

# Send syslog messages via UDP
function Send-SyslogMessage {
    param (
        [string]$Message,
        [System.Net.Sockets.UdpClient]$udpClient
    )

    try {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Message)
        $udpClient.Send($bytes, $bytes.Length, $SyslogServer, $SyslogPort) | Out-Null
    } catch {
        Write-Warning "Error sending syslog message: $_"
    }
}

# Initialize UDP Client (used across polling loop)
$udpClient = New-Object System.Net.Sockets.UdpClient

Write-Host "Monitoring '$LogName' log in real-time. Polling every $PollInterval seconds..." -ForegroundColor Cyan

# Get last seen RecordId
try {
    $lastRecordId = (Get-WinEvent -LogName $LogName -MaxEvents 1 | Select-Object -ExpandProperty RecordId)
} catch {
    Write-Error "Unable to read initial event record. Exiting."
    exit
}

# Real-Time Polling Loop
while ($true) {
    try {
        $events = Get-WinEvent -LogName $LogName | Where-Object { $_.RecordId -gt $lastRecordId } | Sort-Object RecordId

        if ($events) {
            foreach ($event in $events) {
                $entryType = if ($event.LevelDisplayName) { $event.LevelDisplayName } else { "Information" }

                $logEvent = [PSCustomObject]@{
                    EntryType = $entryType
                    EventID   = $event.Id
                    Source    = $event.ProviderName
                    Message   = $event.Message
                }

                $syslogMessage = Format-SyslogMessage -LogEvent $logEvent
                Send-SyslogMessage -Message $syslogMessage -udpClient $udpClient

                $lastRecordId = $event.RecordId
            }
        }
    } catch {
        Write-Warning "Polling error: $_"
    }

    Start-Sleep -Seconds $PollInterval
}

# Close UDP client upon exit
$udpClient.Close()
Write-Host "Syslog transmission completed." -ForegroundColor Green








