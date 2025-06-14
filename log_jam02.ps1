# ---------------- Configuration ----------------
$SyslogServer  = "192.168.0.172"      # Syslog server IP or hostname
$SyslogPort    = 514                  # UDP port (usually 514 for syslog)
$LogName       = "Security"           # Event log to monitor: Security, System, Application
$Facility      = 4                    # Syslog facility (4 = auth/security)
$PollInterval  = 5                    # Poll interval in seconds
$MaxEvents     = 50                   # Max events to fetch per poll

# --------------- Privilege Check ----------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator to access the Security log."
    exit
}

# ------------ Syslog Severity Mapping -----------
function Get-SyslogPriority {
    param([string]$EntryType)
    switch ($EntryType) {
        "Critical"      { return 2 }  # Alert
        "Error"         { return 3 }  # Error
        "Warning"       { return 4 }  # Warning
        "Information"   { return 6 }  # Informational
        "Audit Failure" { return 3 }  # Auth Failure
        "Audit Success" { return 5 }  # Notice
        default         { return 5 }  # Default: Notice
    }
}

# ------------ Format Syslog Message -------------
function Format-SyslogMessage {
    param ([pscustomobject]$LogEvent)

    $hostname = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "MMM dd HH:mm:ss"
    $priority = ($Facility * 8) + (Get-SyslogPriority -EntryType $LogEvent.EntryType)
    $sanitizedMessage = ($LogEvent.Message -replace '[\r\n]+', ' ') -replace '[^\x20-\x7E]', ''

    $message = "<$priority>$timestamp $hostname ${LogName}: EventID=$($LogEvent.EventID); Source=$($LogEvent.Source); $sanitizedMessage"
    if ($message.Length -gt 1024) {
        $message = $message.Substring(0, 1020) + "..."
    }

    return $message
}

# ------------- Send Syslog Message --------------
function Send-SyslogMessage {
    param (
        [string]$Message,
        [System.Net.Sockets.UdpClient]$udpClient
    )
    try {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Message)
        $udpClient.Send($bytes, $bytes.Length, $SyslogServer, $SyslogPort) | Out-Null
    } catch {
        Write-Warning "Failed to send syslog message: $_"
    }
}

# ------------- Initialize and Begin -------------
$udpClient = New-Object System.Net.Sockets.UdpClient
Write-Host "Monitoring '${LogName}' log. Polling every $PollInterval seconds..." -ForegroundColor Cyan

# ---------- Get Starting Record Position --------
try {
    $lastEvent = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
    $lastRecordId = if ($lastEvent) { $lastEvent.RecordId } else { 0 }
    Write-Host "Starting from Record ID: $lastRecordId"
} catch {
    Write-Error "Unable to access log '${LogName}'. Exiting."
    exit
}

# ---------------- Polling Loop ------------------
while ($true) {
    try {
        $filter = @{
            LogName = $LogName
            StartTime = (Get-Date).AddSeconds(-$PollInterval - 1)
        }

        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop |
                  Where-Object { $_.RecordId -gt $lastRecordId } |
                  Sort-Object RecordId

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
    } catch {
        Write-Warning "Polling error: $_"
    }

    Start-Sleep -Seconds $PollInterval
}

# ------------------ Cleanup ---------------------
$udpClient.Close()
Write-Host "Syslog monitoring ended." -ForegroundColor Green



