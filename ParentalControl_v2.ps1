<#
Improved Parental Control Script — Accurate Screen Time Measurement
Author: Hiren Dave
Version: 1.1
#>

$AllowedStartHour = 6
$AllowedEndHour = 22
$MaxDailyUsageMinutes = 240
$LogFile = "C:\ProgramData\ChildUsageTracker.log"

# Ensure Admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run with administrative privileges."
    exit 1
}

$Today = (Get-Date).Date

# Initialize log file if missing or reset daily
if (!(Test-Path $LogFile) -or ((Get-Item $LogFile).LastWriteTime.Date -ne $Today)) {
    $InitialData = @{
        Date = $Today.ToString("yyyy-MM-dd")
        TotalMinutes = 0
        LastCheck = (Get-Date).ToString("o")
    } | ConvertTo-Json
    Set-Content -Path $LogFile -Value $InitialData -Force
    Write-Output "New log initialized."
}

# Read current log data
$LogData = Get-Content $LogFile | ConvertFrom-Json
$CurrentUsageMinutes = [int]$LogData.TotalMinutes
$LastCheck = [datetime]$LogData.LastCheck
$Now = Get-Date

# Calculate elapsed time since last check
$ElapsedMinutes = [math]::Round(($Now - $LastCheck).TotalMinutes, 1)
if ($ElapsedMinutes -lt 0) { $ElapsedMinutes = 0 } # safety

# Check screen lock status
$IsLocked = Get-Process -Name "LogonUI" -ErrorAction SilentlyContinue

if (-not $IsLocked) {
    # Screen active — add actual elapsed time
    $NewUsageMinutes = $CurrentUsageMinutes + [math]::Round($ElapsedMinutes)
    Write-Output "Screen active. +$ElapsedMinutes min → Total: $NewUsageMinutes"
    $CurrentUsageMinutes = $NewUsageMinutes
} else {
    Write-Output "Screen locked. No time added. Total remains: $CurrentUsageMinutes"
}

# Update log
$UpdatedData = @{
    Date = $Today.ToString("yyyy-MM-dd")
    TotalMinutes = $CurrentUsageMinutes
    LastCheck = $Now.ToString("o")
} | ConvertTo-Json
Set-Content -Path $LogFile -Value $UpdatedData -Force

# Check shutdown conditions
$CurrentHour = $Now.Hour
if ($CurrentHour -lt $AllowedStartHour -or $CurrentHour -ge $AllowedEndHour) {
    shutdown /s /t 60 /c "Outside allowed hours ($AllowedStartHour–$AllowedEndHour)" /f
    exit 0
}

if ($CurrentUsageMinutes -ge $MaxDailyUsageMinutes) {
    shutdown /s /t 60 /c "Daily screen time ($MaxDailyUsageMinutes min) exceeded" /f
    exit 0
}

Write-Output "All OK — within allowed limits."
exit 0
