<#
.SYNOPSIS
    Parental Control Script to enforce PC usage time and daily screen time limits.
.DESCRIPTION
    This script is intended to be run via Windows Task Scheduler every 5 minutes.
    It performs two main checks:
    1. Time-of-Day Check: If the current time is not between 6:00 AM and 10:00 PM, it initiates a shutdown.
    2. Daily Usage Check: It tracks active screen time (when the screen is unlocked) and initiates a shutdown
       if the accumulated time exceeds a 4-hour (240-minute) daily limit. The usage counter resets daily.
.NOTES
    Author: Hiren Dave
    Version: 1.0
    - This script must be run with administrative privileges.
    - The usage log is stored in C:\ProgramData\ChildUsageTracker.log
#>

#================================================================================
# Configuration - You can change these values
#================================================================================

# Allowed usage hours (24-hour format). Default is 6 AM to 10 PM.
 $AllowedStartHour = 6
 $AllowedEndHour = 22

# Maximum daily screen time in minutes. Default is 4 hours (240 minutes).
 $MaxDailyUsageMinutes = 240

# Path to the log file for tracking usage. Stored in a secure, system-wide location.
 $LogFile = "C:\ProgramData\ChildUsageTracker.log"

#================================================================================
# Script Logic - Do not modify below this line
#================================================================================

# --- 1. Ensure script is running with Administrative privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run with administrative privileges. Please re-run it from an elevated PowerShell or Task Scheduler."
    exit 1
}

# --- 2. Initialize or Reset Daily Usage Counter ---
 $Today = (Get-Date).Date
if (Test-Path $LogFile) {
    $FileLastModified = (Get-Item $LogFile).LastWriteTime.Date
    if ($FileLastModified -ne $Today) {
        # It's a new day, so reset the counter.
        Set-Content -Path $LogFile -Value "0" -Force
        Write-Output "New day detected. Usage counter has been reset to 0."
    }
} else {
    # Log file doesn't exist, create it and start a new counter.
    try {
        Set-Content -Path $LogFile -Value "0" -Force -ErrorAction Stop
        Write-Output "Usage log file created at $LogFile."
    }
    catch {
        Write-Error "Failed to create log file at $LogFile. Please check permissions."
        exit 1
    }
}

# --- 3. Update Screen Time Usage ---
# We only count time if the screen is NOT locked. The presence of the 'LogonUI' process
# indicates a locked screen or sign-in screen.
 $LogonUIProcess = Get-Process -Name "LogonUI" -ErrorAction SilentlyContinue

if (-not $LogonUIProcess) {
    # Screen is unlocked, user is potentially active. Add 5 minutes to the usage.
    $CurrentUsageMinutes = [int](Get-Content $LogFile)
    $NewUsageMinutes = $CurrentUsageMinutes + 5 # The script runs every 5 minutes.
    Set-Content -Path $LogFile -Value $NewUsageMinutes -Force
    Write-Output "Screen is active. Added 5 minutes. Total usage today: $NewUsageMinutes minutes."
}
else {
    # Screen is locked. Do not add to usage time.
    $CurrentUsageMinutes = [int](Get-Content $LogFile)
    Write-Output "Screen is locked. No usage time added. Total usage remains: $CurrentUsageMinutes minutes."
}

# --- 4. Check for Shutdown Conditions ---

# Get current values for checks
 $CurrentHour = (Get-Date).Hour
 $CurrentUsageMinutes = [int](Get-Content $LogFile)

# Condition 1: Check if the current time is outside allowed hours.
if ($CurrentHour -lt $AllowedStartHour -or $CurrentHour -ge $AllowedEndHour) {
    $Message = "Shutdown initiated: It is outside the allowed usage time of $AllowedStartHour:00 AM to $AllowedEndHour:00 PM."
    Write-Warning $Message
    # Initiate a 60-second shutdown with a warning message.
    shutdown /s /t 60 /c $Message /f
    exit 0
}

# Condition 2: Check if daily usage has exceeded the limit.
if ($CurrentUsageMinutes -ge $MaxDailyUsageMinutes) {
    $Message = "Shutdown initiated: The daily screen time limit of $MaxDailyUsageMinutes minutes has been reached."
    Write-Warning $Message
    # Initiate a 60-second shutdown with a warning message.
    shutdown /s /t 60 /c $Message /f
    exit 0
}

Write-Output "No action required. System is within allowed time and usage limits."
exit 0
