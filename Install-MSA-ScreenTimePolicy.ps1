<# ======================================================================
  Install-MSA-ScreenTimePolicy.ps1
  Offline enforcement for Windows 11 (Microsoft accounts & local accounts)

  What it enforces
    • Curfew (default 22:00–06:00): Log off or Lock (disconnect) all non-exempt sessions.
    • Daily per-user screen-time cap (default 240 minutes): Shuts down PC when reached.
    • Anti-tamper watchdog: If user kills the enforcer, PC shuts down.

  No use of:
    • `net user /times`
    • Local Security Policy / secedit

  Works for:
    • Microsoft accounts, local accounts, and domain accounts (interactive).

  Usage:
    .\Install-MSA-ScreenTimePolicy.ps1 -CurfewStart '22:00' -CurfewEnd '06:00' -MaxMinutes 240 -AllowAdministrators
    .\Install-MSA-ScreenTimePolicy.ps1 -ExemptUsers 'admin','hiren','microsoftaccount\someone@example.com'
    .\Install-MSA-ScreenTimePolicy.ps1 -Uninstall

  Run as: Administrator (elevated pwsh)
====================================================================== #>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [ValidatePattern('^\d{1,2}:\d{2}$')]
    [string]$CurfewStart = '22:00',

    [ValidatePattern('^\d{1,2}:\d{2}$')]
    [string]$CurfewEnd   = '06:00',

    [ValidateRange(30, 720)]
    [int]$MaxMinutes     = 240,

    [ValidateSet('Logoff','Lock')]
    [string]$CurfewAction = 'Logoff',

    [string[]]$ExemptUsers,     # additional usernames to exempt (as shown by `quser`)
    [switch]$AllowAdministrators, # exempts users in local Administrators group

    [switch]$Uninstall
)

# --------------------------- Helpers ---------------------------------------

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run this script in an elevated PowerShell (Run as Administrator)." }
}

function New-TextFile([string]$Path,[string]$Content,[string]$Encoding='UTF8') {
    New-Item -Path (Split-Path $Path) -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath $Path -Value $Content -Encoding $Encoding
}

function Get-CurfewDuration([string]$Start, [string]$End){
    $s = [DateTime]::ParseExact($Start,'HH:mm',$null)
    $e = [DateTime]::ParseExact($End  ,'HH:mm',$null)
    $dur = if ($s -gt $e) { ([TimeSpan]::FromHours(24) - ($s.TimeOfDay - $e.TimeOfDay)) } else { $e - $s }
    "{0:00}:{1:00}" -f [int]$dur.TotalHours, $dur.Minutes
}

# --------------------------- Paths -----------------------------------------

Assert-Admin
# Validate time format
[void][DateTime]::ParseExact($CurfewStart,'HH:mm',$null)
[void][DateTime]::ParseExact($CurfewEnd  ,'HH:mm',$null)

$root = "$env:ProgramData\ScreenTime"
$bin  = Join-Path $root 'bin'
New-Item -Path $bin -ItemType Directory -Force | Out-Null

# --------------------------- Uninstall --------------------------------------

if ($Uninstall) {
    Write-Host "Uninstalling tasks and files..."
    schtasks /Delete /TN "ScreenTime\Enforcer" /F *> $null
    schtasks /Delete /TN "ScreenTime\Curfew"   /F *> $null
    schtasks /Delete /TN "ScreenTime\Watchdog" /F *> $null
    if (Test-Path $root) { Remove-Item $root -Recurse -Force }
    Write-Host "Uninstall complete."
    exit 0
}

# --------------------------- Enforcement scripts ----------------------------

# 1) Per-user screen-time agent
$screenTimePs1 = @'
param(
    [int]$MaxMinutes = 240,
    [int]$IdleGraceSeconds = 300,
    [int]$PollSeconds = 15,
    [string[]]$ExemptUsers,
    [switch]$AllowAdmins
)

# Normalize ExemptUsers (comma-separated -> array)
if ($ExemptUsers -and $ExemptUsers.Count -eq 1 -and ($ExemptUsers[0] -match ',')) {
    $ExemptUsers = $ExemptUsers[0].Split(',')
}

# If current user is exempt, exit silently
$currentUser = $env:USERNAME
# 'quser' may show different casing/domain prefix; compare case-insensitive on simple name and DOMAIN\name forms
$exemptMatch = $false
if ($ExemptUsers) {
    # also consider "COMPUTERNAME\username" and "microsoftaccount\email" possibilities
    $candidates = @($currentUser, "$env:COMPUTERNAME\$currentUser", "microsoftaccount\$currentUser")
    foreach ($x in $ExemptUsers) { if ($candidates -contains $x) { $exemptMatch = $true; break } }
}
if ($exemptMatch) { exit 0 }

# If AllowAdmins and current user is local admin, exit
try {
    if ($AllowAdmins) {
        $wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }
    }
} catch {}

# --- Idle timer via Win32 GetLastInputInfo ---
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class IdleCheck{
  [StructLayout(LayoutKind.Sequential)] struct LASTINPUTINFO{ public uint cbSize; public uint dwTime; }
  [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO lii);
  public static TimeSpan GetIdle(){
    LASTINPUTINFO l=new LASTINPUTINFO(); l.cbSize=(uint)System.Runtime.InteropServices.Marshal.SizeOf(l);
    GetLastInputInfo(ref l); uint diff=((uint)Environment.TickCount)-l.dwTime; return TimeSpan.FromMilliseconds(diff);
  }
}
"@

$stateDir  = Join-Path $env:LOCALAPPDATA 'ScreenTime'
$todayKey  = (Get-Date).ToString('yyyy-MM-dd')
$stateFile = Join-Path $stateDir "state-$todayKey.json"
New-Item -Path $stateDir -ItemType Directory -Force | Out-Null

if (Test-Path $stateFile) { try { $state = Get-Content $stateFile | ConvertFrom-Json } catch { $state = @{ Seconds = 0 } } }
else { $state = @{ Seconds = 0 } }

function Save($s){ @{Date=$todayKey; Seconds=[int]$s} | ConvertTo-Json | Set-Content -Path $stateFile -Encoding UTF8 }
function Warn($m){ try{ msg.exe $env:USERNAME /time:120 $m | Out-Null }catch{} }

while($true){
  $nowKey=(Get-Date).ToString('yyyy-MM-dd')
  if($nowKey -ne $todayKey){ $todayKey=$nowKey; $stateFile=Join-Path $stateDir "state-$todayKey.json"; $state=@{Seconds=0}; Save $state.Seconds }
  $idle=[IdleCheck]::GetIdle().TotalSeconds
  if($idle -lt $IdleGraceSeconds){ $state.Seconds += $PollSeconds; Save $state.Seconds }
  if($state.Seconds -ge ($MaxMinutes*60)){
    Warn "Daily screen time reached ($MaxMinutes min). PC will shut down in 2 minutes. Save your work."
    Start-Process shutdown.exe -ArgumentList '/s /t 120 /c "Screen time limit reached"' -WindowStyle Hidden
    break
  }
  Start-Sleep -Seconds $PollSeconds
}
'@
New-TextFile -Path (Join-Path $bin 'ScreenTime.ps1') -Content $screenTimePs1

# 2) Curfew enforcer (SYSTEM): Logoff or Lock non-exempt sessions during curfew
$forceCurfewPs1 = @"
param(
  [string]`$Start='22:00',
  [string]`$End='06:00',
  [ValidateSet('Logoff','Lock')] [string]`$Action='Logoff',
  [string[]]`$ExemptUsers,
  [switch]`$AllowAdmins
)

# Normalize ExemptUsers
if(`$ExemptUsers -and `$ExemptUsers.Count -eq 1 -and (`$ExemptUsers[0] -match ',')) { `$ExemptUsers = `$ExemptUsers[0].Split(',') }

function In-Curfew{
  param([string]`$Start,[string]`$End)
  `$now = Get-Date
  `$s = [datetime]::ParseExact(`$Start,'HH:mm',$null)
  `$e = [datetime]::ParseExact(`$End,'HH:mm',$null)
  if(`$s -gt `$e){ return (`$now.TimeOfDay -ge `$s.TimeOfDay) -or (`$now.TimeOfDay -lt `$e.TimeOfDay) }
  else{ return (`$now.TimeOfDay -ge `$s.TimeOfDay) -and (`$now.TimeOfDay -lt `$e.TimeOfDay) }
}

# Build exempt list; include Administrators when requested
`$adminList = @()
if(`$AllowAdmins){
  try{ `$adminList = (net localgroup Administrators) -match '^\s+\S' | % { `$_.Trim() } }catch{}
}

# Helper: check if a `quser` username matches exemption
function Is-Exempt([string]`$User){
  if([string]::IsNullOrWhiteSpace(`$User)){ return `$false }
  if(`$AllowAdmins -and (`$adminList -contains `$User)){ return `$true }
  if(-not `$ExemptUsers){ return `$false }
  foreach(`$e in `$ExemptUsers){
    if([string]::Compare(`$e, `$User, `$true) -eq 0){ return `$true }
  }
  return `$false
}

if (In-Curfew -Start `$Start -End `$End){
  `$q = (& quser) 2>$null
  if(`$q){
    `$lines = `$q | Select-Object -Skip 1
    foreach(`$line in `$lines){
      # Normalize spacing and split; columns typically: USERNAME | SESSIONNAME | ID | STATE | IDLE TIME | LOGON TIME
      `$parts = (`$line -replace '\s{2,}','|').Split('|') | ? {`$_ -ne ''}
      if(`$parts.Count -ge 3){
        `$user = `$parts[0].Trim()
        `$id   = `$parts[2].Trim()
        if(`$id -match '^\d+$' -and -not (Is-Exempt `$user)){
          try{
            if(`$Action -eq 'Logoff'){ logoff `$id /V }
            else { tsdiscon `$id }
          }catch{}
        }
      }
    }
  }
}
"@
New-TextFile -Path (Join-Path $bin 'ForceCurfew.ps1') -Content $forceCurfewPs1

# 3) Watchdog (SYSTEM): if a non-exempt session lacks ScreenTime.ps1, shut down
$watchdogPs1 = @"
param([string[]]`$ExemptUsers,[switch]`$AllowAdmins)

if(`$ExemptUsers -and `$ExemptUsers.Count -eq 1 -and (`$ExemptUsers[0] -match ',')) { `$ExemptUsers = `$ExemptUsers[0].Split(',') }

`$adminList = @()
if(`$AllowAdmins){
  try{ `$adminList = (net localgroup Administrators) -match '^\s+\S' | % { `$_.Trim() } }catch{}
}

function Is-Exempt([string]`$User){
  if([string]::IsNullOrWhiteSpace(`$User)){ return `$false }
  if(`$AllowAdmins -and (`$adminList -contains `$User)){ return `$true }
  if(-not `$ExemptUsers){ return `$false }
  foreach(`$e in `$ExemptUsers){
    if([string]::Compare(`$e, `$User, `$true) -eq 0){ return `$true }
  }
  return `$false
}

`$q = (& quser) 2>$null
if(`$q){
  `$lines = `$q | Select-Object -Skip 1
  foreach(`$line in `$lines){
    `$parts = (`$line -replace '\s{2,}','|').Split('|') | ? {`$_ -ne ''}
    if(`$parts.Count -ge 3){
      `$user = `$parts[0].Trim()
      if(Is-Exempt `$user){ continue }
      try{
        # Check for ScreenTime.ps1 in the user's processes
        `$ok = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
          Where-Object { (`$_.CommandLine -like '*ScreenTime.ps1*') -and (($_.GetOwner()).User -eq `$user) } |
          Select-Object -First 1
        if(-not `$ok){
          Start-Process shutdown.exe -ArgumentList '/s /t 60 /c "Tamper detected: screen-time enforcer not running"' -WindowStyle Hidden
        }
      }catch{}
    }
  }
}
"@
New-TextFile -Path (Join-Path $bin 'Watchdog.ps1') -Content $watchdogPs1

# --------------------------- Scheduled Tasks --------------------------------

$curfewDuration = Get-CurfewDuration -Start $CurfewStart -End $CurfewEnd

# Task 1: Per-user enforcer (runs at *any* user logon)
$enfArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\ScreenTime.ps1`" -MaxMinutes $MaxMinutes"
if ($AllowAdministrators) { $enfArgs += " -AllowAdmins" }
if ($ExemptUsers) { $enfArgs += " -ExemptUsers `"$($ExemptUsers -join ',')`"" }

$xmlEnforcer = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>LocalAdmin</Author><Description>Per-user screen-time enforcement</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals>
    <Principal id="AnyUser"><GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="AnyUser">
    <Exec><Command>powershell.exe</Command><Arguments>$enfArgs</Arguments></Exec>
  </Actions>
</Task>
"@
$xmlPath = Join-Path $bin 'Enforcer.xml'; New-TextFile -Path $xmlPath -Content $xmlEnforcer
schtasks /Create /TN "ScreenTime\Enforcer" /XML "$xmlPath" /F *> $null

# Task 2: Curfew enforcer (SYSTEM) – run every 2 minutes during the curfew window
$curfewArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\ForceCurfew.ps1`" -Start `"$CurfewStart`" -End `"$CurfewEnd`" -Action $CurfewAction"
if ($AllowAdministrators) { $curfewArgs += " -AllowAdmins" }
if ($ExemptUsers)        { $curfewArgs += " -ExemptUsers `"$($ExemptUsers -join ',')`"" }

schtasks /Create /TN "ScreenTime\Curfew" /SC DAILY /ST $CurfewStart /RI 2 /DU $curfewDuration `
  /RU "SYSTEM" /RL HIGHEST /TR "powershell.exe $curfewArgs" /F *> $null

# Task 3: Watchdog (SYSTEM) – every 5 minutes all day
$watchArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\Watchdog.ps1`""
if ($AllowAdministrators) { $watchArgs += " -AllowAdmins" }
if ($ExemptUsers)        { $watchArgs += " -ExemptUsers `"$($ExemptUsers -join ',')`"" }

schtasks /Create /TN "ScreenTime\Watchdog" /SC MINUTE /MO 5 /RU "SYSTEM" /RL HIGHEST `
  /TR "powershell.exe $watchArgs" /F *> $null
Write-Host ""
Write-Host "Setup complete."
Write-Host "Curfew: $CurfewStart – $CurfewEnd  (duration $curfewDuration), Action: $CurfewAction"
Write-Host "Daily cap: $MaxMinutes minutes"
if ($AllowAdministrators) { Write-Host "Administrators are exempt from both curfew and screen-time." }
if ($ExemptUsers) { Write-Host "Additional exempt users: $($ExemptUsers -join ', ')" }
