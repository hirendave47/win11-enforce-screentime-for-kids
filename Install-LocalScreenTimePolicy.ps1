<# ======================================================================
  Install-LocalScreenTimePolicy.ps1
  Offline enforcement for Windows 11 Pro

  Features:
   - Curfew block (default 22:00–06:00) + forced logoff for non-allowed users
   - Daily screen-time cap (default 240 minutes) with auto shutdown
   - Restrict "Allow log on locally" to Administrators + specified users
   - Remove "Change the time zone" privilege from standard users
   - Anti-tamper watchdog
   - Fully offline; uses secedit + schtasks

  Usage (run elevated):
    pwsh -NoProfile
    Set-Location <folder>
    .\Install-LocalScreenTimePolicy.ps1 -UserNames 'Kid'

  Uninstall:
    .\Install-LocalScreenTimePolicy.ps1 -UserNames 'Kid' -Uninstall

  NOTE: Specify existing local (non-admin) accounts. The script will remove
        any specified user from local Administrators if present.
====================================================================== #>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$UserNames,

    [ValidatePattern('^\d{1,2}:\d{2}$')]
    [string]$CurfewStart = '22:00',

    [ValidatePattern('^\d{1,2}:\d{2}$')]
    [string]$CurfewEnd   = '06:00',

    [ValidateRange(30, 720)]
    [int]$MaxMinutes = 240,   # 4 hours

    [switch]$Uninstall
)

# --------------------------- Helpers ---------------------------------------

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run this script in an elevated PowerShell (Run as Administrator)." }
}

function Get-UserSID([string]$LocalUser) {
    try {
        $acct = New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME",$LocalUser)
        return $acct.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "User '$LocalUser' not found as a local account on $env:COMPUTERNAME."
    }
}

function Test-ValidTime([string]$hhmm) {
    [void][DateTime]::ParseExact($hhmm,'HH:mm',$null)
}

function New-TextFile([string]$Path,[string]$Content,[string]$Encoding='UTF8') {
    New-Item -Path (Split-Path $Path) -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath $Path -Value $Content -Encoding $Encoding
}

function Run-Cmd([string]$File,[string]$Args){
    $p = Start-Process -FilePath $File -ArgumentList $Args -PassThru -WindowStyle Hidden -Wait
    if ($p.ExitCode -ne 0) { Write-Warning "$File $Args exited with $($p.ExitCode)" }
}

function Get-AdministratorsSID { 'S-1-5-32-544' }  # Built-in Administrators

# Allowed sign-in window based on curfew (1h granularity for 'net user /times')
function Get-AllowedTimesString([string]$Start, [string]$End){
    $tStart = [DateTime]::ParseExact($Start,'HH:mm',$null)
    $tEnd   = [DateTime]::ParseExact($End,'HH:mm',$null)
    if ($tStart -eq $tEnd) { return 'M-Su,0:00-0:00' } # no access at all
    # If curfew crosses midnight (e.g. 22:00->06:00), allowed is 06:00-22:00; else, allowed is 00:00-Start and End-24:00
    $win = if ($tStart -gt $tEnd) { "$($End)-$($Start)" } else { "0:00-$($Start),$($End)-24:00" }
    return "M-Su,$win"
}

# Curfew duration string for schtasks /DU (HH:MM) to span crossing midnight correctly
function Get-CurfewDuration([string]$Start, [string]$End){
    $s = [DateTime]::ParseExact($Start,'HH:mm',$null)
    $e = [DateTime]::ParseExact($End  ,'HH:mm',$null)
    $dur = if ($s -gt $e) { ([TimeSpan]::FromHours(24) - ($s.TimeOfDay - $e.TimeOfDay)) } else { $e - $s }
    "{0:00}:{1:00}" -f [int]$dur.TotalHours, $dur.Minutes
}

# Apply 'Allow log on locally' rights; optionally remove override
function Set-UserRightsAssignment([string[]]$AllowedUserSIDs,[switch]$Remove) {
    $db  = "$env:ProgramData\ScreenTime\secedit.sdb"
    $inf = "$env:ProgramData\ScreenTime\user-rights.inf"

    if ($Remove) {
        if (Test-Path $inf) { Remove-Item $inf -Force }
        # No explicit revert to original baseline (varies by image); admin can reconfigure later if needed.
        return
    }

    $sids = @((Get-AdministratorsSID)) + $AllowedUserSIDs
    $sidList = ($sids | Select-Object -Unique) -join ','

    $infBody = @"
[Unicode]
Unicode=yes
[Version]
signature=`"$CHICAGO$`"
Revision=1

[Privilege Rights]
; Only Administrators + explicit users may log on interactively
SeInteractiveLogonRight = $sidList

; Optional hardening: Only Administrators may change time zone
SeTimeZonePrivilege = $(Get-AdministratorsSID)
"@

    # INF must be Unicode
    New-TextFile -Path $inf -Content $infBody -Encoding Unicode
    Run-Cmd 'secedit.exe' "/configure /db `"$db`" /cfg `"$inf`" /areas USER_RIGHTS /quiet"
}

function Ensure-StandardUser([string]$User) {
    # Remove from local Administrators if present
    $isAdmin = (net localgroup Administrators | Select-String -SimpleMatch " $User") ? $true : $false
    if ($isAdmin) {
        Write-Host "Removing $User from local Administrators..."
        Run-Cmd 'net.exe' "localgroup Administrators `"$User`" /delete"
    }
}

function Set-LogonHours([string]$User,[string]$Allowed) {
    Run-Cmd 'net.exe' "user `"$User`" /times:$Allowed"
}

# --------------------------- Start -----------------------------------------

Assert-Admin
Test-ValidTime $CurfewStart; Test-ValidTime $CurfewEnd

$allowedTimes = Get-AllowedTimesString -Start $CurfewStart -End $CurfewEnd
$curfewDuration = Get-CurfewDuration -Start $CurfewStart -End $CurfewEnd

$root = "$env:ProgramData\ScreenTime"
$bin  = Join-Path $root 'bin'
New-Item -Path $bin -ItemType Directory -Force | Out-Null

# Uninstall path
if ($Uninstall) {
    Write-Host "Uninstalling tasks, policies and files..."
    schtasks /Delete /TN "ScreenTime\Enforcer" /F *> $null
    schtasks /Delete /TN "ScreenTime\Curfew"   /F *> $null
    schtasks /Delete /TN "ScreenTime\Watchdog" /F *> $null

    foreach ($u in $UserNames) { Run-Cmd 'net.exe' "user `"$u`" /time:all" }

    Set-UserRightsAssignment -AllowedUserSIDs @() -Remove

    if (Test-Path $root) { Remove-Item $root -Recurse -Force }
    Write-Host "Uninstall completed."
    exit 0
}

# Validate users & collect SIDs
$userSIDs = @()
foreach ($u in $UserNames) {
    if (-not (Get-LocalUser -Name $u -ErrorAction SilentlyContinue)) {
        throw "Local user '$u' does not exist. Create it first (Standard user) and re-run."
    }
    Ensure-StandardUser $u
    $userSIDs += Get-UserSID $u
}

# ---------------------- Write enforcement scripts --------------------------

# (1) Screen-time agent (runs in user session at logon)
$screenTimePs1 = @'
param(
    [int]$MaxMinutes = 240,
    [int]$IdleGraceSeconds = 300,
    [int]$PollSeconds = 15
)
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
    Warn "Screen time limit reached ($MaxMinutes min). PC will shut down in 2 minutes. Save your work."
    Start-Process shutdown.exe -ArgumentList '/s /t 120 /c "Screen time limit reached"' -WindowStyle Hidden
    break
  }
  Start-Sleep -Seconds $PollSeconds
}
'@
New-TextFile -Path (Join-Path $bin 'ScreenTime.ps1') -Content $screenTimePs1

# (2) ForceCurfew (SYSTEM task, logoff non-allowed sessions during curfew)
$forceCurfewPs1 = @"
param([string[]]`$AllowedUsers, [string]`$Start='22:00', [string]`$End='06:00')

# Support comma-separated single arg -> array
if(`$AllowedUsers.Count -eq 1 -and (`$AllowedUsers[0] -match ',')){ `$AllowedUsers = `$AllowedUsers[0].Split(',') }

function In-Curfew{
  param([string]`$Start,[string]`$End)
  `$now = Get-Date
  `$s = [datetime]::ParseExact(`$Start,'HH:mm',$null)
  `$e = [datetime]::ParseExact(`$End,'HH:mm',$null)
  if(`$s -gt `$e){ return (`$now.TimeOfDay -ge `$s.TimeOfDay) -or (`$now.TimeOfDay -lt `$e.TimeOfDay) }
  else{ return (`$now.TimeOfDay -ge `$s.TimeOfDay) -and (`$now.TimeOfDay -lt `$e.TimeOfDay) }
}
if (In-Curfew -Start `$Start -End `$End){
  `$admins = @()
  try{ `$admins = (net localgroup Administrators) -match '^\s+\S' | % { `$_.Trim() } }catch{}
  `$sessions = (& quser) 2>$null
  if(`$sessions){
    `$sessions | Select-Object -Skip 1 | ForEach-Object {
      `$parts = (`$_ -replace '\s{2,}','|').Split('|') | ? {`$_ -ne ''}
      if(`$parts.Count -ge 3){
        `$user = `$parts[0]
        `$id   = `$parts[1]
        if((`$user -ne '>' ) -and (`$user -ne '') -and (`$id -match '^\d+$')){
          if((`$admins -notcontains `$user) -and (`$AllowedUsers -notcontains `$user)){
            try{ logoff `$id /V } catch {}
          }
        }
      }
    }
  }
}
"@
New-TextFile -Path (Join-Path $bin 'ForceCurfew.ps1') -Content $forceCurfewPs1

# (3) Watchdog (SYSTEM task; shutdown if per-user agent is killed)
$watchdogPs1 = @"
param([string[]]`$AllowedUsers)
if(`$AllowedUsers.Count -eq 1 -and (`$AllowedUsers[0] -match ',')){ `$AllowedUsers = `$AllowedUsers[0].Split(',') }

`$sessions = (& quser) 2>$null
if(`$sessions){
  `$activeUsers = @()
  `$sessions | Select-Object -Skip 1 | ForEach-Object {
    `$parts = (`$_ -replace '\s{2,}','|').Split('|') | ? {`$_ -ne ''}
    if(`$parts.Count -ge 1){ `$u = `$parts[0]; if(`$AllowedUsers -contains `$u){ `$activeUsers += `$u } }
  }
  foreach(`$u in `$activeUsers | Select-Object -Unique){
    try{
      `$proc = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { (`$_.CommandLine -like '*ScreenTime.ps1*') -and ((`$_.GetOwner()).User -eq `$u) }
      if(-not `$proc){
        Start-Process shutdown.exe -ArgumentList '/s /t 60 /c "Tamper detected: screen-time enforcer stopped"' -WindowStyle Hidden
      }
    }catch{}
  }
}
"@
New-TextFile -Path (Join-Path $bin 'Watchdog.ps1') -Content $watchdogPs1

# ------------------ Rights + logon hours + scheduled tasks -----------------

Write-Host "Restricting 'Allow log on locally' to Administrators + $($UserNames -join ', ') ..."
Set-UserRightsAssignment -AllowedUserSIDs $userSIDs

Write-Host "Setting sign-in hours ($allowedTimes) with 'net user /times' ..."
foreach ($u in $UserNames) { Set-LogonHours -User $u -Allowed $allowedTimes }

# Task 1: Per-user ScreenTime enforcer (Logon trigger, Any user, hidden)
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
    <Exec><Command>powershell.exe</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$bin\ScreenTime.ps1" -MaxMinutes $MaxMinutes</Arguments>
    </Exec>
  </Actions>
</Task>
"@
$xmlPath = Join-Path $bin 'Enforcer.xml'; New-TextFile -Path $xmlPath -Content $xmlEnforcer
schtasks /Create /TN "ScreenTime\Enforcer" /XML "$xmlPath" /F *> $null

# Task 2: Curfew enforcer (SYSTEM), runs every 5 mins for the exact curfew duration
$curfewCmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\ForceCurfew.ps1`" -AllowedUsers `"$($UserNames -join ',')`" -Start `"$CurfewStart`" -End `"$CurfewEnd`""
schtasks /Create /TN "ScreenTime\Curfew" /SC DAILY /ST $CurfewStart /RI 5 /DU $curfewDuration /RU "SYSTEM" /RL HIGHEST /TR "$curfewCmd" /F *> $null

# Task 3: Watchdog (SYSTEM) every 5 mins all day; shutdown if agent is missing
$watchCmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\Watchdog.ps1`" -AllowedUsers `"$($UserNames -join ',')`""
schtasks /Create /TN "ScreenTime\Watchdog" /SC MINUTE /MO 5 /RU "SYSTEM" /RL HIGHEST /TR "$watchCmd" /F *> $null

Write-Host ""
Write-Host "Setup complete."
Write-Host "Curfew: $CurfewStart – $CurfewEnd  (duration $curfewDuration)"
Write-Host "Daily cap: $MaxMinutes minutes"
Write-Host "Allowed to sign in locally: Administrators + $($UserNames -join ', ')"
