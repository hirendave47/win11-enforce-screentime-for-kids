<# ======================================================================
  Install-LocalScreenTimePolicy.ps1
  - Offline enforcement for Windows 11 Pro
  - Curfew 22:00–06:00, auto-shutdown after 4h screen-time
  - Only Administrators and specified users may log on locally
  Author: Hiren Dave
====================================================================== #>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
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

# region Helpers ------------------------------------------------------------

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

function New-TextFile([string]$Path,[string]$Content) {
    New-Item -Path (Split-Path $Path) -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
}

function Run-Cmd([string]$File,[string]$Args){
    $p = Start-Process -FilePath $File -ArgumentList $Args -PassThru -WindowStyle Hidden -Wait
    if ($p.ExitCode -ne 0) { Write-Warning "$File $Args exited with $($p.ExitCode)" }
}

function Get-AdministratorsSID { 'S-1-5-32-544' }  # Built-in Administrators

# Parse curfew into allowed hours string for `net user /times`
function Get-AllowedTimesString([string]$Start, [string]$End){
    # We allow 6:00-22:00 by default; generalized formula:
    # If CurfewStart < CurfewEnd => curfew within same day (rare), else crosses midnight (22:00->06:00).
    # Allowed = from End to Start (exclusive), in 1h granularity required by 'net user'.
    $tStart = [DateTime]::ParseExact($Start,'HH:mm',$null)
    $tEnd   = [DateTime]::ParseExact($End,'HH:mm',$null)
    if ($tStart -eq $tEnd) { return 'M-Su,0:00-0:00' } # no access at all
    $win    = if ($tStart -gt $tEnd) { "$($End)-$($Start)" } else { "0:00-$($Start),$($End)-24:00" }
    return "M-Su,$win"
}

# Creates/updates a Local Security Policy INF and applies with secedit
function Set-UserRightsAssignment([string[]]$AllowedUserSIDs,[switch]$Remove=false) {
    $db  = "$env:ProgramData\ScreenTime\secedit.sdb"
    $inf = "$env:ProgramData\ScreenTime\user-rights.inf"
    if ($Remove) {
        # Restore default: let Windows manage (leave untouched). We export current DB and remove our override.
        if (Test-Path $inf) { Remove-Item $inf -Force }
        return
    }
    $sids = @((Get-AdministratorsSID)) + $AllowedUserSIDs
    $sidList = ($sids | Select-Object -Unique) -join ','
@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
; Only Administrators + explicit users may log on interactively
SeInteractiveLogonRight = $sidList
; Optional hardening: Only Administrators may change time zone
SeTimeZonePrivilege = $(Get-AdministratorsSID)
"@ | Set-Content -LiteralPath $inf -Encoding Unicode

    # Apply only USER_RIGHTS from INF
    Run-Cmd 'secedit.exe' "/configure /db `"$db`" /cfg `"$inf`" /areas USER_RIGHTS /quiet"
}

function Ensure-StandardUser([string]$User) {
    # Make sure the account is *not* a local admin
    $isAdmin = (net localgroup Administrators | Select-String -SimpleMatch " $User") ? $true : $false
    if ($isAdmin) {
        Write-Host "Removing $User from local Administrators..."
        Run-Cmd 'net.exe' "localgroup Administrators `"$User`" /delete"
    }
}

function Set-LogonHours([string]$User,[string]$Allowed) {
    # 'net user /times:' requires no spaces, 1h steps. Example: M-Su,6:00-22:00
    Run-Cmd 'net.exe' "user `"$User`" /times:$Allowed"
}

# endregion Helpers ---------------------------------------------------------

Assert-Admin
Test-ValidTime $CurfewStart; Test-ValidTime $CurfewEnd
$allowedTimes = Get-AllowedTimesString -Start $CurfewStart -End $CurfewEnd
$root   = "$env:ProgramData\ScreenTime"
$bin    = Join-Path $root 'bin'
New-Item -Path $bin -ItemType Directory -Force | Out-Null

# region Uninstall path -----------------------------------------------------
if ($Uninstall) {
    Write-Host "Uninstalling tasks, policies and files..."
    schtasks /Delete /TN "ScreenTime\Enforcer" /F *> $null
    schtasks /Delete /TN "ScreenTime\Curfew"   /F *> $null
    schtasks /Delete /TN "ScreenTime\Watchdog" /F *> $null

    # Restore logon hours to 'all' for specified users
    foreach ($u in $UserNames) { Run-Cmd 'net.exe' "user `"$u`" /time:all" }

    # Remove tight 'Allow log on locally' and time-zone hardening (leaves OS defaults)
    Set-UserRightsAssignment -AllowedUserSIDs @() -Remove

    # Clean files
    if (Test-Path $root) { Remove-Item $root -Recurse -Force }
    Write-Host "Uninstall completed."
    exit 0
}
# endregion Uninstall -------------------------------------------------------

# Validate users & collect SIDs
$userSIDs = @()
foreach ($u in $UserNames) {
    # Confirm local user exists
    if (-not (Get-LocalUser -Name $u -ErrorAction SilentlyContinue)) {
        throw "Local user '$u' does not exist. Create the account first (as a Standard user) and re-run."
    }
    Ensure-StandardUser $u
    $sid = Get-UserSID $u
    $userSIDs += $sid
}

# region Write enforcement scripts -----------------------------------------

# 1) ScreenTime.ps1 (per-user, counts active time & shuts down at cap)
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
  public static TimeSpan GetIdle(){ LASTINPUTINFO l=new LASTINPUTINFO(); l.cbSize=(uint)System.Runtime.InteropServices.Marshal.SizeOf(l);
    GetLastInputInfo(ref l); uint diff=((uint)Environment.TickCount)-l.dwTime; return TimeSpan.FromMilliseconds(diff); }
}
"@
# Store state per-user under LocalAppData to avoid permission prompts
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

# 2) ForceCurfew.ps1 (SYSTEM task, logoff all non-admin sessions during curfew)
$forceCurfewPs1 = @"
param([string[]]`$AllowedUsers, [string]`$Start='22:00', [string]`$End='06:00')
function In-Curfew{
  param([string]`$Start,[string]`$End)
  `$now = Get-Date
  `$s = [datetime]::ParseExact(`$Start,'HH:mm',$null)
  `$e = [datetime]::ParseExact(`$End,'HH:mm',$null)
  if(`$s -gt `$e){ return (`$now.TimeOfDay -ge `$s.TimeOfDay) -or (`$now.TimeOfDay -lt `$e.TimeOfDay) }
  else{ return (`$now.TimeOfDay -ge `$s.TimeOfDay) -and (`$now.TimeOfDay -lt `$e.TimeOfDay) }
}
# Get sessions and logoff any interactive user not in Administrators nor in the allowed list
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
            # Force logoff this session
            try{ logoff `$id /V } catch {}
          }
        }
      }
    }
  }
}
"@
New-TextFile -Path (Join-Path $bin 'ForceCurfew.ps1') -Content $forceCurfewPs1
# 3) Watchdog.ps1 (SYSTEM task, anti-tamper)
$watchdogPs1 = @"
param([string[]]`$AllowedUsers)
# If any allowed user has an active session *without* ScreenTime.ps1 running, warn then shut down.
`$sessions = (& quser) 2>$null
if(`$sessions){
  `$activeUsers = @()
  `$sessions | Select-Object -Skip 1 | ForEach-Object {
    `$parts = (`$_ -replace '\s{2,}','|').Split('|') | ? {`$_ -ne ''}
    if(`$parts.Count -ge 1){ `$u = `$parts[0]; if(`$AllowedUsers -contains `$u){ `$activeUsers += `$u } }
  }
  foreach(`$u in `$activeUsers | Select-Object -Unique){
    `$proc = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
      Where-Object { (`$_.CommandLine -like '*ScreenTime.ps1*') -and (`$_.GetOwner().User -eq `$u) }
    if(-not `$proc){
      Start-Process shutdown.exe -ArgumentList '/s /t 60 /c "Tamper detected: screen-time enforcer stopped"' -WindowStyle Hidden
    }
  }
}
"@
New-TextFile -Path (Join-Path $bin 'Watchdog.ps1') -Content $watchdogPs1

# endregion scripts ---------------------------------------------------------

# region Tighten "Allow log on locally" (SeInteractiveLogonRight) ----------
Write-Host "Applying 'Allow log on locally' to Administrators + $($UserNames -join ', ') ..."
Set-UserRightsAssignment -AllowedUserSIDs $userSIDs

# endregion ----------------------------------------------------------------

# region Apply logon hours & curfew tasks ----------------------------------
Write-Host "Setting sign-in hours ($allowedTimes) with 'net user /times' ..."
foreach ($u in $UserNames) { Set-LogonHours -User $u -Allowed $allowedTimes }

# --> Task 1: Per-user ScreenTime enforcer (triggers at user logon)
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

# --> Task 2: Curfew: run every 5 min from CurfewStart for 8h, logoff non-allowed users
schtasks /Create /TN "ScreenTime\Curfew" /SC DAILY /ST $CurfewStart /RI 5 /DU 08:00 /RU "SYSTEM" /RL HIGHEST `
  /TR "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\ForceCurfew.ps1`" -AllowedUsers `"$($UserNames -join ',')`" -Start `"$CurfewStart`" -End `"$CurfewEnd`"" /F *> $null

# --> Task 3: Watchdog: every 5 minutes all day; shutdown if tampered
schtasks /Create /TN "ScreenTime\Watchdog" /SC MINUTE /MO 5 /RU "SYSTEM" /RL HIGHEST `
  /TR "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\Watchdog.ps1`" -AllowedUsers `"$($UserNames -join ',')`"" /F *> $null

Write-Host "Setup complete."
Write-Host "Curfew: $CurfewStart – $CurfewEnd ; Daily cap: $MaxMinutes minutes."
Write-Host "Allowed to sign in locally: Administrators + $($UserNames -join ', ')"
# endregion -----------------------------------------------------------------
