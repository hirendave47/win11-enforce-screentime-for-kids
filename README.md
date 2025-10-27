A **single, offline PowerShell installer** that:

- Blocks **all sign‑ins from 10 PM–6 AM** via local logon‑hours.
- **Logs off** any active non‑admin sessions during curfew.
- Tracks **per‑day screen‑time** and **shuts down** the PC once the user hits **4 hours**.
- **Prevents new local users** from signing in unless explicitly allowed by an admin by tightening **“Allow log on locally”** rights.
- Adds **hardening** (e.g., remove “Change the time zone” from standard users).
- Works **entirely offline** and survives reboots.

> **References used for design & commands**
> - `net user /times` syntax & 1‑hour increments; built into Windows 11.   
> - Curfew tip & hour‑expiry behavior for interactive logons; user‑side enforcement needs policy or script.   
> - `schtasks` for robust scheduled tasks creation (XML + CLI).   
> - PowerShell idle‑time detection via `GetLastInputInfo` (Win32).   
> - “Network security: Force logoff when logon hours expire” is SMB‑only (not console logoff). 

---

## How to use

1) **Run PowerShell as Administrator**.  
2) Save the script below as, e.g., `Install-LocalScreenTimePolicy.ps1`.  
3) Install for one or more users (comma‑separated list):
```powershell
.\Install-LocalScreenTimePolicy.ps1 -UserNames 'USERNAME'       # single user
.\Install-LocalScreenTimePolicy.ps1 -UserNames 'Child1','Child2'  # multiple users
```
4) Optional parameters:
- `-CurfewStart '22:00' -CurfewEnd '06:00'` (change window)
- `-MaxMinutes 240` (daily cap)
- `-Uninstall` (clean removal)

if PowerShell is blocking the installer, use one of these **safe, temporary** options to allow the script to run. Pick whichever you prefer.

---

## Easiest (recommended): Allow just this session
Run **PowerShell as Administrator** and execute:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

> ⚠️ **Important:** The script will restrict **“Allow log on locally”** to **Administrators + the specified users only**. Any other local user will be unable to sign in until you explicitly add them to the allowed list (by re‑running the script with their name or by editing Local Security Policy).

---

## What this script **does**

- **Sign‑in hours**: Uses `net user <name> /times:M-Su,06:00-22:00` (based on your curfew) to block logon outside allowed hours.  
- **Curfew enforcement**: A SYSTEM task runs every 5 minutes **10 PM–6 AM** and **logs off** any non‑admin session not on the allow list—even if they were signed in before 10 PM. (We avoided the SMB‑only policy and enforced interactive sessions directly.)   
- **Daily cap**: A per‑user logon task runs a small agent that measures active time using Win32’s `GetLastInputInfo` and **shuts down** the PC after **4 hours** (default).   
- **Prevent new users from logging in**: The script rewrites **“Allow log on locally”** (**SeInteractiveLogonRight**) so **only** Administrators + the specified usernames can sign in. It applies the change via `secedit /configure` with an INF template (fully offline).  
- **Hardening**: Removes **“Change the time zone”** privilege from standard users to stop curfew bypass via TZ shift (admins retain it).  
- **Anti‑tamper**: A SYSTEM watchdog detects if the per‑user agent is killed and **shuts the PC down** in 60s.

---

## Operational tips

- Test first with **one** non‑critical account.  
- You can change the daily cap or curfew by rerunning the installer with new parameters (it overwrites the tasks).  
- To allow another user to sign in later, simply rerun:
  ```powershell
  .\Install-LocalScreenTimePolicy.ps1 -UserNames 'USERNAME','NewKid'
  ```
- To **uninstall** and restore defaults:
  ```powershell
  .\Install-LocalScreenTimePolicy.ps1 -UserNames 'USERNAME' -Uninstall
  ```
  (The `-UserNames` list is only used here to reset their `/times:all`; the rights template we applied is removed.)

