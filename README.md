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
