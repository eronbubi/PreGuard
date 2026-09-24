using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PreGuard
{
    static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        // Reads an NTFS alternate data stream such as "Zone.Identifier". Returns null if it does not exist.
        public static string ReadAlternateStream(string path, string stream)
        {
            SafeFileHandle h = CreateFileW(LongPath(path) + ":" + stream, 0x80000000 /* GENERIC_READ */,
                7 /* share read|write|delete */, IntPtr.Zero, 3 /* OPEN_EXISTING */, 0, IntPtr.Zero);
            if (h.IsInvalid) { h.Dispose(); return null; }
            using (var fs = new FileStream(h, FileAccess.Read))
            using (var sr = new StreamReader(fs, true))
                return sr.ReadToEnd();
        }

        static string LongPath(string path)
        {
            if (path.Length < 248 || path.StartsWith(@"\\?\")) return path;
            return path.StartsWith(@"\\") ? @"\\?\UNC\" + path.Substring(2) : @"\\?\" + path;
        }

        // ---- Authenticode (WinVerifyTrust) ----

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        public const uint TRUST_E_NOSIGNATURE = 0x800B0100;
        public const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
        public const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
        public const uint TRUST_E_BAD_DIGEST = 0x80096010;
        public const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
        public const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
        public const uint CERT_E_CHAINING = 0x800B010A;
        public const uint CERT_E_REVOKED = 0x800B010C;
        public const uint CERT_E_EXPIRED = 0x800B0101;

        // Verifies the embedded Authenticode signature offline (no revocation lookups, no network).
        public static uint VerifyAuthenticode(string path)
        {
            var fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fileInfo.pcwszFilePath = path;
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, pFile, false);
            try
            {
                var data = new WINTRUST_DATA();
                data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                data.dwUIChoice = 2;            // WTD_UI_NONE
                data.fdwRevocationChecks = 0;   // WTD_REVOKE_NONE
                data.dwUnionChoice = 1;         // WTD_CHOICE_FILE
                data.pFile = pFile;
                data.dwStateAction = 1;         // WTD_STATEACTION_VERIFY
                data.dwProvFlags = 0x10 | 0x1000; // REVOCATION_CHECK_NONE | CACHE_ONLY_URL_RETRIEVAL
                Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
                uint result = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                data.dwStateAction = 2;         // WTD_STATEACTION_CLOSE
                WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                return result;
            }
            finally
            {
                Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pFile);
            }
        }

        // ---- Known folders / DPI ----

        [DllImport("shell32.dll")]
        static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);

        public static string DownloadsFolder()
        {
            IntPtr p;
            if (SHGetKnownFolderPath(new Guid("374DE290-123F-4565-9164-39C4925E467B"), 0, IntPtr.Zero, out p) == 0)
            {
                string s = Marshal.PtrToStringUni(p);
                Marshal.FreeCoTaskMem(p);
                return s;
            }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }

        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        public static void TrySetDpiAware()
        {
            try { SetProcessDPIAware(); } catch { }
        }
    }
}
