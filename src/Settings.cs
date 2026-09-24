using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace PreGuard
{
    static class AppSettings
    {
        public static readonly string Dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PreGuard");
        public static readonly string LogFile = Path.Combine(Dir, "protokoll.txt");
        public static readonly string HeldFile = Path.Combine(Dir, "gesperrt.txt");
        static readonly string FirstRunFlag = Path.Combine(Dir, "eingerichtet.flag");
        const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string RunValue = "PreGuard";
        static readonly object logLock = new object();

        public static void EnsureDir()
        {
            Directory.CreateDirectory(Dir);
        }

        // First start ever: switch autostart on, because starting with Windows is the point of the program.
        public static bool ConsumeFirstRun()
        {
            if (File.Exists(FirstRunFlag)) return false;
            File.WriteAllText(FirstRunFlag, DateTime.Now.ToString("s"));
            return true;
        }

        static string AutostartCommand()
        {
            return "\"" + System.Windows.Forms.Application.ExecutablePath + "\" --background";
        }

        public static bool IsAutostartEnabled()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RunKey, false))
                return key != null && key.GetValue(RunValue) != null;
        }

        public static void SetAutostart(bool enabled)
        {
            using (var key = Registry.CurrentUser.CreateSubKey(RunKey))
            {
                if (enabled) key.SetValue(RunValue, AutostartCommand());
                else if (key.GetValue(RunValue) != null) key.DeleteValue(RunValue);
            }
        }

        // Keeps the Run entry pointing at this exe if the program folder was moved.
        public static void RefreshAutostartPath()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RunKey, true))
            {
                if (key == null) return;
                var current = key.GetValue(RunValue) as string;
                if (current != null && current != AutostartCommand()) key.SetValue(RunValue, AutostartCommand());
            }
        }

        public static void Log(string action, string detail)
        {
            try
            {
                lock (logLock)
                {
                    EnsureDir();
                    File.AppendAllText(LogFile, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + action.PadRight(14) + detail + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch { }
        }
    }

    // Files PreGuard has locked away (renamed to *.preguard) and that still wait for a decision.
    // Persisted so a reboot or a closed program never leaves a download stranded.
    static class HeldStore
    {
        static readonly object gate = new object();

        public static List<KeyValuePair<string, string>> Load()
        {
            lock (gate)
            {
                var list = new List<KeyValuePair<string, string>>();
                if (!File.Exists(AppSettings.HeldFile)) return list;
                foreach (string line in File.ReadAllLines(AppSettings.HeldFile, Encoding.UTF8))
                {
                    int sep = line.IndexOf('|');
                    if (sep > 0) list.Add(new KeyValuePair<string, string>(line.Substring(0, sep), line.Substring(sep + 1)));
                }
                return list;
            }
        }

        public static void Add(string heldPath, string originalPath)
        {
            lock (gate)
            {
                var list = Load().Where(kv => !kv.Key.Equals(heldPath, StringComparison.OrdinalIgnoreCase)).ToList();
                list.Add(new KeyValuePair<string, string>(heldPath, originalPath));
                Save(list);
            }
        }

        public static void Remove(string heldPath)
        {
            lock (gate)
            {
                Save(Load().Where(kv => !kv.Key.Equals(heldPath, StringComparison.OrdinalIgnoreCase)).ToList());
            }
        }

        static void Save(List<KeyValuePair<string, string>> list)
        {
            AppSettings.EnsureDir();
            File.WriteAllLines(AppSettings.HeldFile, list.Select(kv => kv.Key + "|" + kv.Value), Encoding.UTF8);
        }
    }

    // One detected download and what happened to it.
    class DownloadCase
    {
        public const string HeldSuffix = ".preguard";
        public string OriginalPath;
        public string HeldPath;
        public string Reason;
        public DateTime DetectedAt = DateTime.Now;
        public Report Report;
        public bool Decided;
        public bool BlockedByAntivirus;

        public bool IsHeld { get { return HeldPath != null; } }
        public string CurrentPath { get { return HeldPath ?? OriginalPath; } }
        public string DisplayName { get { return Path.GetFileName(OriginalPath); } }

        // Renames the file to "<name>.preguard" so it cannot be opened or started until the user decides.
        // Retries because the browser or Defender can still hold a handle for a moment after the download finished.
        public bool Hold(out string error)
        {
            error = null;
            for (int attempt = 0; attempt < 80; attempt++)
            {
                if (!File.Exists(OriginalPath)) { error = "Datei nicht mehr vorhanden"; return false; }
                string target = UniquePath(OriginalPath + HeldSuffix);
                try
                {
                    File.Move(OriginalPath, target);
                    HeldPath = target;
                    HeldStore.Add(HeldPath, OriginalPath);
                    return true;
                }
                catch (IOException ex)
                {
                    error = ex.Message;
                    int code = ex.HResult & 0xFFFF;
                    if (code == 225 || code == 226) { BlockedByAntivirus = true; return false; }
                    Thread.Sleep(250);
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    Thread.Sleep(250);
                }
            }
            return false;
        }

        // Puts the file back under its original name (or "name (1).ext" if that name was taken meanwhile).
        public string Release()
        {
            if (!IsHeld) return OriginalPath;
            string target = UniquePath(OriginalPath);
            File.Move(HeldPath, target);
            HeldStore.Remove(HeldPath);
            HeldPath = null;
            OriginalPath = target;
            Decided = true;
            return target;
        }

        public void Terminate()
        {
            string path = CurrentPath;
            Exception last = null;
            for (int attempt = 0; attempt < 20; attempt++)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        File.SetAttributes(path, FileAttributes.Normal);
                        File.Delete(path);
                    }
                    last = null;
                    break;
                }
                catch (Exception ex)
                {
                    last = ex;
                    Thread.Sleep(250);
                }
            }
            if (last != null) throw last;
            if (IsHeld) HeldStore.Remove(HeldPath);
            Decided = true;
        }

        static string UniquePath(string path)
        {
            if (!File.Exists(path) && !Directory.Exists(path)) return path;
            string dir = Path.GetDirectoryName(path);
            string name = path.EndsWith(HeldSuffix) ? Path.GetFileName(path.Substring(0, path.Length - HeldSuffix.Length)) : Path.GetFileName(path);
            string suffix = path.EndsWith(HeldSuffix) ? HeldSuffix : "";
            string stem = Path.GetFileNameWithoutExtension(name), ext = Path.GetExtension(name);
            for (int i = 1; ; i++)
            {
                string candidate = Path.Combine(dir, stem + " (" + i + ")" + ext + suffix);
                if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
            }
        }
    }
}
