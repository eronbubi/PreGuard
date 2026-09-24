using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace PreGuard
{
    // Watches the file system for finished downloads.
    //
    // Two signals count as "a download just finished":
    //  1. Anywhere in the user profile or on other fixed drives: a browser renames its temporary file
    //     (.crdownload = Chrome/Edge/Brave/Opera, .part = Firefox, .partial = old Edge/IE, .opdownload, .download)
    //     to the final name. Every mainstream browser finishes a download exactly this way.
    //  2. Directly in the Downloads folder: a new file appears and settles (curl, wget, other tools).
    //     Files that carry a Mark of the Web without a HostUrl were copied or extracted, not downloaded, and are skipped.
    class DownloadMonitor : IDisposable
    {
        // path, reason, gone: true when antivirus blocked/removed the file before it could be checked
        public event Action<string, string, bool> DownloadFinished;

        enum Settle { Ready, Vanished, Blocked, Timeout }

        static readonly HashSet<string> BrowserTempExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".crdownload", ".part", ".partial", ".opdownload", ".download" };
        static readonly HashSet<string> IgnoredExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".crdownload", ".part", ".partial", ".opdownload", ".download", ".tmp", ".temp", DownloadCase.HeldSuffix, ".!ut", ".aria2", ".ytdl" };

        class Pending
        {
            public string Path;
            public bool Strong;
            public string Reason;
            public DateTime LastEvent;
            public bool Processing;
            public DateTime StartedAt;
        }

        readonly object gate = new object();
        readonly Dictionary<string, Pending> pending = new Dictionary<string, Pending>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        readonly List<DateTime> downloadsCreates = new List<DateTime>();
        readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        readonly HashSet<string> watchedRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Timer timer;
        string profile, downloads;
        DateTime bulkUntil = DateTime.MinValue;

        public volatile bool Paused;
        public string DownloadsFolder { get { return downloads; } }
        public IEnumerable<string> WatchedRoots { get { lock (gate) return watchedRoots.ToList(); } }

        public void Start()
        {
            profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            downloads = Native.DownloadsFolder();

            // Top-level folders of the profile, recursively (AppData, dot-folders and legacy junctions excluded).
            foreach (string dir in SafeDirectories(profile))
                if (IsWatchableProfileChild(dir)) AddRecursiveRenameWatcher(dir);
            // Files placed directly in the profile root, plus new top-level folders.
            AddProfileRootWatcher();
            // Downloads: also new files that simply appear there.
            if (!IsUnderWatchedRoot(downloads) && Directory.Exists(downloads)) AddRecursiveRenameWatcher(downloads);
            AddDownloadsWatcher();
            // Other fixed drives (D:, E:, …).
            string systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                    if (drive.RootDirectory.FullName.Equals(systemRoot, StringComparison.OrdinalIgnoreCase)) continue;
                    AddRecursiveRenameWatcher(drive.RootDirectory.FullName);
                }
                catch { }
            }
            timer = new Timer(Tick, null, 400, 400);
        }

        static IEnumerable<string> SafeDirectories(string dir)
        {
            try { return Directory.GetDirectories(dir); }
            catch { return new string[0]; }
        }

        static bool IsWatchableProfileChild(string dir)
        {
            string name = Path.GetFileName(dir);
            if (name.StartsWith(".") || name.Equals("AppData", StringComparison.OrdinalIgnoreCase)) return false;
            try
            {
                var attr = File.GetAttributes(dir);
                if ((attr & FileAttributes.ReparsePoint) != 0) return false;
                if ((attr & FileAttributes.Hidden) != 0 && (attr & FileAttributes.System) != 0) return false;
            }
            catch { return false; }
            return true;
        }

        bool IsUnderWatchedRoot(string path)
        {
            lock (gate)
                return watchedRoots.Any(r => path.StartsWith(r.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase) ||
                                             path.Equals(r, StringComparison.OrdinalIgnoreCase));
        }

        void AddRecursiveRenameWatcher(string root)
        {
            try
            {
                var w = new FileSystemWatcher(root);
                w.IncludeSubdirectories = true;
                w.NotifyFilter = NotifyFilters.FileName;
                w.InternalBufferSize = 64 * 1024;
                w.Renamed += (s, e) => OnRenamed(e);
                w.Error += (s, e) => OnWatcherError(w, e);
                w.EnableRaisingEvents = true;
                lock (gate)
                {
                    watchers.Add(w);
                    watchedRoots.Add(root);
                }
            }
            catch (Exception ex)
            {
                AppSettings.Log("WARNUNG", "Ordner kann nicht überwacht werden: " + root + " (" + ex.Message + ")");
            }
        }

        void AddProfileRootWatcher()
        {
            var w = new FileSystemWatcher(profile);
            w.IncludeSubdirectories = false;
            w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName;
            w.Renamed += (s, e) =>
            {
                if (Directory.Exists(e.FullPath)) { MaybeWatchNewProfileDir(e.FullPath); return; }
                OnRenamed(e);
            };
            w.Created += (s, e) => { if (Directory.Exists(e.FullPath)) MaybeWatchNewProfileDir(e.FullPath); };
            w.Error += (s, e) => OnWatcherError(w, e);
            w.EnableRaisingEvents = true;
            lock (gate) watchers.Add(w);
        }

        void MaybeWatchNewProfileDir(string dir)
        {
            if (IsWatchableProfileChild(dir) && !IsUnderWatchedRoot(dir)) AddRecursiveRenameWatcher(dir);
        }

        void AddDownloadsWatcher()
        {
            if (!Directory.Exists(downloads)) return;
            var w = new FileSystemWatcher(downloads);
            w.IncludeSubdirectories = false;
            w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite;
            w.InternalBufferSize = 64 * 1024;
            w.Created += (s, e) => { NoteDownloadsCreate(); OnDownloadsActivity(e.FullPath); };
            w.Changed += (s, e) => OnDownloadsActivity(e.FullPath);
            w.Renamed += (s, e) => { if (!IsOurRename(e)) OnDownloadsActivity(e.FullPath); };
            w.Error += (s, e) => OnWatcherError(w, e);
            w.EnableRaisingEvents = true;
            lock (gate) watchers.Add(w);
        }

        void OnWatcherError(FileSystemWatcher w, ErrorEventArgs e)
        {
            AppSettings.Log("WARNUNG", "Überwachung " + w.Path + ": " + e.GetException().Message);
            try
            {
                w.EnableRaisingEvents = false;
                w.EnableRaisingEvents = true;
            }
            catch { }
        }

        bool IsOurRename(RenamedEventArgs e)
        {
            if (e.OldFullPath.EndsWith(DownloadCase.HeldSuffix, StringComparison.OrdinalIgnoreCase))
            {
                MarkRecent(e.FullPath); // released by the user
                return true;
            }
            return e.FullPath.EndsWith(DownloadCase.HeldSuffix, StringComparison.OrdinalIgnoreCase);
        }

        void OnRenamed(RenamedEventArgs e)
        {
            if (Paused || IsOurRename(e)) return;
            string oldExt = Path.GetExtension(e.OldFullPath);
            if (!BrowserTempExt.Contains(oldExt)) return;
            if (IsIgnoredName(e.FullPath)) return;
            Enqueue(e.FullPath, true, "Browser-Download abgeschlossen (" + oldExt.ToLowerInvariant() + " → fertig)");
        }

        void OnDownloadsActivity(string path)
        {
            if (Paused || IsIgnoredName(path)) return;
            Enqueue(path, false, "Neue Datei im Download-Ordner");
        }

        static bool IsIgnoredName(string path)
        {
            string name = Path.GetFileName(path);
            if (name.Length == 0 || name.StartsWith("~$") || name.StartsWith(".~")) return true;
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) || name.Equals("thumbs.db", StringComparison.OrdinalIgnoreCase)) return true;
            return IgnoredExt.Contains(Path.GetExtension(name));
        }

        void NoteDownloadsCreate()
        {
            lock (gate)
            {
                DateTime now = DateTime.UtcNow;
                downloadsCreates.Add(now);
                downloadsCreates.RemoveAll(t => (now - t).TotalSeconds > 3);
                // Six or more new files within three seconds: an extraction or a copy, not downloads.
                if (downloadsCreates.Count >= 6) bulkUntil = now.AddSeconds(5);
            }
        }

        void MarkRecent(string path)
        {
            lock (gate) recent[path] = DateTime.UtcNow;
        }

        void Enqueue(string path, bool strong, string reason)
        {
            lock (gate)
            {
                DateTime seen;
                if (recent.TryGetValue(path, out seen) && (DateTime.UtcNow - seen).TotalSeconds < 60) return;
                Pending p;
                if (!pending.TryGetValue(path, out p))
                {
                    p = new Pending { Path = path, Reason = reason };
                    pending[path] = p;
                }
                if (strong && !p.Strong) { p.Strong = true; p.Reason = reason; }
                p.LastEvent = DateTime.UtcNow;
            }
        }

        void Tick(object state)
        {
            var due = new List<Pending>();
            lock (gate)
            {
                DateTime now = DateTime.UtcNow;
                foreach (var p in pending.Values)
                    if (!p.Processing && (now - p.LastEvent).TotalMilliseconds >= (p.Strong ? 1200 : 2000))
                    {
                        p.Processing = true;
                        p.StartedAt = now;
                        due.Add(p);
                    }
                foreach (var key in recent.Where(kv => (now - kv.Value).TotalMinutes > 5).Select(kv => kv.Key).ToList())
                    recent.Remove(key);
            }
            foreach (var p in due) ThreadPool.QueueUserWorkItem(_ => Process(p));
        }

        void Process(Pending p)
        {
            try
            {
                if (Paused) return;
                Settle settle = WaitUntilSettled(p.Path, p.Strong ? TimeSpan.FromMinutes(2) : TimeSpan.FromMinutes(30));
                if (settle == Settle.Blocked || (settle == Settle.Vanished && p.Strong))
                {
                    // A finished browser download that vanished or cannot be opened: almost always real-time protection.
                    MarkRecent(p.Path);
                    var gone = DownloadFinished;
                    if (gone != null) gone(p.Path, p.Reason, true);
                    return;
                }
                if (settle != Settle.Ready) return;
                var info = new FileInfo(p.Path);
                if (!info.Exists || info.Length == 0) return;
                if ((info.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == (FileAttributes.Hidden | FileAttributes.System)) return;

                string reason = p.Reason;
                if (!p.Strong)
                {
                    ZoneInfo zone = ZoneInfo.Read(p.Path);
                    if (zone != null && string.IsNullOrEmpty(zone.HostUrl)) return; // extracted/copied, carries only an inherited mark
                    lock (gate) if (DateTime.UtcNow < bulkUntil) return;
                    if (zone != null) reason = "Download im Download-Ordner";
                }
                else
                {
                    // Chrome and Firefox write the Mark of the Web right after the final rename; give it a moment.
                    for (int i = 0; i < 6 && ZoneInfo.Read(p.Path) == null; i++) Thread.Sleep(250);
                }

                MarkRecent(p.Path);
                var handler = DownloadFinished;
                if (handler != null) handler(p.Path, reason, false);
            }
            catch (Exception ex)
            {
                AppSettings.Log("FEHLER", "Verarbeitung " + p.Path + ": " + ex.Message);
            }
            finally
            {
                lock (gate)
                {
                    Pending current;
                    if (pending.TryGetValue(p.Path, out current) && current == p)
                    {
                        // New events arrived while this one was being checked (e.g. Firefox replacing its empty
                        // placeholder with the finished .part file): look again instead of dropping them.
                        bool detected = recent.ContainsKey(p.Path);
                        if (!detected && p.LastEvent > p.StartedAt) p.Processing = false;
                        else pending.Remove(p.Path);
                    }
                }
            }
        }

        // The file is finished when its size stops changing and no other process holds it open for writing.
        static Settle WaitUntilSettled(string path, TimeSpan timeout)
        {
            DateTime end = DateTime.UtcNow + timeout;
            long lastSize = -1;
            while (DateTime.UtcNow < end)
            {
                if (!File.Exists(path)) return Settle.Vanished;
                long size;
                try { size = new FileInfo(path).Length; }
                catch { return Settle.Vanished; }
                if (size == lastSize)
                {
                    Settle open = TryOpenWithoutWriters(path);
                    if (open != Settle.Timeout) return open;
                }
                lastSize = size;
                Thread.Sleep(500);
            }
            return Settle.Timeout;
        }

        // Ready = nobody is writing; Blocked = Windows refuses access because antivirus flagged the file;
        // Timeout = still in use, try again.
        static Settle TryOpenWithoutWriters(string path)
        {
            try
            {
                using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete)) { }
                return Settle.Ready;
            }
            catch (FileNotFoundException) { return Settle.Vanished; }
            catch (IOException ex)
            {
                int code = ex.HResult & 0xFFFF;
                if (code == 225 || code == 226) return Settle.Blocked; // ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED
                return Settle.Timeout;
            }
            catch { return Settle.Timeout; }
        }

        public void Dispose()
        {
            if (timer != null) timer.Dispose();
            lock (gate)
            {
                foreach (var w in watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
                watchers.Clear();
            }
        }
    }
}
