using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;

namespace PreGuard
{
    class DefenderResult
    {
        public bool Ran;
        public bool Threat;
        public string ThreatName;
        public string Message;
        public int ExitCode;
        public long Milliseconds;
    }

    // On-demand scan of a single file with Microsoft Defender's command line scanner.
    // -DisableRemediation reports a threat without letting Defender delete it, so the user decides.
    static class Defender
    {
        static string cachedPath;

        public static string FindScanner()
        {
            if (cachedPath != null) return cachedPath;
            try
            {
                string platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    @"Microsoft\Windows Defender\Platform");
                if (Directory.Exists(platform))
                {
                    var newest = Directory.GetDirectories(platform)
                        .Select(d => new { Dir = d, Ver = ParseVersion(Path.GetFileName(d)) })
                        .Where(x => x.Ver != null && File.Exists(Path.Combine(x.Dir, "MpCmdRun.exe")))
                        .OrderByDescending(x => x.Ver)
                        .FirstOrDefault();
                    if (newest != null) return cachedPath = Path.Combine(newest.Dir, "MpCmdRun.exe");
                }
            }
            catch { }
            string pf = Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string classic = Path.Combine(pf, @"Windows Defender\MpCmdRun.exe");
            return cachedPath = File.Exists(classic) ? classic : null;
        }

        static Version ParseVersion(string s)
        {
            int dash = s.IndexOf('-');
            if (dash > 0) s = s.Substring(0, dash);
            Version v;
            return Version.TryParse(s, out v) ? v : null;
        }

        public static DefenderResult Scan(string path, int timeoutMs)
        {
            var result = new DefenderResult();
            string exe = FindScanner();
            if (exe == null)
            {
                result.Message = "Microsoft Defender ist nicht installiert – kein Virenscan möglich.";
                return result;
            }
            var sw = Stopwatch.StartNew();
            var psi = new ProcessStartInfo(exe, "-Scan -ScanType 3 -File \"" + path + "\" -DisableRemediation");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            var output = new StringBuilder();
            try
            {
                using (var p = new Process())
                {
                    p.StartInfo = psi;
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
                    p.Start();
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch { }
                        result.Message = "Defender-Scan nach " + (timeoutMs / 1000) + " s abgebrochen (Zeitlimit).";
                        result.Milliseconds = sw.ElapsedMilliseconds;
                        return result;
                    }
                    p.WaitForExit();
                    result.ExitCode = p.ExitCode;
                }
            }
            catch (Exception ex)
            {
                result.Message = "Defender-Scan konnte nicht gestartet werden: " + ex.Message;
                return result;
            }
            result.Milliseconds = sw.ElapsedMilliseconds;
            string text;
            lock (output) text = output.ToString();

            if (result.ExitCode == 0)
            {
                result.Ran = true;
                result.Message = "Keine Bedrohung gefunden";
            }
            else if (result.ExitCode == 2)
            {
                result.Ran = true;
                result.Threat = true;
                result.ThreatName = ExtractThreatName(text);
                result.Message = "BEDROHUNG: " + (result.ThreatName ?? "unbekannt");
            }
            else
            {
                string last = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => l.Trim()).LastOrDefault(l => l.Length > 0);
                result.Message = string.Format("Scan nicht möglich (Code 0x{0:X8}){1}", result.ExitCode,
                    last != null ? ": " + last : "");
            }
            return result;
        }

        static string ExtractThreatName(string output)
        {
            // Output lines look like: "Threat                  : Virus:DOS/EICAR_Test_File"
            foreach (string raw in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int colon = raw.IndexOf(':');
                if (colon <= 0) continue;
                if (raw.Substring(0, colon).Trim().Equals("Threat", StringComparison.OrdinalIgnoreCase))
                {
                    string name = raw.Substring(colon + 1).Trim();
                    if (name.Length > 0) return name;
                }
            }
            return null;
        }
    }

    // Defender's detection history is readable without admin rights. Used when real-time protection
    // blocked or removed a download before PreGuard could look at it.
    static class DefenderHistory
    {
        public static string FindThreat(string path, DateTime sinceUtc)
        {
            try
            {
                var scope = new ManagementScope(@"root\Microsoft\Windows\Defender");
                using (var search = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT ThreatID, Resources, InitialDetectionTime FROM MSFT_MpThreatDetection")))
                {
                    foreach (ManagementObject d in search.Get())
                    {
                        var resources = d["Resources"] as string[];
                        if (resources == null || !resources.Any(x => x.IndexOf(path, StringComparison.OrdinalIgnoreCase) >= 0)) continue;
                        var when = ManagementDateTimeConverter.ToDateTime((string)d["InitialDetectionTime"]).ToUniversalTime();
                        if (when < sinceUtc.AddMinutes(-2)) continue;
                        using (var threats = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT ThreatName FROM MSFT_MpThreat WHERE ThreatID = " + d["ThreatID"])))
                            foreach (ManagementObject t in threats.Get())
                                return (string)t["ThreatName"];
                        return "unbekannte Bedrohung";
                    }
                }
            }
            catch { }
            return null;
        }
    }
}