using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace PreGuard
{
    enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }
    enum Verdict { Clean = 0, Caution = 1, HighRisk = 2, Threat = 3, Missing = 4 }

    enum FileKind
    {
        Unknown, Pe, DosMz, Zip, Rar, SevenZip, Gzip, Cab, Pdf, Ole, Lnk, Iso, Vhd, Vhdx,
        Png, Jpeg, Gif, Webp, Bmp, Mp4, Mkv, Mp3, Ogg, Wav, Flac, Rtf, Html, Svg, Xml, Text, Elf
    }

    class Finding
    {
        public Severity Severity;
        public string Text;
        public Finding(Severity s, string t) { Severity = s; Text = t; }
    }

    class ZoneInfo
    {
        public int ZoneId = -1;
        public string HostUrl, ReferrerUrl;

        public static ZoneInfo Read(string path)
        {
            string raw;
            try { raw = Native.ReadAlternateStream(path, "Zone.Identifier"); }
            catch { return null; }
            if (raw == null) return null;
            var z = new ZoneInfo();
            foreach (string line in raw.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line.Substring(0, eq).Trim(), val = line.Substring(eq + 1).Trim();
                if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase)) int.TryParse(val, out z.ZoneId);
                else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) z.HostUrl = val;
                else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) z.ReferrerUrl = val;
            }
            return z;
        }

        public string ZoneName()
        {
            switch (ZoneId)
            {
                case 0: return "Lokaler Computer";
                case 1: return "Lokales Intranet";
                case 2: return "Vertrauenswürdige Sites";
                case 3: return "Internet";
                case 4: return "Eingeschränkte Sites";
                default: return "unbekannt";
            }
        }
    }

    class Report
    {
        public string FilePath, DisplayName, Extension;
        public string DetectedType = "unbekannt";
        public string Sha256 = "";
        public long Size;
        public ZoneInfo Zone;
        public string Signature = "nicht zutreffend";
        public bool SignedValid;
        public DefenderResult Defender;
        public FileKind Kind;
        public readonly List<Finding> Findings = new List<Finding>();
        public readonly List<KeyValuePair<string, string>> Details = new List<KeyValuePair<string, string>>();
        public int Score;
        public Verdict Verdict;
        public long AnalysisMs;

        public void Add(Severity s, string text) { Findings.Add(new Finding(s, text)); }
        public void Detail(string key, string value) { Details.Add(new KeyValuePair<string, string>(key, value)); }

        public static string VerdictLabel(Verdict v)
        {
            switch (v)
            {
                case Verdict.Clean: return "UNAUFFÄLLIG";
                case Verdict.Caution: return "VORSICHT";
                case Verdict.HighRisk: return "HOHES RISIKO";
                case Verdict.Threat: return "BEDROHUNG ERKANNT";
                default: return "DATEI ENTFERNT";
            }
        }

        public static string SeverityLabel(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return "KRITISCH";
                case Severity.High: return "HOCH";
                case Severity.Medium: return "MITTEL";
                case Severity.Low: return "NIEDRIG";
                default: return "INFO";
            }
        }

        public IEnumerable<Finding> SortedFindings()
        {
            return Findings.OrderByDescending(f => f.Severity);
        }

        public string ToText()
        {
            var sb = new StringBuilder();
            sb.AppendLine("PreGuard-Bericht: " + DisplayName);
            sb.AppendLine("Ergebnis: " + VerdictLabel(Verdict) + " (Risikopunkte " + Score + ")");
            sb.AppendLine("Befunde:");
            foreach (var f in SortedFindings())
                sb.AppendLine("  [" + SeverityLabel(f.Severity) + "] " + f.Text);
            sb.AppendLine("Details:");
            foreach (var kv in Details)
                sb.AppendLine("  " + kv.Key + ": " + kv.Value);
            return sb.ToString();
        }
    }

    static class Analyzer
    {
        static readonly HashSet<string> ProgramExt = Set(".exe", ".scr", ".com", ".pif", ".cpl", ".dll", ".sys", ".ocx",
            ".msi", ".msp", ".msix", ".msixbundle", ".appx", ".appxbundle", ".xll", ".efi", ".drv");
        static readonly HashSet<string> ScriptExt = Set(".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".wsh", ".hta", ".reg", ".inf", ".scf", ".chm", ".jar", ".appinstaller", ".settingcontent-ms",
            ".library-ms", ".search-ms", ".iqy", ".slk", ".url", ".lnk", ".application", ".gadget", ".msc", ".cab", ".diagcab");
        static readonly HashSet<string> RareScriptExt = Set(".hta", ".vbe", ".jse", ".wsf", ".wsh", ".scf",
            ".settingcontent-ms", ".iqy", ".slk", ".gadget", ".pif", ".scr", ".diagcab");
        static readonly HashSet<string> SignableExt = Set(".exe", ".scr", ".com", ".cpl", ".dll", ".sys", ".ocx", ".msi",
            ".msp", ".msix", ".msixbundle", ".appx", ".appxbundle", ".ps1", ".psm1", ".psd1", ".vbs", ".js", ".wsf", ".cab",
            ".xll", ".efi", ".drv", ".cat", ".appinstaller");
        static readonly HashSet<string> PeExt = Set(".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".efi", ".mui",
            ".node", ".pyd", ".drv", ".ax", ".winmd", ".xll", ".tlb", ".acm", ".tsp", ".mun");
        static readonly HashSet<string> DiskImageExt = Set(".iso", ".img", ".vhd", ".vhdx");
        static readonly HashSet<string> MacroExt = Set(".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm", ".ppam", ".sldm");
        static readonly HashSet<string> OoxmlExt = Set(".docx", ".dotx", ".xlsx", ".xltx", ".pptx", ".potx", ".ppsx",
            ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm", ".ppam", ".sldm");
        static readonly HashSet<string> AppPackageExt = Set(".jar", ".apk", ".msix", ".appx", ".msixbundle", ".appxbundle",
            ".nupkg", ".vsix", ".xpi", ".crx", ".whl", ".mrpack", ".aab", ".ipa");
        static readonly HashSet<string> ArchiveExt = Set(".zip", ".rar", ".7z", ".gz", ".tgz", ".bz2", ".xz", ".tar", ".cab", ".zst");

        static HashSet<string> Set(params string[] items)
        {
            return new HashSet<string>(items, StringComparer.OrdinalIgnoreCase);
        }

        static readonly Dictionary<string, FileKind> ExpectedKind = new Dictionary<string, FileKind>(StringComparer.OrdinalIgnoreCase)
        {
            { ".pdf", FileKind.Pdf }, { ".png", FileKind.Png }, { ".jpg", FileKind.Jpeg }, { ".jpeg", FileKind.Jpeg },
            { ".gif", FileKind.Gif }, { ".webp", FileKind.Webp }, { ".bmp", FileKind.Bmp }, { ".zip", FileKind.Zip },
            { ".rar", FileKind.Rar }, { ".7z", FileKind.SevenZip }, { ".gz", FileKind.Gzip }, { ".tgz", FileKind.Gzip },
            { ".doc", FileKind.Ole }, { ".xls", FileKind.Ole }, { ".ppt", FileKind.Ole }, { ".msi", FileKind.Ole },
            { ".docx", FileKind.Zip }, { ".xlsx", FileKind.Zip }, { ".pptx", FileKind.Zip }, { ".docm", FileKind.Zip },
            { ".xlsm", FileKind.Zip }, { ".pptm", FileKind.Zip }, { ".jar", FileKind.Zip }, { ".apk", FileKind.Zip },
            { ".mp4", FileKind.Mp4 }, { ".mov", FileKind.Mp4 }, { ".m4a", FileKind.Mp4 }, { ".mkv", FileKind.Mkv },
            { ".webm", FileKind.Mkv }, { ".mp3", FileKind.Mp3 }, { ".ogg", FileKind.Ogg }, { ".wav", FileKind.Wav },
            { ".flac", FileKind.Flac }, { ".rtf", FileKind.Rtf }, { ".lnk", FileKind.Lnk }, { ".iso", FileKind.Iso },
            { ".vhdx", FileKind.Vhdx }, { ".cab", FileKind.Cab },
        };

        static readonly HashSet<FileKind> PassiveKinds = new HashSet<FileKind>
        {
            FileKind.Png, FileKind.Jpeg, FileKind.Gif, FileKind.Webp, FileKind.Bmp, FileKind.Mp4, FileKind.Mkv,
            FileKind.Mp3, FileKind.Ogg, FileKind.Wav, FileKind.Flac
        };

        public static Report Analyze(string path, string displayName, bool runDefender, Action<string> progress)
        {
            var sw = Stopwatch.StartNew();
            var r = new Report();
            r.FilePath = path;
            r.DisplayName = displayName ?? Path.GetFileName(path);
            r.Extension = Path.GetExtension(r.DisplayName.TrimEnd(' ', '.')).ToLowerInvariant();

            if (!File.Exists(path))
            {
                r.Verdict = Verdict.Missing;
                r.Add(Severity.Info, "Die Datei ist nicht mehr vorhanden – vermutlich hat Windows Defender oder der Browser sie bereits entfernt.");
                return r;
            }

            r.Size = new FileInfo(path).Length;
            r.Detail("Datei", r.DisplayName);
            r.Detail("Speicherort", Path.GetDirectoryName(path));
            r.Detail("Größe", FormatSize(r.Size));

            Step(progress, "Herkunft wird gelesen …");
            r.Zone = ZoneInfo.Read(path);
            CheckOrigin(r);

            CheckName(r);

            Step(progress, "Dateityp wird bestimmt …");
            byte[] head = ReadBytes(path, 0, 64 * 1024);
            r.Kind = DetectKind(path, head, r.Size);
            r.DetectedType = KindName(r.Kind);
            r.Detail("Erkannter Typ", r.DetectedType + (r.Extension.Length > 0 ? " (Endung " + r.Extension + ")" : " (ohne Endung)"));
            CheckTypeMismatch(r);
            CheckExtensionRisk(r);

            Step(progress, "Inhalt wird untersucht …");
            try
            {
                switch (r.Kind)
                {
                    case FileKind.Pe: AnalyzePe(path, r); break;
                    case FileKind.Zip: AnalyzeZip(path, r); break;
                    case FileKind.Ole: AnalyzeOle(path, r); break;
                    case FileKind.Pdf: AnalyzePdf(path, r); break;
                    case FileKind.Lnk: AnalyzeLnk(head, r); break;
                    case FileKind.Rar:
                    case FileKind.SevenZip:
                        r.Add(Severity.Info, "Archivinhalt (" + r.DetectedType + ") wird nur von Windows Defender geprüft, nicht von PreGuard aufgelistet.");
                        break;
                }
                if (r.Kind == FileKind.Html || r.Kind == FileKind.Svg || r.Kind == FileKind.Text || r.Kind == FileKind.Xml ||
                    ScriptExt.Contains(r.Extension))
                    AnalyzeText(path, r);
            }
            catch (Exception ex)
            {
                r.Add(Severity.Low, "Inhaltsanalyse unvollständig: " + ex.Message);
            }

            if (SignableExt.Contains(r.Extension) || r.Kind == FileKind.Pe)
            {
                Step(progress, "Digitale Signatur wird geprüft …");
                CheckSignature(r);
            }

            Step(progress, "Prüfsumme wird berechnet …");
            r.Sha256 = Sha256(path);
            r.Detail("SHA-256", r.Sha256);

            if (runDefender)
            {
                Step(progress, "Windows Defender scannt …");
                r.Defender = Defender.Scan(path, 180000);
                r.Detail("Windows Defender", r.Defender.Message + (r.Defender.Ran ? " (" + r.Defender.Milliseconds + " ms)" : ""));
                if (r.Defender.Threat)
                    r.Add(Severity.Critical, "Windows Defender hat eine Bedrohung erkannt: " + (r.Defender.ThreatName ?? "unbekannt"));
                else if (!r.Defender.Ran)
                    r.Add(Severity.Low, "Virenscan nicht durchgeführt: " + r.Defender.Message);
                else if (!File.Exists(path))
                    r.Add(Severity.Critical, "Die Datei wurde während der Prüfung entfernt (vermutlich von Windows Defender).");
            }

            Score(r);
            r.AnalysisMs = sw.ElapsedMilliseconds;
            return r;
        }

        // For downloads that real-time protection blocked or removed before PreGuard could read them.
        public static Report RemovedReport(string path, string displayName, bool blocked, DateTime detectedUtc)
        {
            var r = new Report { FilePath = path, DisplayName = displayName ?? Path.GetFileName(path) };
            r.Extension = Path.GetExtension(r.DisplayName).ToLowerInvariant();
            r.Detail("Datei", r.DisplayName);
            r.Detail("Speicherort", Path.GetDirectoryName(path));
            string threat = null;
            for (int i = 0; i < 12 && threat == null; i++)
            {
                threat = DefenderHistory.FindThreat(path, detectedUtc);
                if (threat == null) System.Threading.Thread.Sleep(1000);
            }
            if (threat != null)
            {
                r.Verdict = Verdict.Threat;
                r.Add(Severity.Critical, "Windows Defender hat die Datei als „" + threat + "“ erkannt und " + (File.Exists(path) ? "blockiert" : "entfernt") + ".");
                r.Detail("Windows Defender", threat);
            }
            else if (blocked)
            {
                r.Verdict = Verdict.Threat;
                r.Add(Severity.Critical, "Windows blockiert den Zugriff auf die Datei, weil der Virenschutz sie als Schadsoftware einstuft.");
            }
            else
            {
                r.Verdict = Verdict.Missing;
                r.Add(Severity.Info, "Die Datei wurde gelöscht, bevor PreGuard sie prüfen konnte (vom Browser oder einem anderen Programm). Windows Defender hat dazu keinen Eintrag.");
            }
            r.Score = r.Verdict == Verdict.Threat ? 100 : 0;
            return r;
        }

        static void Step(Action<string> progress, string text)
        {
            if (progress != null) progress(text);
        }

        static void Score(Report r)
        {
            int score = 0;
            foreach (var f in r.Findings)
            {
                switch (f.Severity)
                {
                    case Severity.Low: score += 10; break;
                    case Severity.Medium: score += 25; break;
                    case Severity.High: score += 60; break;
                    case Severity.Critical: score += 100; break;
                }
            }
            r.Score = score;
            if (r.Defender != null && r.Defender.Threat) r.Verdict = Verdict.Threat;
            else if (r.Findings.Any(f => f.Severity == Severity.Critical)) r.Verdict = Verdict.Threat;
            else if (score >= 60) r.Verdict = Verdict.HighRisk;
            else if (score >= 25) r.Verdict = Verdict.Caution;
            else r.Verdict = Verdict.Clean;
        }

        // ---------------- origin (Mark of the Web) ----------------

        static void CheckOrigin(Report r)
        {
            var z = r.Zone;
            if (z == null)
            {
                r.Detail("Herkunft", "keine Herkunftsangabe (Mark of the Web fehlt)");
                return;
            }
            r.Detail("Zone", z.ZoneName() + (z.ZoneId >= 0 ? " (ZoneId " + z.ZoneId + ")" : ""));
            if (!string.IsNullOrEmpty(z.HostUrl)) r.Detail("Quelle", Shorten(z.HostUrl, 180));
            if (!string.IsNullOrEmpty(z.ReferrerUrl)) r.Detail("Aufgerufen von", Shorten(z.ReferrerUrl, 180));

            string url = z.HostUrl ?? "";
            if (url.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            {
                r.Detail("Herkunft", "vom Browser aus einer lokalen Datei erzeugt (file://)");
                return;
            }
            if (z.ZoneId == 4)
                r.Add(Severity.Medium, "Quelle ist in Windows als „Eingeschränkte Site“ eingestuft.");

            if (url.StartsWith("blob:", StringComparison.OrdinalIgnoreCase) || url.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
                url.Equals("about:internet", StringComparison.OrdinalIgnoreCase))
            {
                r.Add(Severity.Medium, "Die Datei wurde von einer Webseite per Skript erzeugt (" + url.Split(':')[0] +
                    "-Download) – typisch für HTML-Smuggling, echte Server-Adresse unbekannt.");
                return;
            }
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri)) return;
            if (uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback)
                r.Add(Severity.Low, "Über unverschlüsseltes HTTP geladen – die Datei könnte unterwegs verändert worden sein.");
            if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
            {
                if (!uri.IsLoopback) r.Add(Severity.Low, "Quelle ist eine nackte IP-Adresse (" + uri.Host + ") statt eines Domainnamens.");
            }
        }

        // ---------------- file name tricks ----------------

        static readonly Regex DoubleExt = new Regex(
            @"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif|bmp|webp|mp3|mp4|avi|mov|mkv|wav|zip|rar|7z|html?)(\s|_)*\.([a-z0-9-]+)$",
            RegexOptions.IgnoreCase);

        static void CheckName(Report r)
        {
            string name = r.DisplayName;
            if (name.IndexOfAny(new[] { '‮', '‭', '‪', '‫', '⁦', '⁧', '⁨', '⁩', '‏' }) >= 0)
                r.Add(Severity.High, "Der Dateiname enthält unsichtbare Unicode-Steuerzeichen, die die angezeigte Endung verdrehen (RTLO-Trick).");

            var m = DoubleExt.Match(name);
            if (m.Success)
            {
                string real = "." + m.Groups[3].Value.ToLowerInvariant();
                if (ProgramExt.Contains(real) || ScriptExt.Contains(real))
                    r.Add(Severity.High, "Doppelte Endung: sieht aus wie „." + m.Groups[1].Value + "“, ist aber „" + real + "“ – klassische Tarnung.");
            }
            if (Regex.IsMatch(name, @"\s{6,}\.[A-Za-z0-9]+$") || Regex.IsMatch(name, @"[ _]{12,}"))
                r.Add(Severity.Medium, "Auffällig viele Leerzeichen im Namen – damit wird die echte Endung oft aus dem Sichtfeld geschoben.");
        }

        // ---------------- type ----------------

        static FileKind DetectKind(string path, byte[] h, long size)
        {
            if (h.Length >= 2 && h[0] == 'M' && h[1] == 'Z') return IsPe(h) ? FileKind.Pe : FileKind.DosMz;
            if (StartsWith(h, 0, 0x50, 0x4B, 0x03, 0x04) || StartsWith(h, 0, 0x50, 0x4B, 0x05, 0x06) || StartsWith(h, 0, 0x50, 0x4B, 0x07, 0x08)) return FileKind.Zip;
            if (StartsWith(h, 0, 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07)) return FileKind.Rar;
            if (StartsWith(h, 0, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)) return FileKind.SevenZip;
            if (StartsWith(h, 0, 0x1F, 0x8B)) return FileKind.Gzip;
            if (StartsWith(h, 0, 0x4D, 0x53, 0x43, 0x46)) return FileKind.Cab;
            if (StartsWith(h, 0, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)) return FileKind.Ole;
            if (StartsWith(h, 0, 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00)) return FileKind.Lnk;
            if (StartsWith(h, 0, 0x89, 0x50, 0x4E, 0x47)) return FileKind.Png;
            if (StartsWith(h, 0, 0xFF, 0xD8, 0xFF)) return FileKind.Jpeg;
            if (StartsWith(h, 0, 0x47, 0x49, 0x46, 0x38)) return FileKind.Gif;
            if (StartsWith(h, 0, 0x42, 0x4D) && size > 26) return FileKind.Bmp;
            if (StartsWith(h, 0, 0x52, 0x49, 0x46, 0x46) && StartsWith(h, 8, 0x57, 0x45, 0x42, 0x50)) return FileKind.Webp;
            if (StartsWith(h, 0, 0x52, 0x49, 0x46, 0x46) && StartsWith(h, 8, 0x57, 0x41, 0x56, 0x45)) return FileKind.Wav;
            if (StartsWith(h, 4, 0x66, 0x74, 0x79, 0x70)) return FileKind.Mp4;
            if (StartsWith(h, 0, 0x1A, 0x45, 0xDF, 0xA3)) return FileKind.Mkv;
            if (StartsWith(h, 0, 0x49, 0x44, 0x33) || StartsWith(h, 0, 0xFF, 0xFB) || StartsWith(h, 0, 0xFF, 0xF3)) return FileKind.Mp3;
            if (StartsWith(h, 0, 0x4F, 0x67, 0x67, 0x53)) return FileKind.Ogg;
            if (StartsWith(h, 0, 0x66, 0x4C, 0x61, 0x43)) return FileKind.Flac;
            if (StartsWith(h, 0, 0x7B, 0x5C, 0x72, 0x74, 0x66)) return FileKind.Rtf;
            if (StartsWith(h, 0, 0x7F, 0x45, 0x4C, 0x46)) return FileKind.Elf;
            if (StartsWith(h, 0, 0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65)) return FileKind.Vhdx;
            if (StartsWith(h, 0, 0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78)) return FileKind.Vhd;
            if (IndexOf(h, Encoding.ASCII.GetBytes("%PDF-"), 0, Math.Min(h.Length, 1024)) >= 0) return FileKind.Pdf;
            if (size > 0x8006)
            {
                byte[] iso = ReadBytes(path, 0x8001, 5);
                if (iso.Length == 5 && Encoding.ASCII.GetString(iso) == "CD001") return FileKind.Iso;
            }
            if (size >= 512)
            {
                byte[] tail = ReadBytes(path, size - 512, 8);
                if (tail.Length == 8 && Encoding.ASCII.GetString(tail) == "conectix") return FileKind.Vhd;
            }
            if (LooksLikeText(h))
            {
                string t = DecodeText(h).TrimStart('﻿', ' ', '\t', '\r', '\n').ToLowerInvariant();
                string start = t.Length > 2048 ? t.Substring(0, 2048) : t;
                if (start.StartsWith("<!doctype html") || start.Contains("<html") || start.Contains("<head") ||
                    start.Contains("<body") || start.StartsWith("<script")) return FileKind.Html;
                if (start.StartsWith("<svg") || (start.StartsWith("<?xml") || start.StartsWith("<!doctype svg")) && start.Contains("<svg"))
                    return FileKind.Svg;
                if (start.StartsWith("<?xml")) return FileKind.Xml;
                return FileKind.Text;
            }
            return FileKind.Unknown;
        }

        static bool IsPe(byte[] h)
        {
            if (h.Length < 0x40) return false;
            int lfanew = BitConverter.ToInt32(h, 0x3C);
            return lfanew > 0 && lfanew + 4 <= h.Length && h[lfanew] == 'P' && h[lfanew + 1] == 'E' && h[lfanew + 2] == 0 && h[lfanew + 3] == 0;
        }

        static string KindName(FileKind k)
        {
            switch (k)
            {
                case FileKind.Pe: return "Windows-Programm (PE)";
                case FileKind.DosMz: return "DOS-Programm (MZ)";
                case FileKind.Zip: return "ZIP-Archiv";
                case FileKind.Rar: return "RAR-Archiv";
                case FileKind.SevenZip: return "7-Zip-Archiv";
                case FileKind.Gzip: return "GZIP-Archiv";
                case FileKind.Cab: return "CAB-Archiv";
                case FileKind.Pdf: return "PDF-Dokument";
                case FileKind.Ole: return "OLE-Dokument (Office 97–2003 / MSI)";
                case FileKind.Lnk: return "Windows-Verknüpfung (LNK)";
                case FileKind.Iso: return "ISO-Datenträgerabbild";
                case FileKind.Vhd: return "VHD-Festplattenabbild";
                case FileKind.Vhdx: return "VHDX-Festplattenabbild";
                case FileKind.Png: return "PNG-Bild";
                case FileKind.Jpeg: return "JPEG-Bild";
                case FileKind.Gif: return "GIF-Bild";
                case FileKind.Webp: return "WebP-Bild";
                case FileKind.Bmp: return "BMP-Bild";
                case FileKind.Mp4: return "MP4/MOV-Video";
                case FileKind.Mkv: return "Matroska/WebM-Video";
                case FileKind.Mp3: return "MP3-Audio";
                case FileKind.Ogg: return "Ogg-Audio";
                case FileKind.Wav: return "WAV-Audio";
                case FileKind.Flac: return "FLAC-Audio";
                case FileKind.Rtf: return "RTF-Dokument";
                case FileKind.Html: return "HTML-Seite";
                case FileKind.Svg: return "SVG-Grafik";
                case FileKind.Xml: return "XML-Text";
                case FileKind.Text: return "Text";
                case FileKind.Elf: return "Linux-Programm (ELF)";
                default: return "unbekanntes Binärformat";
            }
        }

        static void CheckTypeMismatch(Report r)
        {
            string ext = r.Extension;
            if (r.Kind == FileKind.Pe || r.Kind == FileKind.DosMz)
            {
                if (ext.Length == 0)
                    r.Add(Severity.Medium, "Windows-Programm ohne Dateiendung.");
                else if (!PeExt.Contains(ext))
                    r.Add(Severity.High, "Die Datei ist in Wahrheit ein Windows-Programm, trägt aber die Endung „" + ext + "“ (Tarnung).");
                return;
            }
            FileKind expected;
            if (!ExpectedKind.TryGetValue(ext, out expected) || expected == r.Kind) return;
            if (r.Kind == FileKind.Unknown)
            {
                if (r.Size > 0) r.Add(Severity.Low, "Der Inhalt ist nicht als „" + ext + "“ erkennbar.");
                return;
            }
            if (PassiveKinds.Contains(expected) && PassiveKinds.Contains(r.Kind))
            {
                r.Add(Severity.Info, "Endung „" + ext + "“, Inhalt ist aber " + KindName(r.Kind) + " (harmlos, nur falsch benannt).");
                return;
            }
            if ((r.Kind == FileKind.Html || r.Kind == FileKind.Svg) && !PassiveKinds.Contains(expected) && expected != FileKind.Pdf)
            {
                r.Add(Severity.Medium, "Endung „" + ext + "“, Inhalt ist aber " + KindName(r.Kind) + ".");
                return;
            }
            r.Add(r.Kind == FileKind.Html || r.Kind == FileKind.Svg ? Severity.High : Severity.Medium,
                "Endung „" + ext + "“ passt nicht zum Inhalt (" + KindName(r.Kind) + ").");
        }

        static void CheckExtensionRisk(Report r)
        {
            string ext = r.Extension;
            if (ProgramExt.Contains(ext))
            {
                if (ext == ".scr" || ext == ".pif" || ext == ".com")
                    r.Add(Severity.High, "Endung „" + ext + "“ wird heute fast nur noch von Schadsoftware verwendet.");
                else
                    r.Add(Severity.Low, "Ausführbares Programm – wird beim Öffnen direkt gestartet.");
            }
            else if (RareScriptExt.Contains(ext))
                r.Add(Severity.High, "Skripttyp „" + ext + "“ – wird kaum legitim verteilt, aber gern für Angriffe genutzt.");
            else if (ext == ".lnk")
                r.Add(Severity.Medium, "Heruntergeladene Verknüpfung (.lnk) – kann beliebige Befehle starten.");
            else if (ext == ".url")
                r.Add(Severity.Low, "Internetverknüpfung (.url).");
            else if (ext == ".jar")
                r.Add(Severity.Low, "Java-Programm (.jar) – wird mit Java ausgeführt, falls installiert.");
            else if (ext == ".cab")
                r.Add(Severity.Info, "CAB-Archiv.");
            else if (ScriptExt.Contains(ext))
                r.Add(Severity.Medium, "Skript/Befehlsdatei („" + ext + "“) – kann beim Doppelklick ohne Rückfrage Befehle ausführen.");
            else if (DiskImageExt.Contains(ext))
                r.Add(Severity.Low, "Datenträgerabbild – der Inhalt wird beim Einbinden als eigenes Laufwerk sichtbar und hier nicht einzeln geprüft.");
            else if (MacroExt.Contains(ext))
                r.Add(Severity.Medium, "Office-Dokument mit Makro-Unterstützung („" + ext + "“).");
        }

        // ---------------- signature ----------------

        static void CheckSignature(Report r)
        {
            uint res;
            try { res = Native.VerifyAuthenticode(r.FilePath); }
            catch (Exception ex) { r.Signature = "Prüfung fehlgeschlagen: " + ex.Message; r.Detail("Signatur", r.Signature); return; }

            bool isProgram = r.Kind == FileKind.Pe || ProgramExt.Contains(r.Extension);
            string signer = SignerName(r.FilePath);
            switch (res)
            {
                case 0:
                    r.SignedValid = true;
                    r.Signature = "gültig – " + (signer ?? "Herausgeber unbekannt");
                    r.Add(Severity.Info, "Gültig digital signiert von: " + (signer ?? "unbekannt"));
                    break;
                case Native.TRUST_E_NOSIGNATURE:
                    r.Signature = "keine digitale Signatur";
                    if (isProgram) r.Add(Severity.Medium, "Das Programm ist nicht digital signiert – der Herausgeber ist nicht überprüfbar.");
                    break;
                case Native.TRUST_E_SUBJECT_FORM_UNKNOWN:
                case Native.TRUST_E_PROVIDER_UNKNOWN:
                    r.Signature = "für diesen Dateityp nicht prüfbar";
                    break;
                case Native.TRUST_E_BAD_DIGEST:
                    r.Signature = "BESCHÄDIGT – Datei wurde nach dem Signieren verändert";
                    r.Add(Severity.High, "Die Signatur passt nicht zum Inhalt: die Datei wurde nach dem Signieren verändert." + (signer != null ? " (Angeblich: " + signer + ")" : ""));
                    break;
                case Native.TRUST_E_EXPLICIT_DISTRUST:
                case Native.CERT_E_REVOKED:
                    r.Signature = "Zertifikat gesperrt/misstraut" + (signer != null ? " – " + signer : "");
                    r.Add(Severity.High, "Das Signaturzertifikat ist von Windows als nicht vertrauenswürdig markiert." + (signer != null ? " (" + signer + ")" : ""));
                    break;
                case Native.CERT_E_UNTRUSTEDROOT:
                case Native.CERT_E_CHAINING:
                    r.Signature = "nicht vertrauenswürdig (selbst ausgestellt/unbekannte Stelle)" + (signer != null ? " – " + signer : "");
                    r.Add(Severity.Medium, "Signiert, aber von keiner vertrauenswürdigen Zertifizierungsstelle." + (signer != null ? " (" + signer + ")" : ""));
                    break;
                case Native.CERT_E_EXPIRED:
                    r.Signature = "Zertifikat abgelaufen (ohne Zeitstempel)" + (signer != null ? " – " + signer : "");
                    r.Add(Severity.Low, "Das Signaturzertifikat ist abgelaufen und die Signatur hat keinen Zeitstempel.");
                    break;
                default:
                    r.Signature = string.Format("nicht bestätigt (0x{0:X8})", res) + (signer != null ? " – " + signer : "");
                    if (isProgram) r.Add(Severity.Medium, string.Format("Die Signatur konnte nicht bestätigt werden (Fehler 0x{0:X8}).", res));
                    break;
            }
            r.Detail("Signatur", r.Signature);
        }

        static string SignerName(string path)
        {
            try
            {
                var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
                string n = cert.GetNameInfo(X509NameType.SimpleName, false);
                return string.IsNullOrEmpty(n) ? cert.Subject : n;
            }
            catch { return null; }
        }

        // ---------------- PE ----------------

        static void AnalyzePe(string path, Report r)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var br = new BinaryReader(fs);
                fs.Position = 0x3C;
                int lfanew = br.ReadInt32();
                fs.Position = lfanew + 4;
                ushort machine = br.ReadUInt16();
                ushort nSections = br.ReadUInt16();
                uint timestamp = br.ReadUInt32();
                br.ReadUInt32(); br.ReadUInt32();
                ushort optSize = br.ReadUInt16();
                ushort characteristics = br.ReadUInt16();
                long optStart = fs.Position;
                ushort magic = br.ReadUInt16();
                bool pe64 = magic == 0x20B;
                fs.Position = optStart + 68;
                ushort subsystem = br.ReadUInt16();
                fs.Position = optStart + (pe64 ? 108 : 92);
                uint nDirs = br.ReadUInt32();
                long dirStart = fs.Position;
                uint certOffset = 0, certSize = 0, clrRva = 0;
                if (nDirs > 4) { fs.Position = dirStart + 4 * 8; certOffset = br.ReadUInt32(); certSize = br.ReadUInt32(); }
                if (nDirs > 14) { fs.Position = dirStart + 14 * 8; clrRva = br.ReadUInt32(); }

                string arch;
                switch (machine)
                {
                    case 0x14C: arch = "32-Bit (x86)"; break;
                    case 0x8664: arch = "64-Bit (x64)"; break;
                    case 0xAA64: arch = "ARM64"; break;
                    case 0x1C4: arch = "ARM"; break;
                    default: arch = string.Format("Maschine 0x{0:X4}", machine); break;
                }
                string kind = (characteristics & 0x2000) != 0 ? "DLL" : subsystem == 3 ? "Konsolenprogramm" : subsystem == 2 ? "Fensterprogramm" : "Subsystem " + subsystem;
                r.Detail("Programm", arch + ", " + kind + (clrRva != 0 ? ", .NET" : ""));
                if (timestamp > 0)
                {
                    DateTime built = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timestamp);
                    r.Detail("Build-Zeitstempel", built > DateTime.UtcNow.AddDays(1) || built.Year < 1995
                        ? built.ToString("yyyy-MM-dd") + " (kein echtes Datum – reproduzierbarer Build oder manipuliert)"
                        : built.ToString("yyyy-MM-dd HH:mm") + " UTC");
                }

                fs.Position = optStart + optSize;
                var sectionInfo = new List<string>();
                long lastRawEnd = 0;
                bool packedName = false, execHighEntropy = false, writableExec = false;
                string packer = null;
                for (int i = 0; i < nSections && i < 96; i++)
                {
                    byte[] nameBytes = br.ReadBytes(8);
                    string name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                    br.ReadUInt32(); br.ReadUInt32();
                    uint rawSize = br.ReadUInt32();
                    uint rawPtr = br.ReadUInt32();
                    br.ReadBytes(12);
                    uint secChars = br.ReadUInt32();
                    long next = fs.Position;
                    lastRawEnd = Math.Max(lastRawEnd, (long)rawPtr + rawSize);

                    double entropy = rawSize > 0 && rawPtr < fs.Length ? Entropy(fs, rawPtr, (int)Math.Min(rawSize, 16 * 1024 * 1024)) : 0;
                    bool exec = (secChars & 0x20000000) != 0;
                    bool write = (secChars & 0x80000000) != 0;
                    sectionInfo.Add(string.Format("{0} {1:0.00}", name.Length > 0 ? name : "?", entropy));
                    string lname = name.ToLowerInvariant();
                    if (lname.StartsWith("upx") || lname == ".aspack" || lname == ".adata" || lname.StartsWith(".themida") ||
                        lname.StartsWith(".vmp") || lname == ".enigma1" || lname == ".mpress1" || lname == ".petite" || lname == "pec2")
                    {
                        packedName = true;
                        packer = name;
                    }
                    if (exec && rawSize > 4096 && entropy > 7.2) execHighEntropy = true;
                    if (exec && write) writableExec = true;
                    fs.Position = next;
                }
                r.Detail("Abschnitte (Entropie)", string.Join(", ", sectionInfo));

                long overlay = fs.Length - lastRawEnd;
                if (certOffset > 0 && certOffset >= lastRawEnd) overlay -= certSize;
                if (overlay > 64 * 1024)
                    r.Detail("Angehängte Daten", FormatSize(overlay) + " hinter dem Programmcode (typisch für Installer/Selbstentpacker)");

                string installer = DetectInstaller(fs);
                if (installer != null) r.Detail("Installer-Typ", installer);

                if (packedName)
                    r.Add(Severity.Medium, "Mit einem Packer komprimiert/verschleiert (" + packer + ") – erschwert die Analyse, oft bei Schadsoftware.");
                else if (execHighEntropy)
                    r.Add(Severity.Medium, "Programmcode ist stark verschlüsselt oder komprimiert (Entropie > 7,2) – Hinweis auf Packer/Verschleierung.");
                if (writableExec)
                    r.Add(Severity.Low, "Ein Code-Abschnitt ist gleichzeitig beschreibbar und ausführbar (typisch für selbstentpackenden Code).");
            }
        }

        static string DetectInstaller(FileStream fs)
        {
            byte[] buf = ReadBytes(fs, 0, (int)Math.Min(fs.Length, 4 * 1024 * 1024));
            string[][] marks =
            {
                new[] { "Nullsoft", "NSIS (Nullsoft)" },
                new[] { "Inno Setup", "Inno Setup" },
                new[] { "InstallShield", "InstallShield" },
                new[] { "WixBurn", "WiX Burn" },
                new[] { "7zS.sfx", "7-Zip-Selbstentpacker" },
                new[] { "PyInstaller", "PyInstaller" },
                new[] { "_MEIPASS", "PyInstaller" },
            };
            foreach (var m in marks)
                if (IndexOf(buf, Encoding.ASCII.GetBytes(m[0]), 0, buf.Length) >= 0) return m[1];
            return null;
        }

        static double Entropy(FileStream fs, long offset, int length)
        {
            var counts = new long[256];
            long total = 0;
            fs.Position = offset;
            var buf = new byte[65536];
            int remaining = length;
            while (remaining > 0)
            {
                int n = fs.Read(buf, 0, Math.Min(buf.Length, remaining));
                if (n <= 0) break;
                for (int i = 0; i < n; i++) counts[buf[i]]++;
                total += n;
                remaining -= n;
            }
            if (total == 0) return 0;
            double e = 0;
            foreach (long c in counts)
            {
                if (c == 0) continue;
                double p = (double)c / total;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }

        // ---------------- ZIP (incl. Office Open XML, JAR, …) ----------------

        class ZipEntry
        {
            public string Name;
            public bool Encrypted;
            public ushort Method;
            public long Compressed, Uncompressed, LocalOffset;
        }

        static List<ZipEntry> ReadZipDirectory(FileStream fs, out string problem)
        {
            problem = null;
            var list = new List<ZipEntry>();
            int tailLen = (int)Math.Min(fs.Length, 65557);
            byte[] tail = ReadBytes(fs, fs.Length - tailLen, tailLen);
            int eocd = -1;
            for (int i = tail.Length - 22; i >= 0; i--)
                if (tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) { eocd = i; break; }
            if (eocd < 0) { problem = "ZIP-Verzeichnis nicht gefunden (unvollständig oder beschädigt)"; return list; }
            int total = BitConverter.ToUInt16(tail, eocd + 10);
            uint cdSize = BitConverter.ToUInt32(tail, eocd + 12);
            uint cdOffset = BitConverter.ToUInt32(tail, eocd + 16);
            if (cdOffset == 0xFFFFFFFF || total == 0xFFFF) { problem = "ZIP64-Archiv – Inhaltsliste wird nicht ausgewertet"; return list; }
            // Self-extracting or prefixed archives: shift offsets by the difference.
            long eocdAbs = fs.Length - tailLen + eocd;
            long shift = eocdAbs - cdSize - cdOffset;
            if (cdSize > 64 * 1024 * 1024) { problem = "ZIP-Verzeichnis zu groß"; return list; }
            byte[] cd = ReadBytes(fs, cdOffset + shift, (int)cdSize);
            var cp437 = Encoding.GetEncoding(437);
            int p = 0;
            while (p + 46 <= cd.Length && list.Count < 20000)
            {
                if (BitConverter.ToUInt32(cd, p) != 0x02014B50) break;
                ushort flags = BitConverter.ToUInt16(cd, p + 8);
                ushort method = BitConverter.ToUInt16(cd, p + 10);
                uint comp = BitConverter.ToUInt32(cd, p + 20);
                uint uncomp = BitConverter.ToUInt32(cd, p + 24);
                int nameLen = BitConverter.ToUInt16(cd, p + 28);
                int extraLen = BitConverter.ToUInt16(cd, p + 30);
                int commentLen = BitConverter.ToUInt16(cd, p + 32);
                uint local = BitConverter.ToUInt32(cd, p + 42);
                if (p + 46 + nameLen > cd.Length) break;
                string name = ((flags & 0x800) != 0 ? Encoding.UTF8 : cp437).GetString(cd, p + 46, nameLen);
                list.Add(new ZipEntry
                {
                    Name = name, Encrypted = (flags & 1) != 0, Method = method,
                    Compressed = comp, Uncompressed = uncomp, LocalOffset = local + shift
                });
                p += 46 + nameLen + extraLen + commentLen;
            }
            return list;
        }

        static byte[] ReadZipEntry(FileStream fs, ZipEntry e, int maxBytes)
        {
            if (e.Encrypted || e.Uncompressed > maxBytes) return null;
            byte[] lh = ReadBytes(fs, e.LocalOffset, 30);
            if (lh.Length < 30 || BitConverter.ToUInt32(lh, 0) != 0x04034B50) return null;
            long dataStart = e.LocalOffset + 30 + BitConverter.ToUInt16(lh, 26) + BitConverter.ToUInt16(lh, 28);
            byte[] comp = ReadBytes(fs, dataStart, (int)Math.Min(e.Compressed, maxBytes * 4L));
            if (e.Method == 0) return comp;
            if (e.Method != 8) return null;
            using (var ms = new MemoryStream(comp))
            using (var ds = new DeflateStream(ms, CompressionMode.Decompress))
            using (var outMs = new MemoryStream())
            {
                ds.CopyTo(outMs);
                return outMs.ToArray();
            }
        }

        static void AnalyzeZip(string path, Report r)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                string problem;
                var entries = ReadZipDirectory(fs, out problem);
                if (problem != null) { r.Add(Severity.Low, problem + "."); return; }
                var files = entries.Where(e => !e.Name.EndsWith("/")).ToList();
                bool isOoxml = OoxmlExt.Contains(r.Extension) || files.Any(e => e.Name == "[Content_Types].xml");
                bool isAppPackage = AppPackageExt.Contains(r.Extension);

                if (isOoxml)
                {
                    AnalyzeOoxml(fs, files, r);
                    return;
                }

                long totalUncompressed = files.Sum(e => e.Uncompressed);
                r.Detail("Archivinhalt", files.Count + " Dateien, entpackt " + FormatSize(totalUncompressed));
                var names = files.Select(e => e.Name).Take(12).ToList();
                if (names.Count > 0)
                    r.Detail("Enthält", string.Join(", ", names) + (files.Count > 12 ? ", … (+" + (files.Count - 12) + ")" : ""));

                var encrypted = files.Where(e => e.Encrypted).ToList();
                var executables = files.Where(e => ProgramExt.Contains(Ext(e.Name)) || ScriptExt.Contains(Ext(e.Name))).ToList();
                var nested = files.Where(e => ArchiveExt.Contains(Ext(e.Name)) || DiskImageExt.Contains(Ext(e.Name))).ToList();
                var doubled = files.Where(e => { var m = DoubleExt.Match(Path.GetFileName(e.Name)); return m.Success &&
                    (ProgramExt.Contains("." + m.Groups[3].Value) || ScriptExt.Contains("." + m.Groups[3].Value)); }).ToList();

                if (encrypted.Count > 0)
                {
                    if (executables.Any(e => e.Encrypted))
                        r.Add(Severity.High, "Passwortgeschütztes Archiv mit Programmen/Skripten darin – Virenscanner können den Inhalt nicht prüfen (typische Malware-Verpackung).");
                    else
                        r.Add(Severity.Medium, "Passwortgeschütztes Archiv – Virenscanner können den Inhalt nicht prüfen.");
                }
                if (executables.Count > 0 && !isAppPackage)
                {
                    string list = string.Join(", ", executables.Take(6).Select(e => Path.GetFileName(e.Name)));
                    r.Add(Severity.Low,
                        "Archiv enthält " + executables.Count + " ausführbare Datei(en)/Skript(e): " + list + (executables.Count > 6 ? ", …" : ""));
                    if (executables.Any(e => Ext(e.Name) == ".lnk" || RareScriptExt.Contains(Ext(e.Name))))
                        r.Add(Severity.High, "Archiv enthält Verknüpfungen oder seltene Skripttypen (.lnk/.hta/.vbe/.wsf …) – häufige Angriffsmethode.");
                }
                if (doubled.Count > 0)
                    r.Add(Severity.High, "Im Archiv steckt eine Datei mit getarnter Doppelendung: " + Path.GetFileName(doubled[0].Name));
                if (nested.Count > 0 && nested.Count == files.Count)
                    r.Add(Severity.Low, "Archiv enthält nur weitere Archive/Abbilder (Verschachtelung).");
                if (files.Any(e => e.Name.Contains("../") || e.Name.Contains("..\\") || e.Name.StartsWith("/") || (e.Name.Length > 1 && e.Name[1] == ':')))
                    r.Add(Severity.Medium, "Archiv enthält Pfade, die beim Entpacken aus dem Zielordner ausbrechen können.");
                long compressed = Math.Max(1, fs.Length);
                if (totalUncompressed > 1L << 30 && totalUncompressed / compressed > 200)
                    r.Add(Severity.Medium, "Extremes Kompressionsverhältnis (" + (totalUncompressed / compressed) + ":1) – mögliche ZIP-Bombe.");
            }
        }

        static readonly Regex ExternalRel = new Regex(
            "<Relationship\\b[^>]*>", RegexOptions.IgnoreCase);

        static void AnalyzeOoxml(FileStream fs, List<ZipEntry> files, Report r)
        {
            r.Detail("Office-Dokument", files.Count + " Bestandteile");
            bool macros = files.Any(e => e.Name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
            if (macros)
            {
                if (MacroExt.Contains(r.Extension))
                    r.Add(Severity.Medium, "Das Dokument enthält VBA-Makros.");
                else
                    r.Add(Severity.High, "Das Dokument enthält VBA-Makros, obwohl die Endung „" + r.Extension + "“ keine Makros erwarten lässt.");
            }
            if (files.Any(e => e.Name.StartsWith("xl/macrosheets/", StringComparison.OrdinalIgnoreCase)))
                r.Add(Severity.High, "Die Arbeitsmappe enthält Excel-4.0-Makroblätter (XLM) – beliebt bei Schadsoftware.");
            if (files.Any(e => e.Name.IndexOf("activeX", StringComparison.OrdinalIgnoreCase) >= 0))
                r.Add(Severity.Medium, "Das Dokument enthält ActiveX-Steuerelemente.");
            if (files.Any(e => e.Name.IndexOf("/embeddings/", StringComparison.OrdinalIgnoreCase) >= 0 &&
                               (e.Name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) || ProgramExt.Contains(Ext(e.Name)))))
                r.Add(Severity.Low, "Das Dokument enthält eingebettete OLE-Objekte.");

            foreach (var e in files.Where(x => x.Name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase)).Take(200))
            {
                byte[] data = ReadZipEntry(fs, e, 2 * 1024 * 1024);
                if (data == null) continue;
                string xml = Encoding.UTF8.GetString(data);
                foreach (Match m in ExternalRel.Matches(xml))
                {
                    string tag = m.Value;
                    if (tag.IndexOf("TargetMode=\"External\"", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    bool dangerousType = tag.IndexOf("/attachedTemplate", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         tag.IndexOf("/oleObject", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         tag.IndexOf("/frame", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         tag.IndexOf("/subDocument", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!dangerousType) continue;
                    var target = Regex.Match(tag, "Target=\"([^\"]*)\"", RegexOptions.IgnoreCase).Groups[1].Value;
                    r.Add(Severity.High, "Das Dokument lädt beim Öffnen Inhalte von außen nach (Template-/OLE-Injection): " + Shorten(target, 100));
                    return;
                }
            }
        }

        // ---------------- OLE (doc/xls/ppt/msi) ----------------

        static void AnalyzeOle(string path, Report r)
        {
            byte[] data = ReadBytes(path, 0, 48 * 1024 * 1024);
            bool vba = IndexOf(data, Encoding.Unicode.GetBytes("_VBA_PROJECT"), 0, data.Length) >= 0 ||
                       IndexOf(data, Encoding.Unicode.GetBytes("VBA"), 0, data.Length) >= 0 &&
                       IndexOf(data, Encoding.Unicode.GetBytes("PROJECT"), 0, data.Length) >= 0 &&
                       IndexOf(data, Encoding.Unicode.GetBytes("Macros"), 0, data.Length) >= 0;
            if (r.Extension == ".msi" || r.Extension == ".msp")
            {
                r.Detail("Paket", "Windows-Installer (führt beim Öffnen eine Installation aus)");
                return;
            }
            if (vba)
                r.Add(Severity.Medium, "Das Office-Dokument enthält VBA-Makros.");
            if (IndexOf(data, Encoding.ASCII.GetBytes("Equation.3"), 0, data.Length) >= 0)
                r.Add(Severity.High, "Enthält ein Formel-Editor-Objekt (Equation.3) – bekannte Sicherheitslücke CVE-2017-11882.");
        }

        // ---------------- PDF ----------------

        static void AnalyzePdf(string path, Report r)
        {
            byte[] data = ReadBytes(path, 0, 48 * 1024 * 1024);
            Func<string, int> count = s => CountOf(data, Encoding.ASCII.GetBytes(s));
            int js = count("/JavaScript") + count("/JS ") + count("/JS(") + count("/JS<");
            int launch = count("/Launch");
            int embedded = count("/EmbeddedFile");
            int openAction = count("/OpenAction") + count("/AA");
            int xfa = count("/XFA");
            var flags = new List<string>();
            if (js > 0) { flags.Add("JavaScript"); r.Add(Severity.Medium, "Das PDF enthält JavaScript."); }
            if (launch > 0) { flags.Add("Launch"); r.Add(Severity.High, "Das PDF enthält eine /Launch-Aktion (kann Programme starten)."); }
            if (embedded > 0) { flags.Add("eingebettete Dateien"); r.Add(Severity.Medium, "Das PDF enthält eingebettete Dateien."); }
            if (openAction > 0) flags.Add("Aktion beim Öffnen");
            if (xfa > 0) flags.Add("XFA-Formular");
            if (openAction > 0 && (js > 0 || launch > 0))
                r.Add(Severity.Medium, "Die Aktion wird automatisch beim Öffnen des PDFs ausgelöst.");
            r.Detail("PDF-Merkmale", flags.Count == 0 ? "keine aktiven Inhalte gefunden" : string.Join(", ", flags));
            if (new FileInfo(path).Length > data.Length)
                r.Detail("Hinweis", "nur die ersten 48 MB des PDFs wurden untersucht");
        }

        // ---------------- LNK ----------------

        static void AnalyzeLnk(byte[] head, Report r)
        {
            string ascii = Encoding.GetEncoding(1252).GetString(head).ToLowerInvariant();
            string wide = Encoding.Unicode.GetString(head).ToLowerInvariant();
            string[] bad = { "powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin", "curl", "http://", "https://", "\\\\" };
            var hits = bad.Where(b => ascii.Contains(b) || wide.Contains(b)).ToList();
            if (hits.Count > 0)
                r.Add(Severity.High, "Die Verknüpfung startet verdächtige Befehle: " + string.Join(", ", hits));
        }

        // ---------------- text: scripts, HTML, SVG ----------------

        static readonly string[][] ScriptPatterns =
        {
            new[] { "-encodedcommand", "PowerShell mit verschlüsseltem Befehl (-EncodedCommand)" },
            new[] { " -enc ", "PowerShell mit verschlüsseltem Befehl (-enc)" },
            new[] { "frombase64string", "dekodiert Base64-Daten zur Laufzeit" },
            new[] { "invoke-expression", "führt dynamisch erzeugten Code aus (Invoke-Expression)" },
            new[] { "iex(", "führt dynamisch erzeugten Code aus (IEX)" },
            new[] { "iex (", "führt dynamisch erzeugten Code aus (IEX)" },
            new[] { "downloadstring", "lädt Code aus dem Internet nach (DownloadString)" },
            new[] { "downloadfile", "lädt Dateien aus dem Internet nach (DownloadFile)" },
            new[] { "net.webclient", "nutzt Net.WebClient für Downloads" },
            new[] { "invoke-webrequest", "lädt Inhalte aus dem Internet (Invoke-WebRequest)" },
            new[] { "start-bitstransfer", "lädt Dateien per BITS nach" },
            new[] { "bitsadmin", "lädt Dateien per bitsadmin nach" },
            new[] { "certutil -decode", "dekodiert Dateien mit certutil" },
            new[] { "certutil -urlcache", "lädt Dateien mit certutil herunter" },
            new[] { "wscript.shell", "startet Befehle über WScript.Shell" },
            new[] { "shell.application", "startet Programme über Shell.Application" },
            new[] { "mshta", "startet mshta (HTML-Anwendungen)" },
            new[] { "regsvr32", "nutzt regsvr32" },
            new[] { "rundll32", "nutzt rundll32" },
            new[] { "-windowstyle hidden", "läuft in einem versteckten Fenster" },
            new[] { "-w hidden", "läuft in einem versteckten Fenster" },
            new[] { "executionpolicy bypass", "umgeht die PowerShell-Ausführungsrichtlinie" },
            new[] { "-ep bypass", "umgeht die PowerShell-Ausführungsrichtlinie" },
            new[] { "add-mppreference", "ändert Windows-Defender-Ausnahmen" },
            new[] { "set-mppreference", "ändert Windows-Defender-Einstellungen" },
            new[] { "vssadmin delete shadows", "löscht Schattenkopien (Ransomware-Muster)" },
            new[] { "schtasks /create", "legt geplante Aufgaben an (Autostart)" },
            new[] { "currentversion\\run", "trägt sich in den Autostart ein" },
        };

        static void AnalyzeText(string path, Report r)
        {
            byte[] raw = ReadBytes(path, 0, 4 * 1024 * 1024);
            string text = DecodeText(raw);
            string t = text.ToLowerInvariant();
            bool isScript = ScriptExt.Contains(r.Extension) && r.Extension != ".url";

            if (r.Extension == ".url")
            {
                var m = Regex.Match(text, @"^\s*URL\s*=\s*(.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline);
                string target = m.Success ? m.Groups[1].Value.Trim() : "";
                r.Detail("Ziel", Shorten(target, 160));
                if (target.StartsWith("file:", StringComparison.OrdinalIgnoreCase) || target.StartsWith("\\\\") ||
                    target.StartsWith("search-ms:", StringComparison.OrdinalIgnoreCase))
                    r.Add(Severity.High, "Die Internetverknüpfung zeigt auf eine Datei/Netzwerkfreigabe statt auf eine Webseite.");
                return;
            }

            var hits = new List<string>();
            if (isScript || r.Kind == FileKind.Html || r.Kind == FileKind.Svg || r.Kind == FileKind.Text || r.Kind == FileKind.Xml)
            {
                foreach (var p in ScriptPatterns)
                    if (t.Contains(p[0]) && !hits.Contains(p[1])) hits.Add(p[1]);
            }
            // Plain text files (READMEs, logs) may legitimately mention these commands, so they only count when executable.
            if (hits.Count > 0 && (isScript || r.Kind == FileKind.Html || r.Kind == FileKind.Svg))
                r.Add(hits.Count >= 3 ? Severity.High : Severity.Medium, "Verdächtige Befehle: " + string.Join("; ", hits.Take(6)));

            if (isScript && Regex.IsMatch(text, @"[A-Za-z0-9+/]{400,}={0,2}"))
                r.Add(Severity.Medium, "Das Skript enthält lange Base64-Blöcke (versteckte Nutzlast).");

            if (r.Kind == FileKind.Html || r.Kind == FileKind.Svg)
            {
                bool smuggling = (t.Contains("atob(") || t.Contains("base64")) && t.Contains("blob") &&
                                 (t.Contains("createobjecturl") || t.Contains("mssaveoropenblob")) &&
                                 (t.Contains(".download") || t.Contains("download=") || t.Contains(".click()"));
                if (smuggling)
                    r.Add(Severity.High, "Die Seite baut per JavaScript eine Datei zusammen und lädt sie herunter (HTML-Smuggling).");
                if (t.Contains("type=\"password\"") || t.Contains("type='password'") || t.Contains("type=password"))
                    r.Add(Severity.Medium, "Lokale HTML-Datei mit Passwortfeld – typisch für Phishing-Anhänge.");
                if (r.Kind == FileKind.Svg && t.Contains("<script"))
                    r.Add(Severity.Medium, "Die SVG-Grafik enthält JavaScript.");
                if (Regex.IsMatch(t, @"<meta[^>]+http-equiv\s*=\s*[""']?refresh[^>]+url\s*=\s*https?://"))
                    r.Add(Severity.Low, "Die Seite leitet automatisch auf eine externe Adresse weiter.");
                var form = Regex.Match(t, @"<form[^>]+action\s*=\s*[""'](https?://[^""']+)");
                if (form.Success)
                    r.Detail("Formular sendet an", Shorten(form.Groups[1].Value, 120));
            }
        }

        // ---------------- helpers ----------------

        static string Ext(string name)
        {
            try { return Path.GetExtension(name.TrimEnd(' ', '.')).ToLowerInvariant(); }
            catch { return ""; }
        }

        static bool LooksLikeText(byte[] h)
        {
            if (h.Length == 0) return false;
            if (StartsWith(h, 0, 0xFF, 0xFE) || StartsWith(h, 0, 0xFE, 0xFF)) return true;
            int n = Math.Min(h.Length, 8192), bad = 0;
            for (int i = 0; i < n; i++)
            {
                byte b = h[i];
                if (b == 0) return false;
                if (b < 0x09 || (b > 0x0D && b < 0x20 && b != 0x1B)) bad++;
            }
            return bad * 100 < n;
        }

        static string DecodeText(byte[] raw)
        {
            if (StartsWith(raw, 0, 0xFF, 0xFE)) return Encoding.Unicode.GetString(raw, 2, raw.Length - 2);
            if (StartsWith(raw, 0, 0xFE, 0xFF)) return Encoding.BigEndianUnicode.GetString(raw, 2, raw.Length - 2);
            return Encoding.UTF8.GetString(raw);
        }

        static bool StartsWith(byte[] h, int offset, params byte[] sig)
        {
            if (h.Length < offset + sig.Length) return false;
            for (int i = 0; i < sig.Length; i++) if (h[offset + i] != sig[i]) return false;
            return true;
        }

        static int IndexOf(byte[] data, byte[] pattern, int start, int end)
        {
            if (pattern.Length == 0) return -1;
            byte first = pattern[0];
            int last = Math.Min(end, data.Length) - pattern.Length;
            for (int i = start; i <= last; i++)
            {
                if (data[i] != first) continue;
                int j = 1;
                while (j < pattern.Length && data[i + j] == pattern[j]) j++;
                if (j == pattern.Length) return i;
            }
            return -1;
        }

        static int CountOf(byte[] data, byte[] pattern)
        {
            int count = 0, pos = 0;
            while ((pos = IndexOf(data, pattern, pos, data.Length)) >= 0) { count++; pos += pattern.Length; }
            return count;
        }

        public static byte[] ReadBytes(string path, long offset, int count)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                return ReadBytes(fs, offset, count);
        }

        static byte[] ReadBytes(FileStream fs, long offset, int count)
        {
            if (offset < 0 || offset >= fs.Length) return new byte[0];
            count = (int)Math.Min(count, fs.Length - offset);
            var buf = new byte[count];
            fs.Position = offset;
            int read = 0;
            while (read < count)
            {
                int n = fs.Read(buf, read, count - read);
                if (n <= 0) break;
                read += n;
            }
            if (read < count) Array.Resize(ref buf, read);
            return buf;
        }

        static string Sha256(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20))
            using (var sha = new SHA256Cng())
                return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
        }

        public static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " Byte";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("0.0") + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / 1048576.0).ToString("0.0") + " MB";
            return (bytes / 1073741824.0).ToString("0.00") + " GB";
        }

        static string Shorten(string s, int max)
        {
            if (s == null) return "";
            return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
        }
    }
}
