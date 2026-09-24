using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PreGuard
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length >= 2 && args[0] == "--make-icon")
            {
                Icons.SaveIco(args[1]);
                return 0;
            }
            if (args.Length >= 1 && args[0] == "--remove-autostart")
            {
                AppSettings.SetAutostart(false);
                return 0;
            }

            bool background = args.Contains("--background");
            bool createdNew;
            using (var mutex = new Mutex(true, @"Local\PreGuard.SingleInstance", out createdNew))
            {
                if (!createdNew)
                {
                    if (!background)
                        MessageBox.Show("PreGuard läuft bereits im Hintergrund.\nDas Schild-Symbol findest du im Infobereich der Taskleiste.",
                            "PreGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 0;
                }
                Native.TrySetDpiAware();
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += (s, e) => AppSettings.Log("FEHLER", e.Exception.ToString());
                AppDomain.CurrentDomain.UnhandledException += (s, e) => AppSettings.Log("FEHLER", e.ExceptionObject.ToString());
                Application.Run(new TrayContext(background));
            }
            return 0;
        }
    }

    class TrayContext : ApplicationContext
    {
        readonly NotifyIcon tray;
        readonly DownloadMonitor monitor = new DownloadMonitor();
        readonly Control ui = new Control();
        readonly List<ReportForm> openForms = new List<ReportForm>();
        readonly List<DownloadCase> undecided = new List<DownloadCase>();
        readonly ToolStripMenuItem pauseItem, autostartItem, pendingItem;
        readonly System.Drawing.Icon activeIcon, pausedIcon;

        public TrayContext(bool background)
        {
            ui.CreateControl();
            AppSettings.EnsureDir();
            if (AppSettings.ConsumeFirstRun()) AppSettings.SetAutostart(true);
            else AppSettings.RefreshAutostartPath();

            int iconSize = SystemInformation.SmallIconSize.Width;
            activeIcon = Icons.Create(iconSize, false);
            pausedIcon = Icons.Create(iconSize, true);

            var menu = new ContextMenuStrip();
            var title = new ToolStripMenuItem("PreGuard – Download-Schutz") { Enabled = false };
            pendingItem = new ToolStripMenuItem("Offene Entscheidungen") { Visible = false };
            var manual = new ToolStripMenuItem("Datei manuell prüfen …", null, (s, e) => ManualCheck());
            pauseItem = new ToolStripMenuItem("Überwachung pausieren", null, (s, e) => TogglePause());
            autostartItem = new ToolStripMenuItem("Mit Windows starten", null, (s, e) => ToggleAutostart());
            var log = new ToolStripMenuItem("Protokoll öffnen", null, (s, e) => OpenLog());
            var exit = new ToolStripMenuItem("Beenden", null, (s, e) => ExitApp());
            menu.Items.AddRange(new ToolStripItem[] { title, new ToolStripSeparator(), pendingItem, manual, pauseItem, autostartItem, log, new ToolStripSeparator(), exit });
            menu.Opening += (s, e) => autostartItem.Checked = AppSettings.IsAutostartEnabled();

            tray = new NotifyIcon { Icon = activeIcon, Text = "PreGuard – Downloads werden geprüft", ContextMenuStrip = menu, Visible = true };
            tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) ShowPendingOrStatus(); };

            monitor.DownloadFinished += OnDownloadFinished;
            monitor.Start();
            AppSettings.Log("START", "überwacht: " + string.Join("; ", monitor.WatchedRoots) + " | Download-Ordner: " + monitor.DownloadsFolder);

            RestoreHeldFiles();
            if (!background)
                tray.ShowBalloonTip(4000, "PreGuard ist aktiv", "Jeder Download wird geprüft, bevor du ihn öffnen kannst.", ToolTipIcon.Info);
        }

        // Called on a worker thread by the monitor.
        void OnDownloadFinished(string path, string reason, bool gone)
        {
            var dc = new DownloadCase { OriginalPath = path, Reason = reason };
            DateTime detected = DateTime.UtcNow;
            if (!gone)
            {
                string error;
                bool held = dc.Hold(out error);
                gone = !held && (dc.BlockedByAntivirus || !File.Exists(path));
                if (!gone)
                {
                    AppSettings.Log(held ? "ERKANNT" : "NICHT GESPERRT", path + "  (" + reason + (held ? "" : "; " + error) + ")");
                    if (!held) dc.Reason = reason + " – Sperren fehlgeschlagen: " + error;
                }
            }
            if (gone)
            {
                if (File.Exists(path)) dc.BlockedByAntivirus = true;
                dc.Report = Analyzer.RemovedReport(path, null, File.Exists(path), detected);
                AppSettings.Log(dc.Report.Verdict == Verdict.Threat ? "BLOCKIERT" : "ENTFERNT",
                    path + "  (" + string.Join(" ", dc.Report.Findings.Select(f => f.Text)) + ")");
            }
            try { ui.BeginInvoke(new Action(() => ShowCase(dc, false))); }
            catch (InvalidOperationException) { }
        }

        void ShowCase(DownloadCase dc, bool manual)
        {
            var existing = openForms.FirstOrDefault(f => f.Case == dc);
            if (existing != null) { existing.Activate(); return; }
            var form = new ReportForm(dc, manual);
            form.PlaceAt(openForms.Count);
            form.Decided += f =>
            {
                undecided.Remove(f.Case);
                if (f.Result == ReportForm.Outcome.Released && !manual)
                    tray.ShowBalloonTip(2500, "Freigegeben", Path.GetFileName(f.Case.OriginalPath), ToolTipIcon.Info);
                else if (f.Result == ReportForm.Outcome.Terminated)
                    tray.ShowBalloonTip(2500, "Gelöscht", f.Case.DisplayName, ToolTipIcon.Info);
            };
            form.FormClosed += (s, e) =>
            {
                openForms.Remove(form);
                if (!dc.Decided && dc.IsHeld && !manual)
                {
                    if (!undecided.Contains(dc)) undecided.Add(dc);
                    tray.ShowBalloonTip(3500, "Download wartet", dc.DisplayName + " bleibt gesperrt. Klick auf das PreGuard-Symbol, um zu entscheiden.", ToolTipIcon.Warning);
                }
                UpdatePendingMenu();
            };
            openForms.Add(form);
            if (!manual && dc.IsHeld && !undecided.Contains(dc)) undecided.Add(dc);
            UpdatePendingMenu();
            form.Show();
        }

        void UpdatePendingMenu()
        {
            pendingItem.DropDownItems.Clear();
            foreach (var dc in undecided.ToList())
            {
                var captured = dc;
                pendingItem.DropDownItems.Add(dc.DisplayName, null, (s, e) => ShowCase(captured, false));
            }
            pendingItem.Visible = undecided.Count > 0;
            pendingItem.Text = "Offene Entscheidungen (" + undecided.Count + ")";
            tray.Text = undecided.Count > 0 ? "PreGuard – " + undecided.Count + " Download(s) warten" :
                        monitor.Paused ? "PreGuard – pausiert" : "PreGuard – Downloads werden geprüft";
        }

        void ShowPendingOrStatus()
        {
            var first = undecided.FirstOrDefault(dc => openForms.All(f => f.Case != dc));
            if (first != null) { ShowCase(first, false); return; }
            if (openForms.Count > 0) { openForms.Last().Activate(); return; }
            tray.ShowBalloonTip(2500, "PreGuard", monitor.Paused ? "Überwachung ist pausiert." : "Alles in Ordnung – Downloads werden überwacht.", ToolTipIcon.Info);
        }

        void RestoreHeldFiles()
        {
            foreach (var kv in HeldStore.Load())
            {
                if (!File.Exists(kv.Key)) { HeldStore.Remove(kv.Key); continue; }
                var dc = new DownloadCase { OriginalPath = kv.Value, HeldPath = kv.Key, Reason = "Noch offen seit dem letzten Start" };
                ShowCase(dc, false);
            }
        }

        void ManualCheck()
        {
            using (var dlg = new OpenFileDialog { Title = "Datei mit PreGuard prüfen", CheckFileExists = true })
            {
                if (dlg.ShowDialog() != DialogResult.OK) return;
                ShowCase(new DownloadCase { OriginalPath = dlg.FileName, Reason = "Manuelle Prüfung" }, true);
            }
        }

        void TogglePause()
        {
            monitor.Paused = !monitor.Paused;
            pauseItem.Checked = monitor.Paused;
            tray.Icon = monitor.Paused ? pausedIcon : activeIcon;
            AppSettings.Log(monitor.Paused ? "PAUSE" : "FORTGESETZT", "");
            UpdatePendingMenu();
        }

        void ToggleAutostart()
        {
            bool enable = !AppSettings.IsAutostartEnabled();
            AppSettings.SetAutostart(enable);
            autostartItem.Checked = enable;
        }

        void OpenLog()
        {
            if (!File.Exists(AppSettings.LogFile)) File.WriteAllText(AppSettings.LogFile, "", Encoding.UTF8);
            Process.Start("notepad.exe", "\"" + AppSettings.LogFile + "\"");
        }

        void ExitApp()
        {
            int waiting = undecided.Count;
            if (waiting > 0)
            {
                var answer = MessageBox.Show(
                    waiting + " Download(s) warten noch auf deine Entscheidung.\nSie bleiben gesperrt und werden beim nächsten Start wieder angezeigt.\n\nPreGuard trotzdem beenden?",
                    "PreGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (answer != DialogResult.Yes) return;
            }
            monitor.Dispose();
            foreach (var f in openForms.ToList()) f.Close();
            tray.Visible = false;
            tray.Dispose();
            AppSettings.Log("BEENDET", "");
            ExitThread();
        }
    }
}
