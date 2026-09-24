using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Media;
using System.Threading;
using System.Windows.Forms;

namespace PreGuard
{
    class ReportForm : Form
    {
        public enum Outcome { None, Released, Terminated }

        public readonly DownloadCase Case;
        public Outcome Result { get; private set; }
        public event Action<ReportForm> Decided;

        readonly bool manualCheck;
        readonly float scale;
        Panel header;
        Label verdictLabel, nameLabel, subLabel, statusLabel;
        RichTextBox body;
        Button keepButton, killButton;

        static readonly Color Scanning = Color.FromArgb(0x37, 0x47, 0x4F);
        static readonly Color CleanColor = Color.FromArgb(0x1B, 0x7F, 0x3B);
        static readonly Color CautionColor = Color.FromArgb(0xB2, 0x5E, 0x00);
        static readonly Color HighColor = Color.FromArgb(0xC6, 0x28, 0x28);
        static readonly Color ThreatColor = Color.FromArgb(0x8E, 0x10, 0x10);
        static readonly Color MissingColor = Color.FromArgb(0x61, 0x61, 0x61);

        public ReportForm(DownloadCase downloadCase, bool manual)
        {
            Case = downloadCase;
            manualCheck = manual;
            using (var g = CreateGraphics()) scale = g.DpiX / 96f;

            Text = "PreGuard – Download-Prüfung";
            Icon = Icons.Create(32, false);
            Font = new Font("Segoe UI", 9.75f);
            BackColor = Color.White;
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(S(640), S(620));
            MinimumSize = new Size(S(520), S(460));
            StartPosition = FormStartPosition.Manual;
            TopMost = true;
            ShowInTaskbar = true;
            MinimizeBox = false; // a minimised report would hide a pending decision
            KeyPreview = true;

            header = new Panel { Dock = DockStyle.Top, Height = S(118), BackColor = Scanning, Padding = new Padding(S(20), S(14), S(20), S(10)) };
            verdictLabel = new Label { Text = "WIRD GEPRÜFT …", ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 17f), AutoSize = false, Dock = DockStyle.Top, Height = S(40), UseMnemonic = false };
            nameLabel = new Label { Text = Case.DisplayName, ForeColor = Color.White, Font = new Font("Segoe UI", 11.5f), AutoSize = false, Dock = DockStyle.Top, Height = S(28), AutoEllipsis = true, UseMnemonic = false };
            subLabel = new Label { Text = Case.Reason ?? "", ForeColor = Color.FromArgb(225, 255, 255, 255), AutoSize = false, Dock = DockStyle.Top, Height = S(24), AutoEllipsis = true, UseMnemonic = false };
            header.Controls.Add(subLabel);
            header.Controls.Add(nameLabel);
            header.Controls.Add(verdictLabel);

            var footer = new Panel { Dock = DockStyle.Bottom, Height = S(70), BackColor = Color.FromArgb(0xF3, 0xF4, 0xF6), Padding = new Padding(S(20), S(14), S(20), S(14)) };
            killButton = MakeButton("Terminate", Color.FromArgb(0xC6, 0x28, 0x28));
            keepButton = MakeButton(manualCheck ? "Fertig" : "Fertig downloaden", Color.FromArgb(0x1B, 0x7F, 0x3B));
            keepButton.Enabled = false;
            killButton.Dock = DockStyle.Right;
            keepButton.Dock = DockStyle.Right;
            var gap = new Panel { Dock = DockStyle.Right, Width = S(12) };
            statusLabel = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Color.FromArgb(0x55, 0x5B, 0x66), Text = "Datei ist gesperrt, bis du entscheidest.", AutoEllipsis = true, UseMnemonic = false };
            footer.Controls.Add(statusLabel);
            footer.Controls.Add(killButton);
            footer.Controls.Add(gap);
            footer.Controls.Add(keepButton);

            var bodyHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(S(20), S(14), S(12), S(8)), BackColor = Color.White };
            body = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = Color.White, DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Vertical, Font = new Font("Segoe UI", 9.75f) };
            body.GotFocus += (s, e) => HideCaret(body.Handle);
            bodyHost.Controls.Add(body);

            Controls.Add(bodyHost);
            Controls.Add(footer);
            Controls.Add(header);
            bodyHost.BringToFront();

            keepButton.Click += (s, e) => Keep();
            killButton.Click += (s, e) => Kill();
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) Close(); };

            if (!Case.IsHeld && !manualCheck && Case.Report == null)
                statusLabel.Text = "Die Datei konnte nicht gesperrt werden.";
            if (manualCheck) statusLabel.Text = "Manuelle Prüfung – die Datei wird nicht gesperrt.";

            if (Case.Report != null) ShowReport(Case.Report);
            else ShowProgress("Prüfung startet …");
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern bool HideCaret(IntPtr hWnd);

        int S(int px) { return (int)Math.Round(px * scale); }

        Button MakeButton(string text, Color color)
        {
            var b = new Button
            {
                Text = text,
                Width = S(text.Length > 12 ? 190 : 140),
                FlatStyle = FlatStyle.Flat,
                BackColor = color,
                ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 10.5f),
                Cursor = Cursors.Hand,
                UseMnemonic = false,
            };
            b.FlatAppearance.BorderSize = 0;
            b.EnabledChanged += (s, e) => b.BackColor = b.Enabled ? color : Color.FromArgb(0xB8, 0xBD, 0xC4);
            return b;
        }

        public void PlaceAt(int index)
        {
            var area = Screen.PrimaryScreen.WorkingArea;
            int offset = S(28) * (index % 6);
            Location = new Point(area.Right - Width - S(16) - offset, area.Bottom - Height - S(16) - offset);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Activate();
            if (Case.Report == null) StartAnalysis();
        }

        void StartAnalysis()
        {
            var thread = new Thread(() =>
            {
                Report report;
                try
                {
                    report = Analyzer.Analyze(Case.CurrentPath, Case.DisplayName, true,
                        msg => { try { BeginInvoke(new Action(() => ShowProgress(msg))); } catch { } });
                }
                catch (Exception ex)
                {
                    if (!File.Exists(Case.CurrentPath))
                        report = Analyzer.RemovedReport(Case.CurrentPath, Case.DisplayName, false, Case.DetectedAt.ToUniversalTime());
                    else
                    {
                        report = new Report { DisplayName = Case.DisplayName, FilePath = Case.CurrentPath, Verdict = Verdict.Caution };
                        report.Add(Severity.Medium, "Die Prüfung ist fehlgeschlagen: " + ex.Message);
                    }
                }
                Case.Report = report;
                try { BeginInvoke(new Action(() => ShowReport(report))); } catch { }
            });
            thread.IsBackground = true;
            thread.Start();
        }

        void ShowProgress(string message)
        {
            if (Case.Report != null) return;
            body.Clear();
            Append("Prüfung läuft\n", Color.FromArgb(0x21, 0x21, 0x21), 11f, true);
            Append(message + "\n", Color.FromArgb(0x55, 0x5B, 0x66), 9.75f, false);
        }

        void ShowReport(Report r)
        {
            Color c;
            switch (r.Verdict)
            {
                case Verdict.Clean: c = CleanColor; break;
                case Verdict.Caution: c = CautionColor; break;
                case Verdict.HighRisk: c = HighColor; break;
                case Verdict.Threat: c = ThreatColor; break;
                default: c = MissingColor; break;
            }
            header.BackColor = c;
            verdictLabel.Text = Report.VerdictLabel(r.Verdict);
            var parts = new System.Collections.Generic.List<string>();
            if (!string.IsNullOrEmpty(Case.Reason)) parts.Add(Case.Reason);
            if (r.Size > 0) parts.Add(Analyzer.FormatSize(r.Size));
            if (r.AnalysisMs > 0) parts.Add("geprüft in " + (r.AnalysisMs / 1000.0).ToString("0.0") + " s");
            subLabel.Text = string.Join("  ·  ", parts);

            body.Clear();
            Append("Befund\n", Color.FromArgb(0x21, 0x21, 0x21), 11f, true);
            var findings = r.SortedFindings().ToList();
            if (findings.Count == 0 || findings.All(f => f.Severity == Severity.Info) && r.Verdict == Verdict.Clean)
                Append("●  Keine Auffälligkeiten gefunden.\n", CleanColor, 9.75f, false);
            foreach (var f in findings)
                Append("●  " + f.Text + "\n", SeverityColor(f.Severity), 9.75f, f.Severity >= Severity.High);

            Append("\nDetails\n", Color.FromArgb(0x21, 0x21, 0x21), 11f, true);
            foreach (var kv in r.Details)
            {
                Append(kv.Key + ":  ", Color.FromArgb(0x55, 0x5B, 0x66), 9.75f, true);
                Append(kv.Value + "\n", Color.FromArgb(0x21, 0x21, 0x21), 9.75f, false);
            }
            Append("\nPreGuard kombiniert den Windows-Defender-Scan mit eigenen Prüfungen von Typ, Signatur, Herkunft und Inhalt. Auch ein unauffälliges Ergebnis ist keine Garantie.\n",
                Color.FromArgb(0x80, 0x86, 0x90), 8.5f, false);
            body.SelectionStart = 0;
            body.ScrollToCaret();

            bool exists = File.Exists(Case.CurrentPath);
            if (r.Verdict == Verdict.Missing || !exists || Case.BlockedByAntivirus)
            {
                keepButton.Enabled = false;
                if (!exists) killButton.Text = "Schließen";
                statusLabel.Text = exists ? "Die Datei ist vom Virenschutz blockiert." : "Die Datei ist nicht mehr vorhanden.";
            }
            else
            {
                keepButton.Enabled = true;
                if (!manualCheck && Case.IsHeld) statusLabel.Text = "Gesperrt als „" + Path.GetFileName(Case.HeldPath) + "“";
            }
            if (r.Verdict >= Verdict.HighRisk && r.Verdict != Verdict.Missing) SystemSounds.Hand.Play();
            else if (r.Verdict == Verdict.Caution) SystemSounds.Exclamation.Play();
        }

        static Color SeverityColor(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return ThreatColor;
                case Severity.High: return HighColor;
                case Severity.Medium: return CautionColor;
                case Severity.Low: return Color.FromArgb(0x5F, 0x63, 0x68);
                default: return Color.FromArgb(0x15, 0x65, 0xC0);
            }
        }

        void Append(string text, Color color, float size, bool bold)
        {
            body.SelectionStart = body.TextLength;
            body.SelectionLength = 0;
            body.SelectionColor = color;
            body.SelectionFont = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular);
            body.AppendText(text);
        }

        void Keep()
        {
            var r = Case.Report;
            if (r != null && r.Verdict >= Verdict.HighRisk && r.Verdict != Verdict.Missing)
            {
                var answer = MessageBox.Show(this,
                    "PreGuard stuft diese Datei als „" + Report.VerdictLabel(r.Verdict) + "“ ein.\n\nTrotzdem freigeben?",
                    "PreGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) return;
            }
            try
            {
                string path = manualCheck ? Case.CurrentPath : Case.Release();
                AppSettings.Log("FREIGEGEBEN", Label(r) + path);
                Result = Outcome.Released;
                Case.Decided = true;
                Finish();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Die Datei konnte nicht freigegeben werden:\n" + ex.Message, "PreGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        void Kill()
        {
            if (!File.Exists(Case.CurrentPath))
            {
                Case.Decided = true;
                if (Case.IsHeld) HeldStore.Remove(Case.HeldPath);
                Finish();
                return;
            }
            try
            {
                string path = Case.CurrentPath;
                Case.Terminate();
                AppSettings.Log("GELÖSCHT", Label(Case.Report) + path);
                Result = Outcome.Terminated;
                Finish();
            }
            catch (Exception ex)
            {
                if (Case.BlockedByAntivirus)
                {
                    // Windows may refuse even deleting a file Defender holds; Defender quarantines it itself.
                    AppSettings.Log("GESCHLOSSEN", Label(Case.Report) + Case.CurrentPath + " (Löschen verweigert: " + ex.Message + " – Defender entfernt die Datei)");
                    Case.Decided = true;
                    Finish();
                    return;
                }
                MessageBox.Show(this, "Die Datei konnte nicht gelöscht werden:\n" + ex.Message, "PreGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static string Label(Report r)
        {
            return r == null ? "[ungeprüft]  " : "[" + Report.VerdictLabel(r.Verdict) + "]  ";
        }

        void Finish()
        {
            var handler = Decided;
            if (handler != null) handler(this);
            Close();
        }
    }
}
