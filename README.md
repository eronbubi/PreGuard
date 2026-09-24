# PreGuard

Windows 11 background program that checks every finished download before you can open it.

**Current version: v1.0.0.** Download `PreGuard.exe` from the [Releases](../../releases) page and run it. No installation is needed; .NET Framework 4.8 ships with Windows 11.

## How it works

1. PreGuard starts with Windows (entry `PreGuard` under `HKCU\...\CurrentVersion\Run`, set on first launch) and sits in the notification area as a blue shield.
2. When a download finishes, PreGuard renames the file to `<name>.preguard` so it cannot be opened or run.
   - Browser downloads are detected anywhere in the user profile and on other fixed drives: Chrome, Edge, Brave and Opera rename `.crdownload`, Firefox renames `.part`.
   - New files that settle directly in the Downloads folder are also caught, for example from curl or wget.
3. A report window shows the verdict (UNAUFFÄLLIG / VORSICHT / HOHES RISIKO / BEDROHUNG ERKANNT), the findings and the details.
4. **Fertig downloaden** restores the original name. For HOHES RISIKO, PreGuard asks you to confirm first. **Terminate** deletes the file.
   If you close the window without deciding, the file stays locked and you can reopen it from the tray icon. Pending files also survive a restart.

## Checks

- Windows Defender on-demand scan (`MpCmdRun -DisableRemediation`), plus Defender's detection history for files that real-time protection has already blocked
- Origin (Mark of the Web): source URL, zone, HTTP instead of HTTPS, bare IP addresses, blob/data downloads (HTML smuggling)
- Actual file type from magic bytes, compared with the extension (for example a program disguised as `.pdf`)
- File name tricks: double extensions (`Rechnung.pdf.exe`), RTLO characters, padding spaces
- Authenticode signature (offline) and the signer's name
- Programs: architecture, packers and entropy, installer type, appended data
- ZIP: contents, password protection, executables inside, path traversal, ZIP bombs
- Office: VBA macros, XLM macro sheets, ActiveX, template injection
- PDF: JavaScript, /Launch, embedded files
- Scripts, HTML, SVG, LNK and URL files: dangerous commands and phishing patterns

## Build

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

The build uses the C# compiler that ships with Windows (.NET Framework 4.8), so no SDK is needed. The result is `dist\PreGuard.exe`.

## Files

- Log: `%LOCALAPPDATA%\PreGuard\protokoll.txt` (also available from the tray menu under "Protokoll öffnen")
- Pending files: `%LOCALAPPDATA%\PreGuard\gesperrt.txt`
- Turn autostart off: use the "Mit Windows starten" entry in the tray menu, or run `PreGuard.exe --remove-autostart`
