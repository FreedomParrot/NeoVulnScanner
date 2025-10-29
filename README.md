# NeoVuln Scanner 🚀🔒

[![Python](https://img.shields.io/badge/Python-3.x-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ethical Hacking](https://img.shields.io/badge/Ethical%20Hacking-%F0%9F%94%92%20Secure-blue.svg)](https://owasp.org/)

<div align="center">
  <img src="https://via.placeholder.com/800x200/0D0D0D/00FFFF?text=NeoVuln+Scanner+-+Cyberpunk+Edition" alt="Banner">
  <br><br>
  <strong>A professional-grade ethical hacking vulnerability scanner with a stunning cyberpunk GUI. Inspired by OWASP ZAP, built for pentesters who love neon vibes. 🌃💻</strong>
</div>

---

## 📖 About the Project

**NeoVuln Scanner** is an open-source tool designed for ethical penetration testers and security enthusiasts. It scans web applications for common vulnerabilities like XSS, SQLi, exposed directories, and more— all wrapped in a futuristic cyberpunk-themed interface with neon cyan, magenta, and green accents. 

- **Why NeoVuln?** Because traditional scanners are boring. This one feels like hacking in a cyber-noir movie. 🎥🔥
- **Ethical Use Only:** Always get permission before scanning. Respect the law and the web. ⚖️

### Key Stats
| Feature | Status |
|---------|--------|
| Multi-Threaded Scans | ✅ |
| SQLite Scan History | ✅ |
| HTML Report Generation | ✅ |
| Proxy & Auth Support | ✅ |
| Cyberpunk GUI | 🎨✨ |

---

## ✨ Features

- **🚀 Cyberpunk GUI**: Dark theme with neon colors (cyan, magenta, green) using Tkinter. Tabs for Scan, Settings, Reports, and Logs.
- **🔍 Vulnerability Checks**:
  - Connectivity & Header Analysis 🛡️
  - Reflected XSS Testing 💥
  - SQL Injection Probes 🗄️
  - Directory Enumeration 📁
  - SSL/TLS Certificate Validation 🔐
  - Subdomain Enumeration 🌐
- **⚙️ Configurable Options**: Timeout, threads, enable/disable modules, proxy, basic auth.
- **📊 Reporting**: Generate beautiful HTML reports with severity-based styling. Export to CSV/JSON.
- **🗄️ Scan History**: SQLite database to track past scans and results.
- **📝 Logging**: Rotated file logs + real-time GUI display.
- **No Dependencies**: Pure Python 3.x – just run it! 🐍

---

## 🛠️ Installation

1. **Prerequisites**:
   - Python 3.6+ (Tkinter included by default).
   - No pip installs needed! 🎉

2. **Clone the Repo**:
   ```bash
   (https://github.com/FreedomParrot/NeoVulnScanner)
   cd NeoVulnScanner
   ```

3. **Run the Scanner**:
   ```bash
   python neovuln_scanner.py
   ```
   - The GUI will launch in a 1200x800 window. Enter a URL and hit **Start Scan**! 🎯

4. **Optional: Virtual Environment** (Recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   python neovuln_scanner.py
   ```

---

## 📱 Usage Guide

### Quick Start
1. Open the app – you'll see the **Scan** tab with a neon URL input.
2. Enter a target: `http://testphp.vulnweb.com` (legal demo site) or your authorized target.
3. **Configure in Settings Tab**:
   - Enable/disable checks (e.g., XSS, SQLi).
   - Set timeout (default: 10s), max threads (default: 5).
   - Add proxy or auth if needed.
4. Hit **Start Scan** – watch the progress bar glow! 🌟
5. Results populate in real-time. Generate reports from the **Reports** tab.

### Example Scan Output
```
[14:30:15] Initializing professional scan on http://example.com...
[14:30:16] ✓ Connected to http://example.com (Status: 200)
[14:30:17] ⚠ Server: Apache/2.4.41 - Potential info leak
[14:30:18] ⚠ Potential reflected XSS vulnerability detected!
[14:30:20] Scan completed. For full assessment, use professional tools like OWASP ZAP.
```



### Advanced Tips
- **Test Legally**: Use sites like [DVWA](http://www.dvwa.co.uk/) or [VulnHub](https://www.vulnhub.com/).
- **Extend It**: Add new checkers (e.g., CSRF) by subclassing `VulnerabilityChecker`.
- **Troubleshooting**: Check `neovuln.log` for errors. GUI logs update every 5s.

---

## ⚙️ Configuration

Edit `neovuln_config.json` for defaults:
```json
{
  "scan_timeout": 10,
  "max_threads": 5,
  "enable_xss": true,
  "enable_sqli": true,
  "proxy": "http://localhost:8080"
}
```
- Reload via **File > Load Config**.

---

## 📈 Performance & Limitations

- **Speed**: Multi-threaded for dir enum (up to 5 threads).
- **Limitations**: Basic checks only – not a full replacement for ZAP/Burp. For production, integrate with them.
- **Metrics**: Scans log requests/errors/duration.

---

## 🤝 Contributing

Love the neon aesthetic? Help us hack better! 💜

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/neon-enhance`).
3. Commit changes (`git commit -m 'Add dark mode toggle ✨'`).
4. Push & PR!



---

## 📜 License

This project is licensed under the MIT License - see [LICENSE] for details. Free for ethical use only. ⚖️

---

## 🙏 Acknowledgments

- Inspired by [OWASP ZAP](https://www.zaproxy.org/).
- Cyberpunk vibes: Neon dreams from Blade Runner & Ghost in the Shell. 🌌

<div align="center">
  <strong>Stay Secure, Stay Ethical. Hack the Planet... Responsibly! 🌍🔒</strong>
  <br><br>
  <a href="https://github.com/FreedomParrot/NeoVulnScanner/issues">Report a Bug</a> | 
  <a href="https://github.com/FreedomParrot/NeoVulnScanner/discussions">Discuss</a> | 
  <img src="https://img.shields.io/badge/⭐-Star%20Us-ff69b4.svg" alt="Star">
</div>

---

*Built with ❤️ in the shadows of the net ~FreedomParrot. Last updated: October 29, 2025*
