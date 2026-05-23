# CyberThrust.IRIS

**Incident Response & Investigation Suite** — open source Windows DFIR application that orchestrates **CrowdStrike Falcon RTR**, **Microsoft Entra ID** and battle-tested open source tools (KAPE, Velociraptor, UAC, WinPmem, SuperMem, MemProcFS, Volatility) inside a single modular, fast, dark-futuristic interface.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4.svg)](https://dotnet.microsoft.com/download/dotnet/8.0)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4.svg)](#)
[![Release](https://img.shields.io/github/v/release/fernandogssilva/cyber-thrust-iris?include_prereleases)](https://github.com/fernandogssilva/cyber-thrust-iris/releases/latest)
[![Issues](https://img.shields.io/github/issues/fernandogssilva/cyber-thrust-iris)](https://github.com/fernandogssilva/cyber-thrust-iris/issues)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/CONTRIBUTING.md)

---

## 📥 Download — install with 2 clicks

> 👉 **Grab the latest installer from [Releases](https://github.com/fernandogssilva/cyber-thrust-iris/releases/latest)**.

| Package | For whom | Size |
|---|---|---|
| **`CyberThrust.IRIS-0.2.0-Setup.exe`** | Most users — pt-BR/en wizard, Start Menu shortcut, uninstaller. **Signed.** | ~74 MB |
| `CyberThrust.IRIS-0.2.0-Portable-win-x64.zip` | Runs without installing (USB, restricted machine). Extract and double-click. **Signed.** | ~74 MB |
| `cyberthrust-codesign-public.cer` | Public cert for your IT admin to trust before first install. | < 1 KB |
| `SHA256SUMS.txt` | Integrity manifest for all release assets. | < 1 KB |

**Requirements**: Windows 10 22H2 or Windows 11. **No additional runtime needed** — `.NET 8` is bundled (self-contained, single-file).

> ✅ Binaries are **Authenticode-signed** (SHA-256 + DigiCert RFC 3161 timestamp) with a self-signed CYBER THRUST certificate.
> To silence SmartScreen, your IT admin should import `cyberthrust-codesign-public.cer` into **Trusted Root** + **Trusted Publisher** via Intune, GPO or PowerShell. Step-by-step in **[docs/TRUST_CERTIFICATE.md](docs/TRUST_CERTIFICATE.md)**.

**After install**: edit `appsettings.local.json` in the install folder with your Entra Tenant + Falcon API key. See [docs/ENTRA_SETUP.md](docs/ENTRA_SETUP.md) and [docs/CROWDSTRIKE_SETUP.md](docs/CROWDSTRIKE_SETUP.md).

---

## 🚀 What it does

- **Entra ID Login** with MSAL (PKCE, Conditional Access, DPAPI-protected cache, WAM broker).
- **CrowdStrike Console** with **Falcon Capability Probe** — automatically detects which modules are licensed on your tenant (Insight XDR, Identity Protection, Spotlight, Discover, Surface, LogScale, Forensics, Fusion, FDR, RTR Admin) and **gracefully degrades** the UI without crashing when something is missing.
- **RTR at scale**: remote shell against 1 to N hosts, batch commands, scripts, get/put, kill/quarantine, host isolation.
- **Remote forensics** via RTR: KAPE (Windows), UAC (Linux/macOS/ESXi), Velociraptor offline collector — direct exfil to S3/Azure Blob via presigned URL (no 4GB cap of `RTR get`).
- **Memory acquisition**: native `xmemdump` + Magnet DumpIt / WinPmem fallback + post-collection analysis with SuperMem and MemProcFS.
- **Futuristic attack graph** (Cytoscape.js via WebView2) wiring IOC → User → Process → Network → Lateral movement, MITRE ATT&CK-tagged.
- **Self-Validation**: Health Check view runs 12+ automated checks and reports a clear `IRIS-*` error code for any failure.
- **Reports** for incident, vulnerabilities and misconfigurations — exportable to PDF/DOCX/JSON (v0.3).

## ⌨️ Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+1..6` | Dashboard, Incidents, RTR Console, Forensics, Memory, Attack Tree |
| `F1` or `Ctrl+7` | Health Check (self-validation) |
| `Ctrl+8` | Settings |
| `Ctrl+L` | Sign out |
| `F5` | Refresh (re-probe Falcon) |

## 🏗️ Architecture

```
CyberThrust.IRIS/
├── src/
│   ├── CyberThrust.IRIS.App/          # WPF shell (dark-futuristic UI)
│   ├── CyberThrust.IRIS.Core/         # Models, errors, abstractions
│   ├── CyberThrust.IRIS.EntraID/      # MSAL + DPAPI token cache
│   ├── CyberThrust.IRIS.CrowdStrike/  # OAuth2 + RTR + Capability Probe
│   ├── CyberThrust.IRIS.Forensics/    # KAPE / Velociraptor / UAC
│   ├── CyberThrust.IRIS.Memory/       # WinPmem / DumpIt / SuperMem
│   ├── CyberThrust.IRIS.Graph/        # Attack graph builder
│   └── CyberThrust.IRIS.Installer/    # MSIX + Inno Setup
├── tests/                             # xUnit + FluentAssertions
├── tools/external/                    # Optional binaries (KAPE, Velo, etc.)
├── docs/                              # Architecture, ERROR_CODES, setup guides
└── .github/                           # Issue/PR templates, dependabot, CI
```

Full deep-dive: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## 🛠️ Build from source

```powershell
# Prereqs (once)
winget install Microsoft.DotNet.SDK.8
winget install Git.Git

# Clone
git clone https://github.com/fernandogssilva/cyber-thrust-iris.git
cd cyber-thrust-iris

# Build & run
dotnet restore
dotnet build -c Release
dotnet run --project src/CyberThrust.IRIS.App
```

## 🤝 Contributing

**PRs welcome!** This is a community-driven security tool — bug fixes, modules, integrations, translations, docs. Read [CONTRIBUTING.md](docs/CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Open issues are labeled `good-first-issue` to help newcomers.

Roadmap and CTO review (gaps blocking enterprise-grade adoption): **[docs/CTO_REVIEW.md](docs/CTO_REVIEW.md)**.

## ⚖️ License

Released under the **[Apache License 2.0](LICENSE)** — free for commercial and non-commercial use, with patent grant.

Third-party attributions in **[NOTICE](NOTICE)**.

## ⚠️ Ethical use

CyberThrust.IRIS performs active response (process termination, host isolation, memory/disk acquisition). **Use it only against systems for which you hold explicit written authorization.** Unauthorized use may violate Brazilian Lei 12.737/2012 (Lei Carolina Dieckmann), US CFAA, EU GDPR/NIS2 and equivalent laws.

## 🔒 Security

Found a vulnerability? **Do not open a public issue.** Use the [private security advisory channel](https://github.com/fernandogssilva/cyber-thrust-iris/security/advisories/new) or email `security@cyberthrust.com.br`. Disclosure policy in [docs/SECURITY.md](docs/SECURITY.md).

## 📚 Documentation

- [Architecture](docs/ARCHITECTURE.md) — modular design, data flows, ADRs
- [Error Codes](docs/ERROR_CODES.md) — 90+ structured `IRIS-*` codes
- [Install](docs/INSTALL.md) — installer + MSIX packaging
- [Entra Setup](docs/ENTRA_SETUP.md) — register the app in Microsoft Entra ID
- [CrowdStrike Setup](docs/CROWDSTRIKE_SETUP.md) — generate Falcon API key + put-files
- [Trust Certificate](docs/TRUST_CERTIFICATE.md) — make Windows trust our binaries
- [Authenticode Roadmap](docs/AUTHENTICODE_ROADMAP.md) — path from self-signed to EV/Store
- [Security & LGPD/GDPR](docs/SECURITY.md) — custody chain, retention, PII handling
- [Validation Report](docs/VALIDATION_REPORT.md) — capability matrix against a real Falcon tenant
- [CTO Review](docs/CTO_REVIEW.md) — independent critique with v0.2/v0.3/v0.4 backlog
- [Contributing](docs/CONTRIBUTING.md) — coding standards, branches, commit style

## 💚 Acknowledgements

Built on the shoulders of the open source DFIR community. Special thanks to the maintainers of **CrowdStrike Falcon-Toolkit**, **Velociraptor**, **KAPE**, **UAC** ([@tclahr](https://github.com/tclahr) — Brazilian, like us 🇧🇷), **WinPmem**, **SuperMem**, **MemProcFS**, **Volatility**, **MSAL.NET**, **CommunityToolkit.Mvvm**, **Cytoscape.js**, **Serilog**, **WPF-UI**, and the broader Microsoft .NET team.
