# Changelog

All notable changes to CyberThrust.IRIS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-05-23

### Changed
- **License**: switched from "Internal Use / Non-Commercial" to **Apache License 2.0**. The project is now **fully open source**.
- **Branding**: UI chip changed from *"Internal Use / Non-Commercial Build"* to **"Open Source · Apache 2.0"** across MainWindow, SplashWindow, LoginView and Inno Setup.
- **NOTICE** file added with third-party attribution table.
- **README** rewritten for an open source audience, with contribution call-to-action and OSS badges.

### Added
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- `.github/ISSUE_TEMPLATE/` with bug, feature and security templates.
- `.github/PULL_REQUEST_TEMPLATE.md`.
- `.github/FUNDING.yml` sponsor placeholder.
- Ethical-use notice in LICENSE clarifying that the project must not be used against unauthorized systems.

### Repository
- Visibility changed from **private** to **public** at `github.com/fernandogssilva/cyber-thrust-iris`.

## [0.1.1] — 2026-05-23

### Added
- Binaries are now **Authenticode-signed** with a self-signed CYBER THRUST certificate (RSA 2048, SHA-256, Code Signing EKU, valid until 2029-05-23) plus DigiCert RFC 3161 timestamp.
- `docs/TRUST_CERTIFICATE.md` — step-by-step on how to install the public `.cer` in **Trusted Root** + **Trusted Publisher** via Intune, GPO, PowerShell or certutil.
- `docs/AUTHENTICODE_ROADMAP.md` — comparison matrix of self-signed vs OV vs EV vs Microsoft Store.
- `publish/signing/sign-all.ps1` — idempotent re-signing helper.

### Fixed
- `HealthCheckService` was missing `using System.IO;` and was passing `Exception` into the `Hint` (string) parameter of `IrisError`. Now uses the `Cause:` named parameter.
- `EntraAuthenticator` depended on `System.IdentityModel.Tokens.Jwt` without an explicit `PackageReference` — added to Central Package Management.
- `LoginView.xaml` had an invalid `{x:Static ...BooleanToVisibilityConverter.}` syntax — replaced by an instance in `UserControl.Resources`.
- `Views/PlaceholderViews.xaml` had an empty XAML root that broke MSBuild WPF — removed.
- `FalconCapabilityProbe` now treats HTTP 405 as "endpoint present" (write-only endpoints like RTR session init and host containment respond 405 to GET probes).

## [0.1.0] — 2026-05-23

### Added
- Initial release of CyberThrust.IRIS — Incident Response & Investigation Suite for Windows.
- 8-project .NET 8 solution (Core, EntraID, CrowdStrike, Forensics, Memory, Graph, App, Tests, Installer).
- 90+ structured `IRIS-*` error codes documented in `docs/ERROR_CODES.md`.
- `Result<T>` pattern + Serilog rolling daily logs.
- **MSAL.NET** integration with WAM broker + DPAPI cache.
- **CrowdStrike OAuth2** client with auto-refresh, alerts v2, hosts, RTR single/batch and `FalconCapabilityProbe` that detects licensed modules without breaking the UI.
- **KAPE / Velociraptor / UAC** orchestrators via RTR with direct exfil to S3/Azure Blob.
- **Memory acquisition** via `xmemdump`, Magnet DumpIt and WinPmem.
- **Attack graph** rendered with Cytoscape.js inside a WebView2 host.
- **Health Check** view with 12 self-validations and clear IRIS-* error codes.
- WPF shell with **dark-futuristic theme**, MSAL login, splash screen, keyboard shortcuts (Ctrl+1..6 / F1 / Ctrl+L / F5), custom `.ico`.
- **Inno Setup** installer with pt-BR/en wizard, EULA, Start Menu shortcuts, uninstaller.
- Self-contained single-file `.exe` (~80 MB) — no .NET runtime install required.
- Full documentation set (README, ARCHITECTURE, ERROR_CODES, INSTALL, ENTRA_SETUP, CROWDSTRIKE_SETUP, SECURITY, CONTRIBUTING, CTO_REVIEW, VALIDATION_REPORT).

[0.2.0]: https://github.com/fernandogssilva/cyber-thrust-iris/releases/tag/v0.2.0
[0.1.1]: https://github.com/fernandogssilva/cyber-thrust-iris/releases/tag/v0.1.1
[0.1.0]: https://github.com/fernandogssilva/cyber-thrust-iris/releases/tag/v0.1.0
