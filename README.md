# CyberThrust.IRIS

**Incident Response & Investigation Suite** — aplicação Windows nativa de DFIR que orquestra CrowdStrike Falcon RTR, Entra ID e ferramentas open-source (KAPE, Velociraptor, UAC, WinPmem, SuperMem, MemProcFS, Volatility) numa única interface modular, leve e responsiva.

> **Build status**: ![internal](https://img.shields.io/badge/build-internal-blue) ![license](https://img.shields.io/badge/license-Non--Commercial-orange) ![dotnet](https://img.shields.io/badge/.NET-8.0-512BD4) ![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4)

## O que faz

- **Login Entra ID** com MSAL (PKCE, Conditional Access, cache DPAPI).
- **Console CrowdStrike** com **Falcon Capability Probe** — detecta automaticamente quais módulos a tenant tem licenciados (Insight XDR, Identity Protection, Spotlight, LogScale, Discover, Surface) e **degrada graciosamente** sem quebrar a UI quando algo falta.
- **RTR em escala**: shell remoto contra 1 a N hosts, batch de comandos, runscripts, get/put, kill/quarantine, isolamento.
- **Forense remota** via RTR: KAPE (Win), UAC (Linux/macOS/ESXi), Velociraptor offline collector — exfil direto para S3/Azure Blob com presigned URL (sem o gargalo de 4GB do `get`).
- **Memória RAM**: `xmemdump` nativo + Magnet DumpIt / WinPmem como fallback + análise pós-coleta com SuperMem e MemProcFS.
- **Grafo de ataque futurista** (Cytoscape.js via WebView2) com IOC → User → Process → Network → Lateral movement, linha do tempo e mapeamento MITRE ATT&CK.
- **Self-Validation**: tela de Health Check executa 30+ verificações automáticas e reporta código de erro IRIS-xxxxx claro para qualquer falha.
- **Relatórios** de incidente, vulnerabilidades, falhas de configuração — exportáveis em PDF/DOCX/JSON.

## Requisitos

- Windows 10 22H2 / Windows 11
- .NET 8 Desktop Runtime ([download](https://dotnet.microsoft.com/download/dotnet/8.0))
- Microsoft Edge WebView2 Runtime (pré-instalado no Windows 11)
- Conta Entra ID (cliente registrado — ver [docs/ENTRA_SETUP.md](docs/ENTRA_SETUP.md))
- API key CrowdStrike Falcon com escopos mínimos (ver [docs/CROWDSTRIKE_SETUP.md](docs/CROWDSTRIKE_SETUP.md))

Funciona **sem licenças extras** do Falcon — recursos cuja licença não está presente aparecem desabilitados com tooltip explicativo, nunca quebram a aplicação.

## Estrutura

```
CyberThrust.IRIS/
├── src/
│   ├── CyberThrust.IRIS.App/           # WPF shell (UI dark futurista)
│   ├── CyberThrust.IRIS.Core/          # Modelos, erros, abstrações
│   ├── CyberThrust.IRIS.EntraID/       # MSAL + DPAPI token cache
│   ├── CyberThrust.IRIS.CrowdStrike/   # OAuth2 + RTR + Capability Probe
│   ├── CyberThrust.IRIS.Forensics/     # KAPE / Velociraptor / UAC
│   ├── CyberThrust.IRIS.Memory/        # WinPmem / DumpIt / SuperMem
│   ├── CyberThrust.IRIS.Graph/         # Builder de grafo de ataque
│   └── CyberThrust.IRIS.Installer/     # MSIX manifest
├── tests/
├── tools/external/                     # binários KAPE, Velociraptor, etc. (não versionado)
├── docs/                               # Architecture, Error Codes, Install, etc.
└── .github/workflows/                  # CI build
```

## Build rápido

```powershell
# Instale o SDK .NET 8 (única pré-condição)
winget install Microsoft.DotNet.SDK.8

# Restaurar e compilar
dotnet restore
dotnet build -c Release

# Rodar
dotnet run --project src/CyberThrust.IRIS.App
```

## Configuração

1. Copie `src/CyberThrust.IRIS.App/appsettings.local.json.example` para `appsettings.local.json`.
2. Preencha tenant Entra, ClientId, scopes, Falcon ClientId/Secret e cloud (us-1, us-2, eu-1, us-gov-1).
3. Execute a aplicação — o **Login** valida Entra e o **Health Check** valida tudo o mais.

## Documentação

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — arquitetura modular, fluxos de dados, decisões.
- [docs/ERROR_CODES.md](docs/ERROR_CODES.md) — catálogo completo de códigos IRIS-xxxxx.
- [docs/INSTALL.md](docs/INSTALL.md) — instalação e empacotamento MSIX.
- [docs/ENTRA_SETUP.md](docs/ENTRA_SETUP.md) — registrar app no Entra ID.
- [docs/CROWDSTRIKE_SETUP.md](docs/CROWDSTRIKE_SETUP.md) — gerar API key Falcon.
- [docs/SECURITY.md](docs/SECURITY.md) — manuseio de evidência, LGPD/GDPR, custody chain.
- [docs/CTO_REVIEW.md](docs/CTO_REVIEW.md) — review crítica do Diretor de TI + Cliente.
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) — padrões de código.

## Status

Build de uso interno **não comercial** — ver [LICENSE](LICENSE).
Mantido por **CYBER THRUST**. Contato: fernandogssilva (GitHub).
