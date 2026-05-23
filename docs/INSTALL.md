# Instalação

## Pré-requisitos

| Item | Versão | Como instalar |
|---|---|---|
| Windows | 10 22H2 ou Windows 11 | nativo |
| .NET 8 Desktop Runtime | 8.0.x | `winget install Microsoft.DotNet.DesktopRuntime.8` |
| .NET 8 SDK (só para compilar) | 8.0.x | `winget install Microsoft.DotNet.SDK.8` |
| Microsoft Edge WebView2 | Evergreen | pré-instalado no Win11 |
| Git | 2.40+ | `winget install Git.Git` |
| GitHub CLI (opcional) | latest | `winget install GitHub.cli` |

## Build de desenvolvimento

```powershell
cd "C:\Users\ferna\OneDrive\Documentos\Empresas\CYBER THRUST\Tecnologias\10-Resposta a Incidente"
dotnet restore
dotnet build -c Debug
dotnet run --project src/CyberThrust.IRIS.App
```

## Build de produção (single-folder)

```powershell
dotnet publish src/CyberThrust.IRIS.App -c Release -r win-x64 --self-contained false -o publish/win-x64
```

O resultado em `publish/win-x64` pode ser copiado para qualquer Windows com o runtime instalado.

## Instalador MSIX (futuro)

Arquivo `src/CyberThrust.IRIS.Installer/Package.appxmanifest` está pronto.
Empacotamento via [MSIX Packaging Tool](https://learn.microsoft.com/en-us/windows/msix/packaging-tool/tool-overview)
ou `MakeAppx.exe` da SDK. O app é assinado com certificado interno CYBER THRUST.

## Pasta de dados

| Pasta | Conteúdo |
|---|---|
| `%LOCALAPPDATA%\CyberThrust\IRIS\logs` | Logs Serilog rolling diário |
| `%LOCALAPPDATA%\CyberThrust\IRIS\cache` | Cache MSAL (DPAPI) |
| `%LOCALAPPDATA%\CyberThrust\IRIS\evidence` | Artefatos baixados (configurável) |

## Pós-instalação

1. Copie `appsettings.local.json.example` → `appsettings.local.json`.
2. Edite e preencha Entra (Tenant + ClientId) e Falcon (ClientId + Secret + Cloud).
3. Abra a aplicação → faça login → vá em **Health Check** → execute.
4. Resolva qualquer item `Warn`/`Fail` antes de operar.

## Verificação rápida

A tela `Health Check` deve mostrar **Pass** em pelo menos:
- Runtime .NET 8
- Windows 10/11
- WebView2 Runtime
- Conectividade
- Entra ID configurado
- Falcon — capability probe
- Logs writable

Itens `Skipped` em "Ferramentas" (KAPE, Velociraptor, etc.) são opcionais — habilitam coletas locais.
