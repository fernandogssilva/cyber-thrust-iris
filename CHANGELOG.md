# Changelog

All notable changes to CyberThrust.IRIS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.9] — 2026-05-24 — Hotfix sintaxe RTR `runscript -Raw`

### Fixed
- **CRÍTICO: todos os 29 comandos `runscript -Raw` falhavam com `Falcon API 400 — Command is not valid (code 40006)`**. A sintaxe correta da Falcon RTR para script inline exige **três crases (` ``` `) delimitando o código PowerShell**, mas eu havia escrito `runscript -Raw=<código>` sem as crases — o parser do Falcon não consegue determinar onde o argumento termina e devolve erro 40006.
- Arquivos corrigidos (29 ocorrências):
  - `Services/RtrScriptCatalog.cs` — 23 dos 20 scripts cross-categoria (recon · persistência · usuários · forense · coleta)
  - `ViewModels/ForensicsViewModel.cs` — 4 ocorrências (KAPE · Velociraptor · UAC · default)
  - `ViewModels/MemoryViewModel.cs` — 2 ocorrências (WinPmem · DumpIt)
- Padrão antes (errado): `runscript -Raw=if(Test-Path 'C:\...'){ & ... }`
- Padrão depois (correto): `` runscript -Raw=```if(Test-Path 'C:\...'){ & ... }``` ``
- Referência: `VelociraptorOrchestrator.cs` no módulo Forensics já usava a sintaxe correta — só não foi propagada para os ViewModels e o catálogo de scripts.

### Note
Nenhuma mudança funcional além do fix. Todos os 4 itens da v0.4.8 (Console RTR + Script auto-executado, Cards de IP intel, AID completo + copy, Árvore de Ataque por alerta) agora **realmente funcionam** — antes terminavam com erro RTR 400.

## [0.4.8] — 2026-05-24

### Added
- **Botão "Console RTR + Script"** no painel de Detecções — agora abre o RTR, conecta automaticamente e **executa o script de investigação mais apropriado** baseado nos IOCs do alerta:
  - Tem `filename` ou `cmdline` → executa `process-tree` parametrizado com o processo
  - Tem `logon_domain` ou `user_name` → executa `logon-history`
  - Tem `ip_address`, `domain` ou `url` → executa `connections`
  - Fallback → `sys-info`
- **Cards de Inteligência de IPs** no painel de detalhes — cada IP de origem/destino enriquecido com:
  - **Geolocalização** (país, região, cidade) via ip-api.com (free, sem chave, 45 req/min)
  - **ISP / Organização / AS Number**
  - **Reputação multi-fonte** (VirusTotal · MalwareBazaar · URLhaus · ThreatFox) com verdict colorido (🔴/🟡/🟢/⚪)
  - **Detection ratio** N/M engines
  - **Botão copiar** o IP
  - Detecção de IP privado (RFC 1918) → pula chamada externa
- **AID + Composite ID completos** no painel — caixas de texto monospace, somente leitura, **selecionáveis e com botão de copiar dedicado**. Antes só aparecia AID truncado (`abc123...`).
- **Árvore de Ataque por alerta** — quando você seleciona um alerta e clica "🕸 Árvore de Ataque" (botão do painel ou menu de contexto), a tela Attack Tree agora constrói um **grafo Cytoscape específico do alerta** com até 10 nós em sequência:
  - **(User)** → **(Host)** → **(Parent Process)** → **(Process)** → **(File Hash)** → **(IP)** / **(Domain)** / **(URL)** → **(Detection)**
  - Cada nó com metadata tooltip (cmdline, hash, IP completo, PID, MITRE técnica)
  - Edges rotuladas: `logged_on`, `executed`, `spawned`, `loaded`, `connected_to`, `resolved`, `accessed`, `triggered`
- **`IpIntelService`** — novo serviço usando ip-api.com (zero-storage, em memória apenas) com detecção automática de IP privado.

### Changed
- Botão "Console RTR" no detail panel **deixou de ser passivo** — agora sempre auto-executa script de investigação ao chegar no Console RTR (antes só pré-preenchia AID).
- `AttackTreeViewModel` reescrito do zero para consumir `AlertInvestigationContext`. O fallback para grafo "live" agregado continua disponível quando não há alerta selecionado.
- Tela Attack Tree com novo header mostrando contexto do alerta (nome · host · MITRE · severidade · timestamp) + estado vazio amigável quando não há alerta selecionado.
- Rota `attacktree` / `attack-tree` / `ataque` adicionada ao `NavigationService` (todas resolvem para `AttackTreeView`).

## [0.4.7] — 2026-05-24 — Hotfix do instalador

### Fixed
- **CRÍTICO: Instalador v0.4.4/v0.4.5/v0.4.6 não incluía DLLs nem `runtimeconfig.json`**. O script Inno Setup `.iss` só copiava o `CyberThrust.IRIS.exe` (que é apenas o apphost de 180 KB) e o `appsettings.json` — sem a DLL gerenciada (`CyberThrust.IRIS.dll`), sem `runtimeconfig.json`, sem `deps.json` e sem as ~70 DLLs de dependências (CommunityToolkit.Mvvm, Serilog.*, Microsoft.Identity.Client, etc.). Resultado: ao executar, o .NET host falhava com `IRIS-NET-1001 The application to execute does not exist: 'CyberThrust.IRIS.dll'` — antes de inicializar o Serilog, sem deixar rastro no log nem no `crash.log`.
- A regressão foi introduzida quando `<PublishSingleFile>` foi mudado para `false` no `csproj` — o EXE deixou de ser auto-contido mas o instalador continuou só copiando ele. Corrigido para empacotar **todo o conteúdo de `publish\win-x64\*`** (96 arquivos · 68 DLLs · main DLL · runtimeconfig + deps + WebAssets).
- Versões 0.4.4, 0.4.5 e 0.4.6 dos Setup.exe estão **inutilizáveis** — instalam mas não abrem. Use exclusivamente o `CyberThrust.IRIS-0.4.7-Setup.exe`.

### Note
Nenhuma mudança funcional no código da aplicação em relação à v0.4.6 — todas as features de v0.4.6 (right-click context menu, painel enriquecido com IOCs/Device Profile/Alertas Correlacionados, RTR Host Card, cross-module IOC context) estão presentes. Esta release entrega exatamente o que v0.4.6 deveria ter entregue, agora num instalador funcional.

## [0.4.6] — 2026-05-24

### Added
- **Menu de contexto (botão direito) em Detecções** — ações cross-módulo direto na grade, sem precisar abrir o painel lateral:
  - Investigar no Console RTR · Investigar processo (RTR) · Conexões de rede (RTR) · Histórico de logon (RTR)
  - Coleta com Velociraptor · Forense (disco) · Capturar Memória
  - Reputação (VT/AbuseIPDB) · Conter / Levantar contenção
  - Copiar AID / Composite ID / Hostname
  - Escalar para Incidente · Marcar Verdadeiro+/Falso+
- **Painel de investigação enriquecido** — ao clicar em qualquer detecção o painel agora chama Falcon API em paralelo e exibe:
  - **IOCs / Telemetria** — chips clicáveis (copiam para clipboard) com SHA256, MD5, caminho, processo, cmdline, parent process, IP local/externo, domínio, URL. Extraídos automaticamente do alerta.
  - **Perfil do Dispositivo** — OS, versão, IP local/externo, domínio AD, OU, hardware (manufacturer/model), agente Falcon, status de contenção, primeira/última conexão.
  - **Alertas correlacionados no mesmo host (24 h)** — lista compacta com severidade, técnica MITRE e timestamp.
- **Auto-enriquecimento via `GetDeviceProfileAsync`** — novo método em `IFalconClient` chama `/devices/entities/devices/v2` retornando 16 campos do device.
- **`FalconAlertsFilter.Aid`** — novo parâmetro que filtra a query Alerts API v2 por `agent_id`, usado para correlação no mesmo host.
- **Extração automática de IOCs** — `FalconClient.ListAlertsAsync` agora popula `FalconAlert.Extra` com 17 campos (hashes, IPs, processos, cmdlines, parent process, domínio, URL, user principal, falcon_host_link).
- **`AlertInvestigationContext` enriquecido** — agora carrega IpAddress, Sha256, Md5, FilePath, ProcessName, CommandLine, UserName, Domain e `PreferredRtrScriptId` para comunicação entre todos os módulos.
- **Console RTR com auto-fill de filtros** — ao navegar de uma detecção, os campos Hostname/IP/Hash/Usuário/Processo/Domínio são pré-preenchidos com os IOCs extraídos.
- **Console RTR com Host Card enriquecido** — ao conectar, o sidebar exibe automaticamente um card com OS, IPs, domínio AD, versão do agente e status de contenção. Chamada paralela a `GetDeviceProfileAsync`.
- **Auto-execução de script preferido** — clicar "Investigar processo (RTR)" no menu de contexto abre o RTR, conecta e executa automaticamente o script `process-tree` parametrizado com o nome do processo do alerta. Mesma mecânica para `connections` e `logon-history`.

### Changed
- `AlertInvestigationContext.SetFromAlert` agora extrai IOCs do dict `Extra` do alerta.
- `RtrConsoleViewModel.Connect` agora dispara `FetchDeviceProfileAsync` em paralelo após sessão estabelecida.

## [0.4.5] — 2026-05-24

### Added
- **Filtros de investigação no Console RTR** — painel lateral com campos Hostname (com busca AID automática via 🔎), IP, Domínio, Hash (SHA256/MD5), Usuário e Processo. Os valores substituem os tokens `{HOST}/{IP}/{DOMAIN}/{HASH}/{USER}/{PROCESS}` nos scripts do catálogo.
- **Catálogo de 20 scripts CrowdStrike** no Console RTR — derivados dos repositórios públicos `psfalcon`, `falcon-scripts` e `detection-strategy-scripts`. Organizados em 5 categorias:
  - 🔍 Reconhecimento do Sistema (5 scripts Low): sys-info, process-tree, connections, autoruns, scheduled-tasks
  - ⏰ Persistência e Autoinício (5 scripts Medium): services, startup-entries, registry-run, drivers, wmi-subscriptions
  - 👤 Usuários e Credenciais (4 scripts Low): local-users, active-sessions, logon-history, powershell-history
  - 🔬 Artefatos Forenses (6 scripts Low): prefetch-list, event-ids-security, event-ids-system, lnk-files, recycle-bin, mft-list
  - 💾 Coleta de Evidências (4 scripts High): memdump-xrtr, disk-triage-kape, disk-triage-velo, disk-triage-uac
- **Busca de host por hostname** — `SearchHostCommand` no RTR chama `IFalconClient.SearchHostsAsync`, preenche AID automaticamente e exibe resultado inline.
- **Tela Memória RAM completa** — substitui o placeholder; suporta 3 ferramentas:
  - **xmemdump** (nativo Falcon RTR Active Responder, sem upload de binário)
  - **WinPmem** (Velocidex, open source, put-and-run)
  - **DumpIt** (Comae, profissional, put-and-run)
  - Seleção visual por card com indicador nativo/OSS/PRO.
  - Banner e saída terminal em tempo real; caminho do dump exibido pós-captura com instrução `get` para recuperação.
- **Tela Forense de Disco completa** — substitui o placeholder; suporta KAPE, Velociraptor e UAC com:
  - Escopo granular: EventLogs, RegistryHives, Prefetch, WebBrowsers, Sistema/LNK, Rede, Triage Completo.
  - Botões Selecionar Todos / Nenhum para seleção rápida de escopo.
  - Ferramenta pré-selecionada quando navegado via botão "Velociraptor" em Detecções.
- **Zero-Storage enforced** — dumps e artefatos forenses criados no endpoint remoto via RTR; nota informativa visível em ambas as telas.
- `ForensicsViewModel` e `MemoryViewModel` promovidos a `AddSingleton` na DI — sessão RTR sobrevive à navegação entre telas.

### Changed
- `PlaceholderViewModels.cs` esvaziado: todos os ViewModels migrados para arquivos dedicados.

## [0.4.4] — 2026-05-24

### Added
- **Painel lateral de investigação em Detecções** — clicar em qualquer linha da grade abre um painel de 440 px à direita com todos os campos do alerta (severidade, nome da detecção, endpoint, identidade, MITRE ATT&CK, descrição) sem sair da tela.
- **Ações de IR direto na detecção** — botões inline no painel:
  - **Conter Host** / **Levantar Contenção** — chama Falcon Network Containment API em 1 clique; feedback de sucesso/erro inline.
  - **Console RTR** — navega para o console com AID pré-preenchido e conecta automaticamente.
  - **Velociraptor** — navega para Forense com ferramenta Velociraptor pré-selecionada.
  - **Forense (Disco)** / **Capturar Memória** — atalhos para os módulos correspondentes com contexto de investigação preenchido.
- **Atualizar status do alerta** — botões Em Progresso / Verdadeiro+ / Falso+ / Ignorar / Fechar chamam `PATCH /alerts/entities/alerts/v2` diretamente; a grade recarrega silenciosamente após sucesso.
- **Encaminhar para Incidente** — marca o alerta como `in_progress` e exibe instrução para o analista acompanhar em Incidentes (Ctrl+2); integra ao fluxo de correlação automática do Falcon.
- **Console RTR real** (`RtrConsoleViewModel` + `RtrConsoleView`) — substitui o placeholder:
  - Terminal monoespaçado com histórico de saída colorido (Info/Prompt/Output/Error/Success).
  - Barra de comandos com tecla Enter + botão Executar.
  - Quick-actions: `ls`, `ps`, `netstat`, `ipconfig`, `whoami`, `env`, `history`, `reg query`, `tasklist (runscript)`, `autoruns (runscript)`.
  - Botões **Conter Host** e **Levantar Contenção** disponíveis também na console RTR.
  - Auto-scroll para a última linha a cada nova saída.
  - Sessão singleton: sessão RTR sobrevive a navegação entre telas (o analista pode ir a Incidentes e voltar sem perder o terminal).
  - Desconectar limpa a sessão; o contexto de investigação persiste.
- **`AlertInvestigationContext`** (singleton em memória) — transporta AID, hostname e ferramenta forense preferida entre Detecções → RTR / Forense / Memória. Zero-Storage: nenhum dado escrito em disco.

### Changed
- `RtrConsoleViewModel` promovido de `AddTransient` para `AddSingleton` na DI para preservar a sessão RTR ativa durante a navegação.
- `AlertsViewModel` passou a receber `AlertInvestigationContext` via constructor injection.

## [0.4.3] — 2026-05-24

### Fixed
- **Detecções aparecendo em branco** — `POST /alerts/entities/alerts/v2` retornava `HTTP 400 "at least one identifier should be present in the request"` (`IRIS-CS-2013`). A Alerts API v2 do Falcon **exige o campo `composite_ids`** no body, e o cliente estava enviando `ids` (contrato antigo da `/detects` deprecada). Corrigido em `FalconClient.ListAlertsAsync` e `FalconClient.ListRecentDetectionsAsync`.
- **Mapeamento do schema v2 do Alerts API** — os detalhes vinham como `null` mesmo após o fix do `composite_ids` porque o cliente tentava ler `device.hostname` / `tactic` / `technique` / `user_name` no topo, mas a API moderna retorna esses dados em:
  - `host_names[0]` (preferido) ou `source_endpoint_host_name` (fallback EPP).
  - `mitre_attack[0].{tactic, technique, tactic_id, technique_id}` em vez do topo.
  - `display_name` (NG-SIEM/IDP) em vez de só `name` (técnico EDR).
  - `source_account_name` (IDP) em vez de `user_name`.
  - `source_vendors[0]` em vez de `vendor` string.
  - Fallback de `updated_timestamp` → `crawled_timestamp` quando ausente.
- Helpers privados `ExtractHostname`, `ExtractMitre`, `ExtractUserName`, `ExtractFirstFromStringArray` em `FalconClient` para isolar a complexidade do schema.

### Validated
- Endpoint real `api.us-2.crowdstrike.com` com credenciais Falcon do tenant: `GET /alerts/queries/alerts/v2` → `meta.pagination.total: 8141`; `POST /alerts/entities/alerts/v2` com `{"composite_ids":[...]}` → 200 OK com detalhes completos; com `{"ids":[...]}` → 400 (reproduz o bug do v0.4.2).

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
