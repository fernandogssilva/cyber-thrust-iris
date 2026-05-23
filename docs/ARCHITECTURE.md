# Arquitetura — CyberThrust.IRIS

## Visão de alto nível

```
┌────────────────────────────────────────────────────────────────────┐
│                       CyberThrust.IRIS.App  (WPF)                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Shell (MainWindow)                                          │  │
│  │   ├─ TopBar (user, build label, sign-out)                    │  │
│  │   ├─ Sidebar (Dashboard, Incidents, RTR, Forensics, …)       │  │
│  │   ├─ ContentControl ← Views/ViewModels via DI                │  │
│  │   └─ StatusBar (Entra status, Falcon status, msg)            │  │
│  └──────────────────────────────────────────────────────────────┘  │
│      ▲ MVVM (CommunityToolkit.Mvvm)                                │
│      │                                                             │
│  ┌───┴────────────┬──────────────┬──────────────┬───────────────┐  │
│  │ NavigationSvc  │ HealthChkSvc │ DialogService│ Logging       │  │
│  └────────────────┴──────────────┴──────────────┴───────────────┘  │
└────────────────────────────────────────────────────────────────────┘
            │ DI (Microsoft.Extensions.DependencyInjection)
            ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────┐
│ EntraID      │   │ CrowdStrike  │   │ Forensics    │   │ Memory  │
│  MSAL + DPAPI│   │  OAuth2+RTR  │   │  KAPE/Velo/  │   │ xmemdump│
│  Broker WAM  │   │  Probe (lic.)│   │  UAC via RTR │   │ DumpIt  │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └────┬────┘
       │                  │                  │                │
       └──────────────────▼──────────────────▼────────────────┘
                             Core (Errors, Result, Models, Abstractions)
```

## Princípios

1. **Modularidade flutuante**: cada vertical (auth, falcon, forensics, memory, graph) é um projeto separado com sua interface no `Core`. A UI compõe via DI. Trocar uma implementação não obriga rebuild do mundo.
2. **Degradação graciosa**: a `FalconCapabilityProbe` detecta o que está licenciado e expõe ao `MainViewModel`. Cada View consulta o estado e desabilita botões com tooltip explicativo — **nada quebra por falta de licença**.
3. **Erros estruturados**: tudo retorna `Result<T>` ou levanta `IrisException` carregando `IrisErrorCode`. A UI exibe `IRIS-CS-2012` em vez de "erro desconhecido".
4. **Self-validation**: o `HealthCheckService` é a fonte de verdade do estado do app. Roda na abertura, no menu, e antes de qualquer operação crítica.
5. **Custody chain**: toda coleta gera `JobId` UUID, hash SHA-256 do artefato, timestamp UTC e usuário Entra que autorizou. Os logs Serilog (rolling diário) carregam essa correlação.
6. **Não-comercial visível**: chip permanente "Internal Use / Non-Commercial Build" no shell + texto na `LoginView` e `Settings`. Não é só licença — é UI.

## Fluxos críticos

### 1. Login e probe
1. `App.OnStartup` constrói o `Host` e o DI.
2. `MainWindow` carrega `MainViewModel` → `InitializeAsync` tenta `SignInSilentAsync` (cache DPAPI).
3. Se silencioso falha, navega para `LoginView`.
4. Pós-login: `FalconCapabilityProbe.ProbeAsync()` chama 10 endpoints de leitura leve, mapeia 200/403/404 → licenciamento.
5. StatusBar mostra Entra=verde, Falcon=verde + lista de módulos. Sidebar habilita itens conforme.

### 2. Coleta forense remota (KAPE exemplo)
1. Operador escolhe host AID + targets/modules KAPE + URL exfil presigned.
2. `KapeOrchestrator.StartCollectionAsync`:
   - `StartRtrSessionAsync(aid)` → `RtrSessionInfo`.
   - `Put` do KAPE.zip (registrado previamente como put-file no Falcon).
   - `RunScript` expand-archive.
   - `RunScript` executa kape.exe com `--zip kape-{aid}`.
   - `RunScript` faz `Invoke-WebRequest PUT` direto para o presigned S3.
   - `RunScript` limpa C:\Windows\Temp\KAPE*.
3. `IProgress<JobProgress>` atualiza a UI em % e estágio.

### 3. Coleta de memória
- Hosts ≤ 4GB RAM → `memdump`/`xmemdump` nativo Falcon + `get`.
- Hosts > 4GB → exfil **direto** via `Invoke-WebRequest PUT` para presigned URL (evita o gargalo de 4GB do `get`).
- Análise pós-coleta: SuperMem (Volatility 2/3 + bulk_extractor) ou MemProcFS como filesystem montado.

### 4. Grafo de ataque
1. `AttackGraphBuilder` consulta detections + (futuro) Identity Protection + LogScale.
2. Constrói `AttackNode`/`AttackEdge` (IOC → Host → User → Process → Net).
3. Serializa para `{ elements: [...] }` Cytoscape.
4. `AttackTreeView` injeta JSON no WebView2 via `ExecuteScriptAsync("window.loadGraph(...)")`.
5. Layout dagre LR, paleta neon CYBER THRUST.

## Decisões arquiteturais (ADRs resumidos)

| # | Decisão | Por quê |
|---|---------|---------|
| 1 | WPF .NET 8, não WinUI 3 | Maturidade do tooling, instalador menor, runtime já pré-instalado no Win11, performance |
| 2 | Cytoscape.js via WebView2 | Melhor render de grafo do mercado JS; tempo curto até foto final; sem dependência de OxyPlot/etc. |
| 3 | MSAL com broker WAM | SSO transparente em joined-machine, MFA via WebAuthn, melhor UX |
| 4 | Result pattern + IrisException | Códigos previsíveis na UI; menos try/catch espalhado |
| 5 | Central Package Management | Versões consistentes em 8 projetos sem repetição |
| 6 | Sem auto-update no MVP | Reduz surface de ataque; updates passam por canal CYBER THRUST controlado |
| 7 | Exfil direto para cloud no host | Resolve o limite ~4GB do RTR `get` (documentado em CrowdStrike docs) |
| 8 | Capability Probe leve | Não consome quotas pesadas; degrada UI sem quebrar fluxos |

## Performance

- **Tela inicial < 1s** após `dotnet run` (em SSD).
- **Probe de capabilities < 3s** (10 chamadas paralelizáveis — versão atual é sequencial; otimizar na v0.2).
- **Memória ociosa < 80MB** (medido em build Release).
- **Sem auto-refresh agressivo** — toda atualização é manual (`Atualizar`) para preservar bateria de notebooks de analista em incidente longo.

## Extensibilidade futura

- **Plugins**: trocar `IForensicsCollector` por descoberta MEF para terceiros (Magnet, Cyber Triage).
- **SOAR**: emissor de eventos OpenC2 para XSOAR/Splunk SOAR.
- **AI Triage**: hook para Claude/Charlotte AI análisar grafo + sugerir hipóteses.
- **Modo offline**: cache LogScale local com tantivy/Lucene.
