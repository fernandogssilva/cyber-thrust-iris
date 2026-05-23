# Códigos de Erro IRIS

Todo erro exibido ao operador carrega um código `IRIS-{CAT}-{NNNN}` que permite triagem rápida.
A categoria identifica a camada; os 4 dígitos identificam o caso específico.

## Categorias

| Prefixo | Faixa | Camada |
|---|---|---|
| `IRIS-AUTH` | 1000–1999 | Autenticação Entra ID |
| `IRIS-CS`   | 2000–2999 | CrowdStrike Falcon API / RTR |
| `IRIS-MEM`  | 3000–3999 | Coleta e análise de memória |
| `IRIS-DSK`  | 4000–4999 | Coleta e triagem de disco |
| `IRIS-NET`  | 5000–5999 | Rede / conectividade / TLS |
| `IRIS-UI`   | 6000–6999 | Camada WPF / apresentação |
| `IRIS-CFG`  | 7000–7999 | Configuração e secrets |
| `IRIS-PLG`  | 8000–8999 | Ferramentas externas (KAPE, Velociraptor, etc.) |
| `IRIS-SYS`  | 9000–9999 | OS, runtime, genéricos |

## AUTH — Entra ID

| Código | Quando aparece | Como resolver |
|---|---|---|
| `IRIS-AUTH-1001` | SignIn interativo falhou | Verifique conexão e Conditional Access |
| `IRIS-AUTH-1002` | Cache MSAL inválido | Force logout e login interativo |
| `IRIS-AUTH-1003` | Token expirado e refresh falhou | Refaça login |
| `IRIS-AUTH-1004` | Consentimento administrativo requerido | Admin do tenant precisa aprovar app |
| `IRIS-AUTH-1005` | MFA pendente | Conclua MFA no popup |
| `IRIS-AUTH-1006` | Conditional Access bloqueou | Verifique device compliance e localização |
| `IRIS-AUTH-1007` | ClientId/Tenant inválidos | Confira `appsettings.local.json` |
| `IRIS-AUTH-1008` | Tenant mismatch | Sua conta não pertence ao tenant configurado |
| `IRIS-AUTH-1009` | Claim `roles` ausente | Atribua roles no Entra App Roles |
| `IRIS-AUTH-1010` | Cache DPAPI corrompido | Apague `%LOCALAPPDATA%\CyberThrust\IRIS\cache` |
| `IRIS-AUTH-1011` | Conta bloqueada | Contate IT do tenant |

## CS — CrowdStrike

| Código | Quando aparece | Como resolver |
|---|---|---|
| `IRIS-CS-2001` | OAuth2 falhou | Confira ClientId/Secret Falcon |
| `IRIS-CS-2002` | OAuth2 sem escopo | Habilite os escopos da API key no Falcon Support Portal |
| `IRIS-CS-2003` | Cloud inválido | Cloud deve ser us-1/us-2/eu-1/us-gov-1 |
| `IRIS-CS-2010` | 401 numa rota | Token expirou; auto-refresh deveria ter agido — reabra |
| `IRIS-CS-2011` | 403 numa rota | Sem permissão no escopo |
| `IRIS-CS-2012` | 429 Rate Limited | Reduza paralelismo; aguardar back-off |
| `IRIS-CS-2013` | 5xx Falcon | Status CrowdStrike — retry automático Polly |
| `IRIS-CS-2014` | 502 Bad Gateway | Transitório — retry |
| `IRIS-CS-2015` | Timeout | Aumente `HttpTimeoutSeconds` |
| `IRIS-CS-2020` | Capability probe falhou | Re-rode Health Check |
| `IRIS-CS-2021` | Módulo não licenciado | Funcionalidade desabilitada; contate seu Account Exec |
| `IRIS-CS-2030` | RTR init session falhou | Host offline ou sem permissão RTR |
| `IRIS-CS-2031` | RTR session expirou | Recrie sessão |
| `IRIS-CS-2032` | Comando RTR rejeitado | Verifique base_command e command_string |
| `IRIS-CS-2033` | RTR command timeout | Aumente timeout, ou divida o trabalho |
| `IRIS-CS-2034` | get > 4GB falhou | Use exfil direto via runscript |
| `IRIS-CS-2035` | Batch falhou parcial | Inspecione `RtrCommandResult.Stderr` por AID |
| `IRIS-CS-2036` | Script RTR ausente | Suba o script para a Script Library |
| `IRIS-CS-2040` | Host offline | Verifique conexão e LastSeen |
| `IRIS-CS-2041` | Host não encontrado | AID errado ou removido |
| `IRIS-CS-2042` | Contenção falhou | Sem permissão ou host offline |
| `IRIS-CS-2050` | Conflito de IOC | IOC já existe com outra severidade |
| `IRIS-CS-2060` | Detection não encontrada | ID inválido |

## MEM — Memória

| Código | Detalhe |
|---|---|
| `IRIS-MEM-3001` | Coletor não encontrado / não configurado |
| `IRIS-MEM-3002` | `xmemdump` falhou |
| `IRIS-MEM-3003` | WinPmem falhou |
| `IRIS-MEM-3004` | DumpIt falhou |
| `IRIS-MEM-3010` | Disco insuficiente no host alvo |
| `IRIS-MEM-3020` | Upload para storage falhou (presigned expired/403) |
| `IRIS-MEM-3030` | Análise (Volatility/MemProcFS) falhou |
| `IRIS-MEM-3031` | SuperMem ausente em `tools/external/supermem` |
| `IRIS-MEM-3032` | Volatility ausente |
| `IRIS-MEM-3033` | MemProcFS ausente |

## DSK — Disco / Forensics

| Código | Detalhe |
|---|---|
| `IRIS-DSK-4001` | KAPE binário ausente em `tools/external/kape/kape.exe` |
| `IRIS-DSK-4002` | KAPE execution failed (ver stderr) |
| `IRIS-DSK-4003` | Velociraptor ausente |
| `IRIS-DSK-4004` | Velociraptor execution failed |
| `IRIS-DSK-4005` | UAC ausente |
| `IRIS-DSK-4006` | UAC execution failed |
| `IRIS-DSK-4010` | Exfil falhou |
| `IRIS-DSK-4011` | Presigned URL expirou — gere outra |
| `IRIS-DSK-4020` | Disco local insuficiente para parsing |
| `IRIS-DSK-4030` | Parsing artefato falhou |

## NET — Rede

| Código | Detalhe |
|---|---|
| `IRIS-NET-5001` | DNS resolution failed |
| `IRIS-NET-5002` | TLS handshake failed |
| `IRIS-NET-5003` | Proxy auth required |
| `IRIS-NET-5004` | Ping/connectivity check failed |
| `IRIS-NET-5005` | Certificate invalid |
| `IRIS-NET-5010` | WebView2 navigation failed |

## UI — Apresentação

| Código | Detalhe |
|---|---|
| `IRIS-UI-6001` | Theme load failed |
| `IRIS-UI-6002` | WebView2 Runtime ausente |
| `IRIS-UI-6003` | View binding failed |
| `IRIS-UI-6004` | Navigation failed |
| `IRIS-UI-6005` | Asset ausente |

## CFG — Configuração

| Código | Detalhe |
|---|---|
| `IRIS-CFG-7001` | Arquivo de config ausente |
| `IRIS-CFG-7002` | JSON inválido |
| `IRIS-CFG-7003` | Campo obrigatório ausente |
| `IRIS-CFG-7004` | Secret ausente |
| `IRIS-CFG-7005` | Path inválido |
| `IRIS-CFG-7006` | Seção EntraId inválida |
| `IRIS-CFG-7007` | Seção Falcon inválida |

## PLG — Plugins / ferramentas externas

| Código | Detalhe |
|---|---|
| `IRIS-PLG-8001` | Binário externo ausente |
| `IRIS-PLG-8002` | Assinatura inválida |
| `IRIS-PLG-8003` | Versão antiga |
| `IRIS-PLG-8004` | Crash da ferramenta externa |

## SYS — Sistema

| Código | Detalhe |
|---|---|
| `IRIS-SYS-9000` | Erro genérico desconhecido — abra issue com log |
| `IRIS-SYS-9001` | Operação cancelada |
| `IRIS-SYS-9002` | Out of memory |
| `IRIS-SYS-9003` | OS não suportado |
| `IRIS-SYS-9004` | Elevation necessária |
| `IRIS-SYS-9005` | File system error |
| `IRIS-SYS-9006` | Serialização falhou |

---

### Como reportar um erro

1. Copie o código (clique direito → copiar no DataGrid de Health Check).
2. Anexe o log de `%LOCALAPPDATA%\CyberThrust\IRIS\logs\iris-YYYYMMDD.log`.
3. Abra issue no repo privado descrevendo o passo a passo.
