# Review Crítica — Diretor de Tecnologia + Cliente

## Persona: **Diretor de Tecnologia (Cliente Tier 1)**

> "Eu paguei caro pelo Falcon. Por que preciso de mais uma ferramenta?"

### Pontos duros levantados ao **Gerente de Desenvolvimento**

1. **"Esse app pode rodar offline durante uma crise?"**
   - **Resposta atual**: parcialmente. MSAL precisa rede para token, Falcon API idem. Coletas locais (analyzer SuperMem/MemProcFS) funcionam offline desde que binários estejam em `tools/external/`.
   - **GAP**: precisamos de modo "evidence-only" que aceite dumps locais sem rede. **AÇÃO**: criar `IrisLocalAnalyzerView` na v0.2.

2. **"Por que WPF e não WinUI 3?"**
   - **Resposta**: WPF é mais estável no Win10 corporativo. Win11 only ainda não é realidade no nosso parque (Allianz, Bradesco, BMG têm 30%+ Win10). Migrar quando atingir 80% Win11.

3. **"O grafo é bonito mas é útil?"**
   - **Resposta**: hoje só desenha detections recentes. **GAP**: amarrar Identity Protection + LogScale lateral movement. **AÇÃO**: v0.3 entrega grafo IOC→User→Logon→Process→Net→LateralHop.

4. **"E se o analista for novo? A UI joga código de erro IRIS-CS-2034 e ele não sabe o que fazer."**
   - **Resposta**: ERROR_CODES.md já tem hint por código. **AÇÃO v0.2**: tooltip na UI com o texto do hint, sem precisar abrir docs.

### Ao **Gerente de Middleware**

5. **"O HttpClient para Falcon tem retry?"**
   - **Sim**, via `AddHttpMessageHandler<FalconAuthHandler>` + Polly (decorate via `Microsoft.Extensions.Http.Polly`). **PORÉM** ainda não está configurado o policy default. **AÇÃO**: adicionar exponencial 3 retries em 5xx/429/timeout.

6. **"Token cache concorrente?"**
   - MSAL gerencia internamente, mas o nosso FalconAuthHandler tem `SemaphoreSlim(1,1)` para evitar dupla emissão. ✅

7. **"Onde está o circuit breaker?"**
   - **GAP**. Adicionar Polly Circuit Breaker no client Falcon — após 5 falhas em 60s, abre por 30s. v0.2.

### Ao **Gerente de SI**

8. **"Onde estão os logs?"**
   - `%LOCALAPPDATA%\CyberThrust\IRIS\logs` rolling diário, 14 dias retenção. ✅
   - **GAP**: precisamos forward para LogScale do CYBER THRUST. **AÇÃO**: adicionar sink Serilog HTTP para LogScale na v0.2.

9. **"Hashing de evidência?"**
   - Está documentado mas **não implementado no código** ainda. **AÇÃO**: bloqueador para v0.2.

10. **"Quem tem acesso a executar `kill` em produção?"**
    - Hoje qualquer Active Responder. **GAP**: precisamos aplicar `roles` claim Entra como gate por Command. **AÇÃO**: `[RequiresIrisRole("IRIS.Responder")]` attribute na v0.2.

### Ao **Gerente de Infraestrutura**

11. **"Deploy em 200 estações? Como?"**
    - MSIX + Intune. Branch policy assina o pacote.
    - **GAP**: pipeline GitHub Actions ainda monta só Debug build. **AÇÃO**: estágio MSIX + sign no `build.yml`.

12. **"Quanto consome de RAM?"**
    - Medido <80MB ocioso na build inicial. WebView2 sobe quando entra em "Árvore de Ataque" (~+150MB). Aceitável.
    - **GAP**: ainda não fizemos perf test com 500 detections. Pode haver lag no DataGrid.

13. **"Atualizações?"**
    - **NÃO HÁ** auto-update no MVP. Operadores devem rodar instalador novo. Para v0.2: assinatura + canal "stable/edge" via Squirrel.Windows ou Velopack.

---

## Persona: **Cliente final (Analista IR de Allianz/Bradesco)**

> "Acabei de receber um alerta crítico às 03h. O que faço primeiro?"

### Fluxo cliente → Diretor (lista de melhorias)

| # | Item | Severidade | Categoria | Status |
|---|------|-----------|-----------|--------|
| C1 | Tela inicial deveria mostrar "Top 5 ações sugeridas" automaticamente | Alta | UX | Pending |
| C2 | Botão "Isolar host" tem que estar a 1 clique do alerta | Crítica | UX | Pending |
| C3 | Falta atalho de teclado para navegar entre módulos (Ctrl+1..9) | Média | UX | Pending |
| C4 | Quando o probe falha, deveria mostrar **qual** credencial falhou (Entra vs Falcon) | Alta | UI | ✅ separado em StatusBar |
| C5 | Faltam relatórios prontos: "Resumo do incidente", "Vulnerabilidades expostas", "Misconfig de Entra" | Crítica | Funcional | Pending v0.3 |
| C6 | Falta integração com Jira/ServiceNow para abrir ticket direto do incidente | Alta | Integração | Pending v0.3 |
| C7 | Visualização da árvore deve permitir filtrar por tactic MITRE | Alta | UX | Pending v0.2 |
| C8 | Quero ver % de progresso real durante coleta KAPE, não só "estágio" | Alta | UX | ✅ JobProgress já reporta % |
| C9 | Quando RTR falha 2x, sugerir comando alternativo (ex: ps falha → `tasklist`) | Média | Helper | Pending v0.3 |
| C10 | Modo "apresentação" sem dados sensíveis para mostrar em call com cliente | Baixa | UX | Pending |
| C11 | Notificação Windows toast quando coleta termina | Média | UX | Pending |
| C12 | Logs deveriam ser exportáveis em formato CSV/JSON pelo próprio app | Média | Funcional | Pending |

---

## Cronograma de remediação (prioridades acordadas)

| Sprint | Foco | Itens |
|---|---|---|
| v0.2 (Junho) | Robustez | Polly retry + circuit breaker, hashing evidência, RBAC por role, tooltip de hint, atalhos teclado, perf test 500 detections, sink LogScale |
| v0.3 (Julho) | Funcional | Grafo Identity + lateral, relatórios prontos, integração Jira/ServiceNow, filtro tactic MITRE, modo offline analyzer |
| v0.4 (Agosto) | Distribuição | Auto-update Velopack, MSIX signing no CI, deploy Intune, treinamento ops |

---

## Veredito do CTO

> "Tem fundação. Os módulos estão bem isolados, os erros têm código, a UI não desabiliza nada por falta de licença. **Mas até v0.2 não vai para produção em cliente Tier 1.** As 12 ações acima são bloqueadoras. Aprovado para piloto interno e teste contra tenant lab."

**Assinado**: Direção de Tecnologia — CYBER THRUST, 2026-05-23.
