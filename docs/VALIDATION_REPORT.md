# Relatório de Validação — Tenant CrowdStrike Falcon

> Documento operacional gerado pela própria aplicação durante o **Health Check**. **Sem credenciais ou IDs sensíveis** — apenas o estado dos módulos.

## Execução de referência

| Campo | Valor |
|---|---|
| Data (UTC) | 2026-05-23T18:09Z |
| Cloud | `us-2` (https://api.us-2.crowdstrike.com) |
| OAuth2 | **OK** — token emitido em 1.6s, TTL 30 min |
| Hosts visíveis na frota | **632** |
| Put-files RTR já cadastrados | 2 |

## Matriz de capacidades

| Módulo | HTTP | Status | Necessário p/ IRIS |
|---|---|---|---|
| **Insight XDR — Detections / Alerts v2** | 200 | LICENCIADO | obrigatório |
| **RTR Admin — Scripts (read)** | 200 | LICENCIADO | obrigatório |
| **RTR Admin — Put-files (read)** | 200 | LICENCIADO | obrigatório (forensics) |
| **RTR — Session init (Write)** | 404 sobre AID inexistente | **WRITE OK** | obrigatório |
| **Hosts — Read** | 200 | LICENCIADO | obrigatório |
| **Hosts — Action contain (Write)** | 404 sobre AID inexistente | **WRITE OK** | obrigatório |
| Spotlight Vulnerabilities | 403 | Negado por scope OU licença | desejável |
| Discover (Asset Inventory) | 403 | Negado por scope OU licença | desejável |
| Surface (EASM / External Assets) | 403 | Negado por scope OU licença | desejável |
| Identity Protection | 404 | Módulo não na tenant | recomendado |
| LogScale / Humio | 404 | Módulo não na tenant | recomendado |
| Falcon Forensics (pacote pago) | 404 | Módulo não na tenant | opcional |
| Fusion SOAR (workflows) | 404 | Módulo não na tenant | opcional |
| Falcon Data Replicator | 404 | Módulo não na tenant | opcional |

### Como ler

- **HTTP 200/206**: módulo presente, key habilitada para leitura. Pode usar livremente.
- **HTTP 404 sobre AID inexistente** em endpoint Write (session init, contain): endpoint **existe** e a key tem **permissão de escrita** — apenas o ID que enviamos não existe (esperado). Confirma write OK.
- **HTTP 403**: a tenant **possivelmente tem o módulo**, mas a **API key não foi marcada com o scope correspondente**. Solução: editar a API key no Falcon Console → API clients and keys → marcar scope (sem custo, requer admin).
- **HTTP 404 sobre endpoint base** (sem id): o módulo **não está disponível** na tenant — não é uma questão de scope. Requer contrato com a CrowdStrike para habilitar.

## Veredito operacional

**A API key fornecida é suficiente para um piloto completo do IRIS sobre:**
- ✅ Triagem de detecções em tempo real (Insight XDR / Alerts v2)
- ✅ Inventário de hosts e busca por filtro FQL
- ✅ Contenção / lift containment de hosts
- ✅ Console RTR (single + batch) com 27 comandos
- ✅ Coleta KAPE / Velociraptor / UAC via RTR
- ✅ Coleta de memória (xmemdump nativo, DumpIt, WinPmem) via RTR
- ✅ Exfil direto para S3 / Azure Blob via runscript

**Para destravar mais funcionalidades nesta mesma tenant**, sem custo adicional (só ajuste de scope da API key):
- Spotlight → permite módulo *Vulnerabilities*
- Discover → permite módulo *Asset Inventory*
- Surface → permite módulo *EASM*

**Não disponíveis na tenant** (precisaria contratar):
- Identity Protection — sem ele, o grafo `IOC → User → Logon → LateralMove` fica incompleto (apenas baseado em detection telemetria)
- LogScale — sem ele, retenção da hunting fica nos 90 dias do Insight XDR
- Falcon Forensics (pacote pago) — não é o mesmo que RTR; **o IRIS não depende dele**, usa KAPE / Velociraptor / UAC via RTR
- Fusion SOAR — workflows internos do Falcon não acessíveis; o IRIS supre via sua própria orquestração
- Falcon Data Replicator — sem stream de eventos brutos para SIEM externo

## Próximos passos sugeridos

1. **Habilite scopes adicionais** na API key (Spotlight + Discover + Surface) para expandir visibilidade — só Account Executive CrowdStrike precisa autorizar.
2. **Suba os put-files essenciais** na Script Library do Falcon: `KAPE.zip`, `velociraptor-collector.exe`, `uac.tar.gz`, `DumpIt.exe`, `winpmem.exe` (ver `docs/CROWDSTRIKE_SETUP.md`).
3. **Gere presigned URL** para o bucket S3 / Azure Blob de evidência e configure em `appsettings.local.json` → `Exfil.PresignedUrlTemplate`.
4. **Inicie um piloto** contra 5-10 hosts marcados com tag `iris-pilot` antes de operar em produção.
