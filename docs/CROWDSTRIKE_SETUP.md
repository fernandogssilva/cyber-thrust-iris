# Configuração do CrowdStrike Falcon

## 1. Criar API Key

1. Falcon Console → **Support and resources** → **API clients and keys** → **Create API client**.
2. Nome: `CyberThrust.IRIS`. Descrição: aplicação interna de IR.
3. Selecione os escopos necessários conforme a operação desejada:

| Escopo | Permissão | Necessário para |
|---|---|---|
| Hosts | Read | listar hosts, status |
| Hosts | Write | contenção / lift |
| Detections | Read | dashboard |
| Detections | Write | acknowledge, assign |
| Alerts | Read & Write | API v2 (Falcon 2.0) |
| Real Time Response | Read | abrir sessões / consultar |
| Real Time Response | Write | comandos read-only (`ls`, `ps`, `netstat`) |
| Real Time Response (Admin) | Write | comandos invasivos (`kill`, `rm`, `runscript`, `xmemdump`) |
| Real Time Response (Admin) | Read | scripts e put-files |
| IOC Management | Read & Write | adicionar IOC custom |
| Spotlight | Read | vulnerabilidades |
| Identity Protection | Read | grafo de identidade |
| Discover | Read | inventário |
| LogScale / Humio | Read | hunting queries (se licenciado) |

Mínimo absoluto: **Hosts Read**, **Detections Read**, **Real Time Response Read/Write**.

4. Copie **Client ID** e **Client Secret** (o Secret só aparece UMA VEZ).
5. Identifique seu **Cloud**:
   - `us-1` → https://falcon.crowdstrike.com
   - `us-2` → https://falcon.us-2.crowdstrike.com
   - `eu-1` → https://falcon.eu-1.crowdstrike.com
   - `us-gov-1` → https://falcon.laggar.gcw.crowdstrike.com

## 2. RTR Scripts e Put-Files

Para o módulo Forensics funcionar, suba os binários como put-files na **Script Library** do Falcon:

| Arquivo | Caminho local | Uso |
|---|---|---|
| `KAPE.zip` | Compactar a pasta KAPE | KapeOrchestrator |
| `velociraptor-collector.exe` | Gerar no Velociraptor admin UI | VelociraptorOrchestrator |
| `uac.tar.gz` | Download em [tclahr/uac](https://github.com/tclahr/uac/releases) | UacOrchestrator |
| `DumpIt.exe` | Download Magnet Forensics | MemoryCollector (DumpIt) |
| `winpmem.exe` | [Velocidx/WinPmem](https://github.com/Velocidex/WinPmem) | MemoryCollector (WinPmem) |

No Falcon Console → **Configuration** → **Response policies** → **Real Time Response** → **Put files** → upload.

## 3. appsettings.local.json

```json
{
  "Falcon": {
    "Cloud": "us-1",
    "ClientId": "abcdef0123456789abcdef0123456789",
    "ClientSecret": "Z9y8x7w6v5u4t3s2r1q0p..."
  }
}
```

## 4. Exfil — presigned URL

Configure um bucket S3 ou Azure Blob para receber evidência. Gere presigned URLs (TTL 4-8h) por job:

```bash
# AWS exemplo
aws s3 presign s3://cyberthrust-iris-evidence/aid-XXXX/kape.zip --expires-in 28800
```

Cole na seção `Exfil.PresignedUrlTemplate`.

## Validação

Health Check → "Falcon — capability probe" deve aparecer **Pass** com a lista de módulos licenciados.
