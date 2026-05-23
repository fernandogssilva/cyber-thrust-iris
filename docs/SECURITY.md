# Segurança, Custody Chain e LGPD/GDPR

## Princípios

1. **Mínimo privilégio**: a API key Falcon e o app Entra carregam apenas os escopos necessários.
2. **Secrets nunca no repo**: `appsettings.local.json` está no `.gitignore`. CI usa GitHub Secrets / Azure Key Vault.
3. **Token Cache cifrado**: MSAL salva em `%LOCALAPPDATA%\CyberThrust\IRIS\cache` usando DPAPI (Windows scope).
4. **TLS 1.2+**: HttpClient padrão .NET 8 — aceita só TLS 1.2/1.3.
5. **Logs sem PII**: usuários aparecem por UPN apenas em DEBUG. Em INFO, log usa `objectId`.

## Custody chain (cadeia de custódia)

Cada coleta gera registro estruturado:

```json
{
  "jobId": "f0d3a8e2c4d4...",
  "tool": "KAPE",
  "aid": "abc123...",
  "operatorUpn": "fernandogssilva@cyberthrust.com.br",
  "operatorObjectId": "...",
  "startedUtc": "2026-05-23T14:33:21Z",
  "finishedUtc": "2026-05-23T14:51:08Z",
  "artifactUri": "s3://cyberthrust-iris-evidence/abc123/kape.zip",
  "artifactSha256": "9f86d081884c7d65...",
  "artifactBytes": 814572032,
  "irisVersion": "0.1.0"
}
```

Esse JSON é gravado em `evidence/{aid}/{jobId}.json` e exportado para o ticket de IR.

## LGPD (Brasil) e GDPR (UE)

- Dados pessoais coletados durante incidente são **dados sensíveis** (`Art. 11 LGPD`).
- Base legal: legítimo interesse + cumprimento de obrigação legal contratual.
- **Retenção**: 180 dias por padrão; configurável por contrato. Past 180d → expurgo automático no bucket S3 com Lifecycle Policy.
- **Direito de acesso**: operadores documentados via Entra logs.
- **Notificação ANPD**: se vazamento detectado, dispare playbook BACEN/ANPD em 48h.

## Reportar vulnerabilidade no IRIS

Email: security@cyberthrust.com.br (PGP key em https://cyberthrust.com.br/.well-known/security.txt).
Não abra issue pública para CVE. Tempo de resposta SLA: 48h úteis.

## Boas práticas operacionais

- **Nunca rode RTR contra hosts sem autorização escrita** do cliente. RTR é considerado coleta forense.
- **Faça hashing antes e depois** da exfil — confirme SHA-256 no S3.
- **Use sempre presigned URL com TTL curto** (4-8h), não chave estática.
- **Treine os analistas** em FALCON 240 ou equivalente antes de dar permissão `IRIS.Responder`.
