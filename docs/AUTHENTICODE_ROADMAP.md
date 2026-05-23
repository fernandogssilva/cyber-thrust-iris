# Roadmap de assinatura Authenticode

| Estado | Como | Custo anual | UX no cliente | Quando |
|---|---|---|---|---|
| **Hoje (v0.1.1)** | Self-signed CYBER THRUST 2048 RSA | R$ 0 | Cliente importa `.cer` em Trusted Root via Intune/GPO. SmartScreen aceita depois disso. | Já entregue |
| **v0.2 (Q3 2026)** | OV Code Signing (Sectigo/DigiCert) | ~US$ 200 | Sem import. SmartScreen alerta "Editor desconhecido" por algumas semanas até construir reputação. | Quando adquirir |
| **v1.0 (produto)** | EV Code Signing (Sectigo/DigiCert/SSL.com) + USB token | ~US$ 500 + hardware | **Zero atrito**. SmartScreen aceita imediatamente. Reputação instantânea. | Quando virar produto comercial |
| Alternativa | Submeter ao **Microsoft Store / Partner Center** | R$ 0 | Microsoft assina. Cliente instala via Store ou Intune Private Store. | Quando ficar OK rodar review |

## Por que self-signed agora

- Custo: zero.
- Tempo: 5 minutos.
- Funciona em domínio corporativo (GPO/Intune) sem dor.
- Permite seguir adiante com piloto em cliente sem aguardar compra.
- Cadeia de custódia: a assinatura física + timestamp DigiCert estão lá; aumenta integridade contra adulteração do binário pós-publish.

## Por que NÃO ficar para sempre em self-signed

- SmartScreen continua alertando para usuários fora do domínio.
- Implementadores precisam tomar a ação extra de importar o `.cer` antes da primeira instalação — gera fricção em deploys ad-hoc.
- Reputação não construída no Windows Defender Cloud — não pode aproveitar telemetria positiva da Microsoft.

## Roadmap detalhado

### Q3 2026 — OV Code Signing
1. Comprar OV cert (~US$ 200 Sectigo).
2. Substituir self-signed em `Set-AuthenticodeSignature`.
3. Versão `v0.2.0` re-assinada.
4. Documentar SmartScreen warning temporário.

### Q4 2026 — EV Code Signing (decisão depende de tração comercial)
1. Comprar EV cert + USB hardware token (~US$ 500 + token).
2. Assinatura passa a usar `signtool /fd SHA256 /sha1 <thumbprint>` via token.
3. SmartScreen aceita imediatamente.
4. Versão `v1.0.0` lançada como pacote comercial.

### Alternativa em qualquer momento — Microsoft Store private
1. Criar conta Partner Center (US$ 19 una vez).
2. Submeter MSIX (já temos manifest).
3. Aprovação em 1-7 dias.
4. Cliente instala via Store ou Intune Private Store.
5. Microsoft assina por nós.

## Hashes de cada release devem ir junto

Toda release v0.x.y do IRIS publica:
- `.exe` Setup
- `.zip` portátil
- `cyberthrust-codesign-public.cer` (até virar OV/EV)
- SHA-256 de todos os artefatos no body do Release

Isso compõe a cadeia de custódia mínima.
