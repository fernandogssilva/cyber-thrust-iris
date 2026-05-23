# Como confiar no certificado CYBER THRUST

O CyberThrust.IRIS v0.1.1+ é assinado com um certificado **self-signed** da CYBER THRUST porque ainda não dispomos de Authenticode Code Signing comercial. Para que o Windows e o SmartScreen aceitem a assinatura sem mostrar "Editor desconhecido", o **administrador de TI do cliente** deve importar o certificado público (`.cer`) nos repositórios `Trusted Root Certification Authorities` e `Trusted Publishers`.

## O que está no Release

| Arquivo | Conteúdo | Distribuir? |
|---|---|---|
| `CyberThrust.IRIS-0.1.1-Setup.exe` | Instalador assinado | Sim — usuário final |
| `CyberThrust.IRIS-0.1.1-Portable-win-x64.zip` | EXE portátil assinado | Sim — usuário final |
| `cyberthrust-codesign-public.cer` | **Cert PÚBLICO** (sem chave privada) | Para o admin de TI |
| ~~`*.pfx`~~ | Cert **privado** | **NUNCA** distribuir; fica só com a CYBER THRUST |

## Caminho 1 — Implantação corporativa (recomendado para Tier 1)

### A) Via Microsoft Intune

1. **Intune Admin Center** → **Devices** → **Configuration profiles** → **Create profile**.
2. Platform: *Windows 10 and later*. Profile type: *Templates → Trusted certificate*.
3. Upload `cyberthrust-codesign-public.cer`.
4. Destination store: **Computer certificate store - Root** (e crie um segundo perfil para **Trusted Publisher**).
5. Atribua aos grupos de IR/SOC.

### B) Via GPO em domínio Active Directory

1. **Group Policy Management Console** → cria ou edita uma GPO ligada à OU dos analistas.
2. **Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies**:
   - **Trusted Root Certification Authorities → Import** → selecione o `.cer`.
   - **Trusted Publishers → Import** → mesmo `.cer`.
3. `gpupdate /force` nas estações.

### C) Via PowerShell (uma máquina avulsa, sem GPO/Intune)

Como Administrador:

```powershell
$cer = 'C:\path\para\cyberthrust-codesign-public.cer'
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

ou via `certutil` (mais antigo, mesmo efeito):

```cmd
certutil -addstore -f Root "cyberthrust-codesign-public.cer"
certutil -addstore -f TrustedPublisher "cyberthrust-codesign-public.cer"
```

## Caminho 2 — Usuário único, sem privilégios de admin

```powershell
$cer = '.\cyberthrust-codesign-public.cer'
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\Root
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\TrustedPublisher
```

Limitação: vale só para esse usuário Windows.

## Validação

Após import, verifique:

```powershell
$exe = 'C:\Program Files\CyberThrust\IRIS\CyberThrust.IRIS.exe'
Get-AuthenticodeSignature $exe | Select-Object Status, SignerCertificate, TimeStamperCertificate
```

Resultado esperado: `Status = Valid`. Se aparecer `UnknownError` ou `NotTrusted`, o cert não foi importado nos dois stores corretos.

## Hash de referência do cert público

Para conferir que você está importando o `.cer` legítimo da CYBER THRUST (e não um substituído por adversário):

```
SHA-256 do cyberthrust-codesign-public.cer:
3546F8BCCAADC1D269C733836C53C7F5EDED0BF573DA5619636F9E495A90E189
```

Confira esse hash **antes** de importar:

```powershell
Get-FileHash .\cyberthrust-codesign-public.cer -Algorithm SHA256
```

## Sobre o cert

- Subject: `CN=CYBER THRUST, O=CYBER THRUST, C=BR`
- Algoritmo: RSA 2048 + SHA-256
- EKU: `1.3.6.1.5.5.7.3.3` (Code Signing)
- Validade: 3 anos a partir da emissão
- Issuer: ele mesmo (self-signed)
- Thumbprint: `5A3CCBCFBF27445B2DBB26B4B340DE8A247889AC`

## Caminho de produção (futuro)

Quando a CYBER THRUST adquirir certificado **OV** (~US$ 200/ano DigiCert/Sectigo) ou **EV Code Signing** (~US$ 500/ano + token USB):
- A próxima versão do IRIS será assinada com a chave comercial.
- O CER atual pode ser desaposentado das estações.
- SmartScreen aceitará a assinatura sem nenhum import prévio (EV) ou após algumas semanas de reputação (OV).

Veja `docs/AUTHENTICODE_ROADMAP.md` para o plano completo.
