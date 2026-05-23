# Installer (MSIX)

Configuração de empacotamento MSIX para distribuição interna via Microsoft Intune ou MSIX App Installer.

## Pré-requisitos
- Certificado de assinatura interno CYBER THRUST (CN=CYBER THRUST, O=CYBER THRUST, C=BR).
- Windows SDK (MakeAppx.exe, signtool.exe).

## Empacotar

```powershell
$src = "..\..\publish\win-x64"
$out = "..\..\publish\CyberThrust.IRIS_0.1.0.0_x64.msix"
MakeAppx.exe pack /d $src /p $out
signtool.exe sign /fd SHA256 /a /f cyberthrust-cert.pfx /p $env:CT_CERT_PW $out
```

## Distribuir
- Upload no Intune → Win32 apps (MSIX) → Required deploy para `IRIS Responders` group.
- Ou via canal direto: `https://internal.cyberthrust.com.br/iris/install.appinstaller`.

## Branding
- `Assets\Square*.png`, `Assets\StoreLogo.png` ainda **não criados** — substituir pelo logo CYBER THRUST + chip "Internal Use".
