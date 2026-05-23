# Configuração do Entra ID (Azure AD)

## 1. Registrar a aplicação

1. Acesse [Entra Admin Center → Identity → App registrations](https://entra.microsoft.com/).
2. **New registration**:
   - Name: `CyberThrust.IRIS`
   - Supported account types: *Accounts in this organizational directory only*
   - Redirect URI (Platform: **Public client/native (mobile & desktop)**): `http://localhost`
3. Copie o **Application (client) ID** e o **Directory (tenant) ID** para `appsettings.local.json`.

## 2. Permissões de API

Em **API permissions** → Add:

| API | Permission | Type |
|---|---|---|
| Microsoft Graph | `User.Read` | Delegated |
| Microsoft Graph | `Group.Read.All` (opcional) | Delegated |
| Microsoft Graph | `Directory.Read.All` (opcional) | Delegated |
| Microsoft Graph | `SecurityAlert.Read.All` (recomendado) | Delegated |

Clique em **Grant admin consent for {tenant}**.

## 3. App Roles (RBAC IRIS)

Em **App roles** → Create:

| Display name | Value | Description |
|---|---|---|
| IRIS Admin | `IRIS.Admin` | Acesso total: contenção, IOCs, configurações |
| IRIS Responder | `IRIS.Responder` | RTR + Forensics + Memory |
| IRIS Analyst | `IRIS.Analyst` | Read-only + dashboards + grafo |

Em **Enterprise Applications** → CyberThrust.IRIS → Users and groups → atribua usuários a cada role.

## 4. Conditional Access

Recomendado criar uma política dedicada:
- Grant: require MFA + compliant device
- Sign-in frequency: 12 horas

## 5. Authentication

- **Allow public client flows**: **Yes** (necessário para WAM broker + PKCE).
- **Logout URL**: deixe vazio.

## 6. appsettings.local.json

```json
{
  "EntraId": {
    "TenantId": "11111111-2222-3333-4444-555555555555",
    "ClientId": "66666666-7777-8888-9999-aaaaaaaaaaaa",
    "RedirectUri": "http://localhost",
    "Scopes": ["User.Read", "Group.Read.All"],
    "UseBroker": true
  }
}
```

## Validação

Na aplicação, **Health Check** → "Entra ID configurado" deve aparecer **Pass**.
Faça login → o nome do usuário aparece na TopBar e Status Entra fica verde.
