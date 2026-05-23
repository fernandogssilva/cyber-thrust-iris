using System.IdentityModel.Tokens.Jwt;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensions.Msal;

namespace CyberThrust.IRIS.EntraID;

/// <summary>
/// Implementação MSAL.NET com:
///  - WAM broker (Windows Authentication Manager) quando disponível
///  - PKCE em fluxo interativo
///  - Cache persistente DPAPI (Microsoft.Identity.Client.Extensions.Msal)
///  - SignIn silencioso primeiro, fallback para interativo
/// </summary>
public sealed class EntraAuthenticator : IAuthenticator, IAsyncDisposable
{
    private readonly EntraOptions _options;
    private readonly ILogger<EntraAuthenticator> _log;
    private readonly IPublicClientApplication _app;
    private IrisIdentity? _current;

    public bool IsAuthenticated => _current is not null && _current.TokenExpiresUtc > DateTimeOffset.UtcNow.AddMinutes(2);

    public EntraAuthenticator(EntraOptions options, ILogger<EntraAuthenticator> log)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _log = log;

        if (string.IsNullOrWhiteSpace(_options.ClientId))
            throw new IrisException(IrisErrorCode.CfgEntraSectionInvalid, "EntraId:ClientId não configurado em appsettings.local.json.");

        // ClientId placeholder zerado → não tenta inicializar MSAL/WAM (P/Invoke nativo pode crashar)
        if (_options.ClientId.StartsWith("00000000", StringComparison.Ordinal))
        {
            throw new IrisException(IrisErrorCode.CfgEntraSectionInvalid,
                "EntraId:ClientId está como placeholder zero. Configure em appsettings.local.json antes de fazer login.",
                hint: "Veja docs/ENTRA_SETUP.md");
        }

        var builder = PublicClientApplicationBuilder.Create(_options.ClientId)
            .WithAuthority($"https://login.microsoftonline.com/{_options.TenantId}")
            .WithRedirectUri(_options.RedirectUri);

        // WAM broker só quando explicitamente habilitado + Windows. WAM falha nativamente em
        // configurações inválidas (ClientId não registrado no tenant), então mantemos opt-in.
        if (_options.UseBroker && OperatingSystem.IsWindows())
        {
            try
            {
                builder = builder.WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
                {
                    Title = "CyberThrust.IRIS"
                });
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "WAM broker indisponível, usando browser fallback.");
            }
        }

        _app = builder.Build();
        _ = InitCacheAsync();
    }

    private async Task InitCacheAsync()
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberThrust", "IRIS", "cache");
            Directory.CreateDirectory(dir);
            var storage = new StorageCreationPropertiesBuilder(_options.CacheFileName, dir)
                .WithUnprotectedFile()
                .Build();
            var cache = await MsalCacheHelper.CreateAsync(storage).ConfigureAwait(false);
            cache.RegisterCache(_app.UserTokenCache);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "MSAL cache persistente falhou; usando memória.");
        }
    }

    public async Task<Result<IrisIdentity>> SignInInteractiveAsync(CancellationToken ct = default)
    {
        return await Result.Try(async () =>
        {
            AuthenticationResult auth;
            try
            {
                auth = await _app.AcquireTokenInteractive(_options.Scopes)
                    .WithUseEmbeddedWebView(false)
                    .ExecuteAsync(ct).ConfigureAwait(false);
            }
            catch (MsalUiRequiredException ex) when (ex.Classification == UiRequiredExceptionClassification.ConsentRequired)
            {
                throw new IrisException(IrisErrorCode.AuthEntraConsentRequired, "Consentimento administrativo é necessário para os scopes solicitados.", ex);
            }
            catch (MsalServiceException ex) when (ex.ErrorCode == "access_denied")
            {
                throw new IrisException(IrisErrorCode.AuthEntraConditionalAccessBlock, "Conditional Access bloqueou o login.", ex);
            }
            catch (MsalClientException ex) when (ex.ErrorCode == "authentication_canceled")
            {
                throw new IrisException(IrisErrorCode.SysOperationCanceled, "Login cancelado pelo usuário.", ex);
            }
            catch (MsalException ex)
            {
                throw new IrisException(IrisErrorCode.AuthEntraInteractiveFailed, $"Falha MSAL: {ex.ErrorCode} — {ex.Message}", ex);
            }
            return _current = BuildIdentity(auth);
        }, IrisErrorCode.AuthEntraInteractiveFailed).ConfigureAwait(false);
    }

    public async Task<Result<IrisIdentity>> SignInSilentAsync(CancellationToken ct = default)
    {
        return await Result.Try(async () =>
        {
            var accounts = await _app.GetAccountsAsync().ConfigureAwait(false);
            var account = accounts.FirstOrDefault();
            if (account is null) throw new IrisException(IrisErrorCode.AuthEntraSilentFailed, "Nenhuma conta em cache para login silencioso.");
            try
            {
                var auth = await _app.AcquireTokenSilent(_options.Scopes, account).ExecuteAsync(ct).ConfigureAwait(false);
                return _current = BuildIdentity(auth);
            }
            catch (MsalUiRequiredException ex)
            {
                throw new IrisException(IrisErrorCode.AuthEntraTokenExpired, "Token silencioso expirou — necessário re-login interativo.", ex);
            }
        }, IrisErrorCode.AuthEntraSilentFailed).ConfigureAwait(false);
    }

    public async Task<Result<bool>> SignOutAsync(CancellationToken ct = default)
    {
        return await Result.Try<bool>(async () =>
        {
            var accounts = await _app.GetAccountsAsync().ConfigureAwait(false);
            foreach (var a in accounts) await _app.RemoveAsync(a).ConfigureAwait(false);
            _current = null;
            return true;
        }, IrisErrorCode.SysUnknown).ConfigureAwait(false);
    }

    public async Task<Result<string>> GetAccessTokenAsync(IEnumerable<string> scopes, CancellationToken ct = default)
    {
        return await Result.Try(async () =>
        {
            var accounts = await _app.GetAccountsAsync().ConfigureAwait(false);
            var account = accounts.FirstOrDefault();
            if (account is null) throw new IrisException(IrisErrorCode.AuthEntraSilentFailed, "Sem conta para emitir token. Faça login.");
            var auth = await _app.AcquireTokenSilent(scopes, account).ExecuteAsync(ct).ConfigureAwait(false);
            return auth.AccessToken;
        }, IrisErrorCode.AuthEntraSilentFailed).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    // ─── helpers ───────────────────────────────────────────────────────────
    private static IrisIdentity BuildIdentity(AuthenticationResult auth)
    {
        var roles = ExtractClaim(auth.IdToken, "roles");
        var scopes = auth.Scopes?.ToArray() ?? [];
        return new IrisIdentity(
            ObjectId: auth.UniqueId,
            Upn: auth.Account?.Username ?? "(unknown)",
            DisplayName: auth.ClaimsPrincipal?.FindFirst("name")?.Value ?? auth.Account?.Username ?? "(unknown)",
            Roles: roles,
            Scopes: scopes,
            TokenExpiresUtc: auth.ExpiresOn);
    }

    private static IReadOnlyList<string> ExtractClaim(string? idToken, string claimType)
    {
        if (string.IsNullOrWhiteSpace(idToken)) return Array.Empty<string>();
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(idToken);
            return jwt.Claims.Where(c => c.Type == claimType).Select(c => c.Value).ToArray();
        }
        catch { return Array.Empty<string>(); }
    }
}
