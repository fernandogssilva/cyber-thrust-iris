using System.Net.Http.Headers;
using System.Text.Json;
using CyberThrust.IRIS.Core.Errors;

namespace CyberThrust.IRIS.CrowdStrike.Api;

/// <summary>HttpMessageHandler que injeta Bearer token OAuth2 do Falcon, refresca quando expira.</summary>
public sealed class FalconAuthHandler : DelegatingHandler
{
    private readonly FalconOptions _opt;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _token;
    private DateTimeOffset _expiresUtc = DateTimeOffset.MinValue;

    public FalconAuthHandler(FalconOptions opt) => _opt = opt;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        await EnsureTokenAsync(ct).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        var resp = await base.SendAsync(request, ct).ConfigureAwait(false);
        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            await ForceRefreshAsync(ct).ConfigureAwait(false);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            resp.Dispose();
            resp = await base.SendAsync(request, ct).ConfigureAwait(false);
        }
        return resp;
    }

    private async Task EnsureTokenAsync(CancellationToken ct)
    {
        if (_token is not null && _expiresUtc > DateTimeOffset.UtcNow.AddSeconds(60)) return;
        await ForceRefreshAsync(ct).ConfigureAwait(false);
    }

    private async Task ForceRefreshAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_token is not null && _expiresUtc > DateTimeOffset.UtcNow.AddSeconds(60)) return;
            using var client = new HttpClient { BaseAddress = new Uri(_opt.BaseUrl), Timeout = TimeSpan.FromSeconds(_opt.HttpTimeoutSeconds) };
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = _opt.ClientId,
                ["client_secret"] = _opt.ClientSecret
            });
            using var req = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token") { Content = form };
            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (resp.StatusCode == System.Net.HttpStatusCode.Forbidden)
                throw new IrisException(IrisErrorCode.CsOAuth2Forbidden, "Credenciais Falcon válidas porém sem escopo. Verifique as permissões da API key.");
            if (!resp.IsSuccessStatusCode)
                throw new IrisException(IrisErrorCode.CsOAuth2Failed, $"OAuth2 Falcon falhou ({(int)resp.StatusCode}): {body}");

            using var doc = JsonDocument.Parse(body);
            var token = doc.RootElement.GetProperty("access_token").GetString()
                ?? throw new IrisException(IrisErrorCode.CsOAuth2Failed, "access_token ausente.");
            var expires = doc.RootElement.TryGetProperty("expires_in", out var e) ? e.GetInt32() : 1800;
            _token = token;
            _expiresUtc = DateTimeOffset.UtcNow.AddSeconds(expires);
        }
        finally
        {
            _gate.Release();
        }
    }
}
