using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Testes ad-hoc de conexão usados pela tela de Configurações.
/// Não dependem do DI nem da config atual — recebem credenciais como parâmetro
/// para que o usuário possa testar ANTES de salvar.
/// </summary>
public sealed class ConnectionTester
{
    /// <summary>Testa OAuth2 + uma chamada GET /devices/queries/devices/v1?limit=1 (smoke test mínimo).</summary>
    public async Task<ConnectionTestResult> TestFalconAsync(FalconConfigSection cfg, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(cfg.ClientId) || string.IsNullOrWhiteSpace(cfg.ClientSecret))
            return new ConnectionTestResult(false, "ClientId e ClientSecret são obrigatórios.", Code: "IRIS-CFG-7007");

        var baseUrl = cfg.Cloud.ToLowerInvariant() switch
        {
            "us-1" => "https://api.crowdstrike.com",
            "us-2" => "https://api.us-2.crowdstrike.com",
            "eu-1" => "https://api.eu-1.crowdstrike.com",
            "us-gov-1" => "https://api.laggar.gcw.crowdstrike.com",
            _ => null
        };
        if (baseUrl is null) return new ConnectionTestResult(false, $"Cloud '{cfg.Cloud}' inválido. Use us-1/us-2/eu-1/us-gov-1.", Code: "IRIS-CS-2003");

        var sw = Stopwatch.StartNew();
        try
        {
            using var http = new HttpClient { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(cfg.HttpTimeoutSeconds) };
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = cfg.ClientId,
                ["client_secret"] = cfg.ClientSecret
            });
            using var tokenResp = await http.PostAsync("/oauth2/token", form, ct).ConfigureAwait(false);
            var tokenBody = await tokenResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!tokenResp.IsSuccessStatusCode)
            {
                var code = tokenResp.StatusCode == System.Net.HttpStatusCode.Forbidden ? "IRIS-CS-2002" : "IRIS-CS-2001";
                return new ConnectionTestResult(false, $"OAuth2 falhou ({(int)tokenResp.StatusCode}): {Truncate(tokenBody, 200)}", sw.Elapsed, code);
            }
            using var doc = JsonDocument.Parse(tokenBody);
            var token = doc.RootElement.GetProperty("access_token").GetString();

            // smoke: lista 1 host pra confirmar scope mínimo
            using var req = new HttpRequestMessage(HttpMethod.Get, "/devices/queries/devices/v1?limit=1");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var smokeResp = await http.SendAsync(req, ct).ConfigureAwait(false);
            if (!smokeResp.IsSuccessStatusCode)
            {
                return new ConnectionTestResult(false, $"OAuth2 OK, mas /devices retornou {(int)smokeResp.StatusCode}. Confira escopo 'Hosts Read' na API key.", sw.Elapsed, $"IRIS-CS-2{(int)smokeResp.StatusCode}");
            }
            var smokeBody = await smokeResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var smokeDoc = JsonDocument.Parse(smokeBody);
            var total = smokeDoc.RootElement.TryGetProperty("meta", out var meta) && meta.TryGetProperty("pagination", out var pg) && pg.TryGetProperty("total", out var t)
                ? t.GetInt32() : 0;

            sw.Stop();
            return new ConnectionTestResult(true, $"Conexão OK · cloud={cfg.Cloud} · {total} hosts visíveis", sw.Elapsed);
        }
        catch (TaskCanceledException)
        {
            return new ConnectionTestResult(false, "Timeout na chamada Falcon. Verifique conectividade e firewall.", Code: "IRIS-CS-2015");
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "TestFalcon falhou");
            return new ConnectionTestResult(false, ex.Message, Code: "IRIS-NET-5004");
        }
    }

    /// <summary>Valida formato da config Entra (não faz login real — só checagem estática).</summary>
    public Task<ConnectionTestResult> TestEntraAsync(EntraConfigSection cfg, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(cfg.ClientId))
            return Task.FromResult(new ConnectionTestResult(false, "ClientId é obrigatório.", Code: "IRIS-CFG-7006"));
        if (cfg.ClientId.StartsWith("00000000", StringComparison.Ordinal))
            return Task.FromResult(new ConnectionTestResult(false, "ClientId está como placeholder zero.", Code: "IRIS-CFG-7006"));
        if (!Guid.TryParse(cfg.ClientId, out _))
            return Task.FromResult(new ConnectionTestResult(false, "ClientId não parece um GUID válido.", Code: "IRIS-CFG-7006"));
        if (string.IsNullOrWhiteSpace(cfg.TenantId))
            return Task.FromResult(new ConnectionTestResult(false, "TenantId é obrigatório (use 'common' ou um GUID).", Code: "IRIS-CFG-7006"));
        if (cfg.TenantId != "common" && cfg.TenantId != "organizations" && cfg.TenantId != "consumers" && !Guid.TryParse(cfg.TenantId, out _))
            return Task.FromResult(new ConnectionTestResult(false, "TenantId inválido. Use 'common', 'organizations', 'consumers' ou um GUID.", Code: "IRIS-CFG-7006"));
        if (cfg.Scopes is null || cfg.Scopes.Length == 0)
            return Task.FromResult(new ConnectionTestResult(false, "Pelo menos um Scope é necessário (ex: User.Read).", Code: "IRIS-CFG-7006"));
        return Task.FromResult(new ConnectionTestResult(true, $"Configuração válida · tenant={cfg.TenantId} · scopes={string.Join(',', cfg.Scopes)}"));
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
