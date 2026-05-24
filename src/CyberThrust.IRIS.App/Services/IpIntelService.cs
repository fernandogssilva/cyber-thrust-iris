using System.Net.Http;
using System.Text.Json;
using Serilog;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Enriquecimento de IP: geolocalização + ISP + AS via ip-api.com (free, 45 req/min, sem key).
/// Zero-Storage: nada cacheado em disco, apenas em memória do app.
/// </summary>
public sealed record IpIntelReport(
    string Ip,
    string Country,
    string CountryCode,
    string Region,
    string City,
    string Isp,
    string Org,
    string AsNumber,
    bool IsPrivate,
    bool LookupSucceeded,
    string? Error);

public sealed class IpIntelService
{
    private readonly HttpClient _http;

    public IpIntelService()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("CyberThrust.IRIS/0.4.8");
    }

    /// <summary>Consulta ip-api.com retornando geo + ISP + AS. Detecta IP privado (RFC 1918) e pula a chamada.</summary>
    public async Task<IpIntelReport> LookupAsync(string ip, CancellationToken ct = default)
    {
        ip = (ip ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(ip))
            return new IpIntelReport(ip, "—", "—", "—", "—", "—", "—", "—", false, false, "IP vazio");

        // IPs privados — pula API
        if (IsPrivateIp(ip))
            return new IpIntelReport(ip, "—", "—", "—", "—", "Rede interna", "Privado", "—", true, true, null);

        try
        {
            using var resp = await _http.GetAsync($"http://ip-api.com/json/{Uri.EscapeDataString(ip)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query", ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return new IpIntelReport(ip, "—", "—", "—", "—", "—", "—", "—", false, false, $"HTTP {(int)resp.StatusCode}");

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var root = doc.RootElement;
            var status = root.TryGetProperty("status", out var s) ? s.GetString() : null;
            if (status != "success")
            {
                var msg = root.TryGetProperty("message", out var m) ? m.GetString() : "fail";
                return new IpIntelReport(ip, "—", "—", "—", "—", "—", "—", "—", false, false, msg);
            }

            return new IpIntelReport(
                Ip:           root.TryGetProperty("query",       out var q) ? q.GetString() ?? ip : ip,
                Country:      root.TryGetProperty("country",     out var c) ? c.GetString() ?? "—" : "—",
                CountryCode:  root.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? "—" : "—",
                Region:       root.TryGetProperty("regionName",  out var rn) ? rn.GetString() ?? "—" : "—",
                City:         root.TryGetProperty("city",        out var ct1) ? ct1.GetString() ?? "—" : "—",
                Isp:          root.TryGetProperty("isp",         out var i) ? i.GetString() ?? "—" : "—",
                Org:          root.TryGetProperty("org",         out var o) ? o.GetString() ?? "—" : "—",
                AsNumber:     root.TryGetProperty("as",          out var an) ? an.GetString() ?? "—" : "—",
                IsPrivate:    false,
                LookupSucceeded: true,
                Error:        null);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "IpIntel.LookupAsync falhou para {Ip}", ip);
            return new IpIntelReport(ip, "—", "—", "—", "—", "—", "—", "—", false, false, ex.Message);
        }
    }

    private static bool IsPrivateIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr)) return false;
        var b = addr.GetAddressBytes();
        if (b.Length != 4) return false;
        // 10.0.0.0/8
        if (b[0] == 10) return true;
        // 172.16.0.0/12
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        // 192.168.0.0/16
        if (b[0] == 192 && b[1] == 168) return true;
        // 127.0.0.0/8 loopback
        if (b[0] == 127) return true;
        // 169.254.0.0/16 link-local
        if (b[0] == 169 && b[1] == 254) return true;
        return false;
    }
}
