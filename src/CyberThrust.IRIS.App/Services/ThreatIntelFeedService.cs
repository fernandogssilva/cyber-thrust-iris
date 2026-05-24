using System.Net.Http;
using System.Text.Json;
using Serilog;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Feed de threat intelligence público — consulta abuse.ch (URLhaus, ThreatFox, MalwareBazaar)
/// em tempo real, SEM persistir nada no disco. Operacional mesmo antes de configurar Falcon.
/// </summary>
public sealed class ThreatIntelFeedService
{
    private readonly HttpClient _http;

    public ThreatIntelFeedService()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("CyberThrust.IRIS/0.3.2 (+https://github.com/fernandogssilva/cyber-thrust-iris)");
    }

    /// <summary>Últimas N URLs maliciosas detectadas por URLhaus.</summary>
    public async Task<IReadOnlyList<ThreatIocItem>> GetUrlHausRecentAsync(int limit = 5, CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync("https://urlhaus-api.abuse.ch/v1/urls/recent/", ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return Array.Empty<ThreatIocItem>();
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array)
                return Array.Empty<ThreatIocItem>();

            var list = new List<ThreatIocItem>();
            foreach (var u in urls.EnumerateArray().Take(limit))
            {
                list.Add(new ThreatIocItem(
                    Indicator: u.TryGetProperty("url", out var urlEl) ? urlEl.GetString() ?? "" : "",
                    Type: "URL",
                    Threat: u.TryGetProperty("threat", out var th) ? th.GetString() ?? "" : "malware_download",
                    Source: "URLhaus",
                    AddedUtc: ParseDate(u, "date_added"),
                    Tags: ExtractTags(u, "tags")));
            }
            return list;
        }
        catch (Exception ex) { Log.Warning(ex, "URLhaus feed falhou"); return Array.Empty<ThreatIocItem>(); }
    }

    /// <summary>Últimos IOCs (hashes, URLs, IPs) submetidos ao ThreatFox.</summary>
    public async Task<IReadOnlyList<ThreatIocItem>> GetThreatFoxRecentAsync(int limit = 5, CancellationToken ct = default)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new { query = "get_iocs", days = 1 });
            using var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync("https://threatfox-api.abuse.ch/api/v1/", content, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return Array.Empty<ThreatIocItem>();
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                return Array.Empty<ThreatIocItem>();

            var list = new List<ThreatIocItem>();
            foreach (var d in data.EnumerateArray().Take(limit))
            {
                list.Add(new ThreatIocItem(
                    Indicator: d.TryGetProperty("ioc", out var ioc) ? ioc.GetString() ?? "" : "",
                    Type: d.TryGetProperty("ioc_type", out var iocType) ? iocType.GetString() ?? "" : "",
                    Threat: d.TryGetProperty("malware_printable", out var mp) ? mp.GetString() ?? "" : "",
                    Source: "ThreatFox",
                    AddedUtc: ParseDate(d, "first_seen"),
                    Tags: ExtractTags(d, "tags")));
            }
            return list;
        }
        catch (Exception ex) { Log.Warning(ex, "ThreatFox feed falhou"); return Array.Empty<ThreatIocItem>(); }
    }

    /// <summary>Últimos samples submetidos ao MalwareBazaar (hashes maliciosos confirmados).</summary>
    public async Task<IReadOnlyList<ThreatIocItem>> GetMalwareBazaarRecentAsync(int limit = 5, CancellationToken ct = default)
    {
        try
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["query"] = "get_recent",
                ["selector"] = "100"
            });
            using var resp = await _http.PostAsync("https://mb-api.abuse.ch/api/v1/", form, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return Array.Empty<ThreatIocItem>();
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                return Array.Empty<ThreatIocItem>();

            var list = new List<ThreatIocItem>();
            foreach (var d in data.EnumerateArray().Take(limit))
            {
                list.Add(new ThreatIocItem(
                    Indicator: d.TryGetProperty("sha256_hash", out var h) ? h.GetString() ?? "" : "",
                    Type: "SHA-256",
                    Threat: d.TryGetProperty("signature", out var sig) ? sig.GetString() ?? "" : (d.TryGetProperty("file_type", out var ft) ? ft.GetString() ?? "" : ""),
                    Source: "MalwareBazaar",
                    AddedUtc: ParseDate(d, "first_seen"),
                    Tags: ExtractTags(d, "tags")));
            }
            return list;
        }
        catch (Exception ex) { Log.Warning(ex, "MalwareBazaar feed falhou"); return Array.Empty<ThreatIocItem>(); }
    }

    /// <summary>Agrega os 3 feeds em uma lista única ordenada por data desc.</summary>
    public async Task<IReadOnlyList<ThreatIocItem>> GetCombinedFeedAsync(int perSource = 4, CancellationToken ct = default)
    {
        var tasks = new[]
        {
            GetUrlHausRecentAsync(perSource, ct),
            GetThreatFoxRecentAsync(perSource, ct),
            GetMalwareBazaarRecentAsync(perSource, ct)
        };
        var all = await Task.WhenAll(tasks).ConfigureAwait(false);
        return all.SelectMany(x => x).OrderByDescending(x => x.AddedUtc ?? DateTimeOffset.MinValue).ToArray();
    }

    private static DateTimeOffset? ParseDate(JsonElement el, string prop)
    {
        if (!el.TryGetProperty(prop, out var d)) return null;
        var s = d.GetString();
        if (string.IsNullOrWhiteSpace(s)) return null;
        return DateTimeOffset.TryParse(s, out var dt) ? dt : null;
    }

    private static string[] ExtractTags(JsonElement el, string prop)
    {
        if (!el.TryGetProperty(prop, out var t) || t.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
        return t.EnumerateArray().Select(x => x.GetString() ?? "").Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
    }
}

public sealed record ThreatIocItem(string Indicator, string Type, string Threat, string Source, DateTimeOffset? AddedUtc, string[] Tags)
{
    public string ShortIndicator => Indicator.Length <= 64 ? Indicator : Indicator[..32] + "…" + Indicator[^16..];
    public string AgeLabel
    {
        get
        {
            if (!AddedUtc.HasValue) return "—";
            var diff = DateTimeOffset.UtcNow - AddedUtc.Value;
            if (diff.TotalMinutes < 60) return $"{(int)diff.TotalMinutes}m";
            if (diff.TotalHours < 24) return $"{(int)diff.TotalHours}h";
            return $"{(int)diff.TotalDays}d";
        }
    }
    public string TagsCsv => Tags.Length == 0 ? "" : string.Join(" · ", Tags.Take(4));
}
