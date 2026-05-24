using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Consulta múltiplas fontes públicas de reputação para um hash de arquivo,
/// URL, domínio ou IP. Nada é persistido em disco — toda chamada vai direto
/// para a API e o resultado fica em memória do app até o usuário fechar.
///
/// Fontes integradas:
///   - VirusTotal v3 Public API (precisa key gratuita em virustotal.com/gui/join-us)
///   - MalwareBazaar (abuse.ch) — open, sem key obrigatória, score por tags
///   - URLhaus (abuse.ch) — URLs e domínios maliciosos, open
///   - ThreatFox (abuse.ch) — IOC database, open
///
/// O cliente respeita rate limits documentados de cada fonte (4 req/min VT free).
/// </summary>
public sealed class ArtifactReputationClient
{
    private readonly SessionCredentials _creds;
    private readonly HttpClient _http;

    public ArtifactReputationClient(SessionCredentials creds)
    {
        _creds = creds;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("CyberThrust.IRIS/0.3.1 (+https://github.com/fernandogssilva/cyber-thrust-iris)");
    }

    public async Task<ArtifactReputationReport> QueryAsync(string artifact, ArtifactKind kind, CancellationToken ct = default)
    {
        artifact = (artifact ?? string.Empty).Trim();
        Log.Information("ArtifactReputation: querying {Kind} {Artifact}", kind, Redact(artifact));

        var sources = new List<ReputationSource>();
        var threatLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var meta = new Dictionary<string, string>();
        int? malicious = null, suspicious = null, harmless = null, undetected = null, totalEngines = null;
        DateTimeOffset? firstSeen = null, lastSeen = null;

        // ─── VirusTotal v3 ──────────────────────────────────────────
        if (!string.IsNullOrWhiteSpace(_creds.VirusTotalApiKey))
        {
            var vt = await TryVirusTotalAsync(artifact, kind, ct).ConfigureAwait(false);
            if (vt is { } v)
            {
                sources.Add(new ReputationSource("VirusTotal", v.Verdict, v.Detail, v.Url, v.Latency));
                if (v.Stats is { } st)
                {
                    malicious = st.Malicious;
                    suspicious = st.Suspicious;
                    harmless = st.Harmless;
                    undetected = st.Undetected;
                    totalEngines = st.Total;
                }
                foreach (var l in v.Labels) threatLabels.Add(l);
                foreach (var t in v.Tags) tags.Add(t);
                if (v.FirstSeenUtc.HasValue) firstSeen = v.FirstSeenUtc;
                if (v.LastSeenUtc.HasValue) lastSeen = v.LastSeenUtc;
                foreach (var kv in v.Metadata) meta[kv.Key] = kv.Value;
            }
        }
        else
        {
            sources.Add(new ReputationSource("VirusTotal", Verdict.Unknown, "API key não configurada", null, null));
        }

        // ─── MalwareBazaar (apenas hash) ────────────────────────────
        if (kind == ArtifactKind.FileHash)
        {
            var mb = await TryMalwareBazaarAsync(artifact, ct).ConfigureAwait(false);
            if (mb is { } m)
            {
                sources.Add(new ReputationSource("MalwareBazaar (abuse.ch)", m.Verdict, m.Detail, m.Url, m.Latency));
                foreach (var t in m.Tags) tags.Add(t);
                if (!string.IsNullOrWhiteSpace(m.Signature)) threatLabels.Add(m.Signature);
                if (m.FirstSeenUtc.HasValue && (!firstSeen.HasValue || m.FirstSeenUtc < firstSeen)) firstSeen = m.FirstSeenUtc;
            }
        }

        // ─── URLhaus (URL e Domínio) ───────────────────────────────
        if (kind is ArtifactKind.Url or ArtifactKind.Domain)
        {
            var uh = await TryUrlHausAsync(artifact, kind, ct).ConfigureAwait(false);
            if (uh is { } u) sources.Add(u);
        }

        // ─── ThreatFox (IP, hash, URL) ─────────────────────────────
        var tf = await TryThreatFoxAsync(artifact, kind, ct).ConfigureAwait(false);
        if (tf is { } f)
        {
            sources.Add(f);
        }

        var finalVerdict = AggregateVerdict(sources, malicious, totalEngines);

        return new ArtifactReputationReport(
            Artifact: artifact,
            Kind: kind,
            Verdict: finalVerdict,
            MaliciousCount: malicious,
            SuspiciousCount: suspicious,
            HarmlessCount: harmless,
            UndetectedCount: undetected,
            TotalEngines: totalEngines,
            Sources: sources,
            ThreatLabels: threatLabels.ToArray(),
            Tags: tags.ToArray(),
            FirstSeenUtc: firstSeen,
            LastSeenUtc: lastSeen,
            Metadata: meta);
    }

    // ─── Implementações por fonte ───────────────────────────────────
    private async Task<VirusTotalResult?> TryVirusTotalAsync(string artifact, ArtifactKind kind, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var path = kind switch
            {
                ArtifactKind.FileHash => $"https://www.virustotal.com/api/v3/files/{Uri.EscapeDataString(artifact)}",
                ArtifactKind.Url => $"https://www.virustotal.com/api/v3/urls/{Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(artifact)).TrimEnd('=').Replace('+', '-').Replace('/', '_')}",
                ArtifactKind.Domain => $"https://www.virustotal.com/api/v3/domains/{Uri.EscapeDataString(artifact)}",
                ArtifactKind.IpAddress => $"https://www.virustotal.com/api/v3/ip_addresses/{Uri.EscapeDataString(artifact)}",
                _ => null
            };
            if (path is null) return null;

            using var req = new HttpRequestMessage(HttpMethod.Get, path);
            req.Headers.Add("x-apikey", _creds.VirusTotalApiKey);
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);

            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return new VirusTotalResult(Verdict.Unknown, "Artefato desconhecido pelo VirusTotal", $"https://www.virustotal.com/gui/search/{Uri.EscapeDataString(artifact)}", sw.Elapsed, null, [], [], null, null, new Dictionary<string, string>());
            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return new VirusTotalResult(Verdict.Unknown, "API key inválida", null, sw.Elapsed, null, [], [], null, null, new Dictionary<string, string>());
            if (resp.StatusCode == (System.Net.HttpStatusCode)429)
                return new VirusTotalResult(Verdict.Unknown, "Rate limit excedido (4/min free)", null, sw.Elapsed, null, [], [], null, null, new Dictionary<string, string>());
            if (!resp.IsSuccessStatusCode) return new VirusTotalResult(Verdict.Unknown, $"HTTP {(int)resp.StatusCode}", null, sw.Elapsed, null, [], [], null, null, new Dictionary<string, string>());

            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var attrs = doc.RootElement.GetProperty("data").GetProperty("attributes");

            VtStats? stats = null;
            if (attrs.TryGetProperty("last_analysis_stats", out var lasStats))
            {
                stats = new VtStats(
                    Malicious: lasStats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0,
                    Suspicious: lasStats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0,
                    Harmless: lasStats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0,
                    Undetected: lasStats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0,
                    Total: 0);
                stats = stats with { Total = stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected };
            }

            var labels = new List<string>();
            if (attrs.TryGetProperty("popular_threat_classification", out var ptc))
            {
                if (ptc.TryGetProperty("suggested_threat_label", out var stl)) labels.Add(stl.GetString() ?? "");
                if (ptc.TryGetProperty("popular_threat_category", out var ptcArr) && ptcArr.ValueKind == JsonValueKind.Array)
                    foreach (var t in ptcArr.EnumerateArray()) labels.Add(t.GetProperty("value").GetString() ?? "");
                if (ptc.TryGetProperty("popular_threat_name", out var ptnArr) && ptnArr.ValueKind == JsonValueKind.Array)
                    foreach (var t in ptnArr.EnumerateArray()) labels.Add(t.GetProperty("value").GetString() ?? "");
            }

            var tags = new List<string>();
            if (attrs.TryGetProperty("tags", out var tagsArr) && tagsArr.ValueKind == JsonValueKind.Array)
                foreach (var t in tagsArr.EnumerateArray()) tags.Add(t.GetString() ?? "");

            DateTimeOffset? firstSeen = attrs.TryGetProperty("first_submission_date", out var fs) ? DateTimeOffset.FromUnixTimeSeconds(fs.GetInt64()) : null;
            DateTimeOffset? lastSeen = attrs.TryGetProperty("last_submission_date", out var ls) ? DateTimeOffset.FromUnixTimeSeconds(ls.GetInt64()) : null;

            var metaDict = new Dictionary<string, string>();
            if (attrs.TryGetProperty("meaningful_name", out var mn)) metaDict["name"] = mn.GetString() ?? "";
            if (attrs.TryGetProperty("type_description", out var td)) metaDict["type"] = td.GetString() ?? "";
            if (attrs.TryGetProperty("size", out var sz)) metaDict["size"] = sz.GetInt64().ToString();
            if (attrs.TryGetProperty("reputation", out var rep)) metaDict["reputation"] = rep.GetInt32().ToString();

            var verdict = stats switch
            {
                { Malicious: > 5 } => Verdict.Malicious,
                { Malicious: > 0 } => Verdict.Suspicious,
                { Suspicious: > 0 } => Verdict.Suspicious,
                _ => Verdict.Clean
            };

            var url = kind switch
            {
                ArtifactKind.FileHash => $"https://www.virustotal.com/gui/file/{artifact}",
                ArtifactKind.Url => $"https://www.virustotal.com/gui/url/{Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(artifact)).TrimEnd('=').Replace('+', '-').Replace('/', '_')}",
                ArtifactKind.Domain => $"https://www.virustotal.com/gui/domain/{artifact}",
                ArtifactKind.IpAddress => $"https://www.virustotal.com/gui/ip-address/{artifact}",
                _ => null
            };
            var detail = stats is null ? "Sem estatísticas" : $"{stats.Malicious}/{stats.Total} engines maliciosos";
            return new VirusTotalResult(verdict, detail, url, sw.Elapsed, stats, labels.Where(s => !string.IsNullOrWhiteSpace(s)).ToArray(), tags.Where(s => !string.IsNullOrWhiteSpace(s)).ToArray(), firstSeen, lastSeen, metaDict);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "VirusTotal lookup falhou");
            return new VirusTotalResult(Verdict.Unknown, ex.Message, null, sw.Elapsed, null, [], [], null, null, new Dictionary<string, string>());
        }
    }

    private async Task<MalwareBazaarResult?> TryMalwareBazaarAsync(string hash, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["query"] = "get_info",
                ["hash"] = hash
            });
            using var resp = await _http.PostAsync("https://mb-api.abuse.ch/api/v1/", form, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return new MalwareBazaarResult(Verdict.Unknown, $"HTTP {(int)resp.StatusCode}", null, sw.Elapsed, null, [], null);
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.TryGetProperty("query_status", out var qs) ? qs.GetString() : null;
            if (status == "hash_not_found")
                return new MalwareBazaarResult(Verdict.Unknown, "Hash desconhecido pelo MalwareBazaar", $"https://bazaar.abuse.ch/browse.php?search={hash}", sw.Elapsed, null, [], null);
            if (status != "ok") return new MalwareBazaarResult(Verdict.Unknown, $"status={status}", null, sw.Elapsed, null, [], null);
            var data = doc.RootElement.GetProperty("data").EnumerateArray().FirstOrDefault();
            var sig = data.TryGetProperty("signature", out var s) ? s.GetString() : null;
            var tags = new List<string>();
            if (data.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array)
                foreach (var x in t.EnumerateArray()) tags.Add(x.GetString() ?? "");
            DateTimeOffset? fs = data.TryGetProperty("first_seen", out var fsEl) && DateTime.TryParse(fsEl.GetString(), out var fsDt) ? new DateTimeOffset(fsDt, TimeSpan.Zero) : null;
            return new MalwareBazaarResult(Verdict.Malicious, $"Conhecido — assinatura: {sig ?? "(none)"}", $"https://bazaar.abuse.ch/sample/{hash}/", sw.Elapsed, sig, tags.Where(s => !string.IsNullOrWhiteSpace(s)).ToArray(), fs);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "MalwareBazaar lookup falhou");
            return new MalwareBazaarResult(Verdict.Unknown, ex.Message, null, sw.Elapsed, null, [], null);
        }
    }

    private async Task<ReputationSource?> TryUrlHausAsync(string artifact, ArtifactKind kind, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["url"] = artifact
            });
            using var resp = await _http.PostAsync("https://urlhaus-api.abuse.ch/v1/url/", form, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return new ReputationSource("URLhaus", Verdict.Unknown, $"HTTP {(int)resp.StatusCode}", null, sw.Elapsed);
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.TryGetProperty("query_status", out var qs) ? qs.GetString() : null;
            if (status == "ok")
            {
                var threat = doc.RootElement.TryGetProperty("threat", out var th) ? th.GetString() : null;
                return new ReputationSource("URLhaus", Verdict.Malicious, $"Conhecido — {threat ?? ""}", "https://urlhaus.abuse.ch/", sw.Elapsed);
            }
            return new ReputationSource("URLhaus", Verdict.Unknown, "Não listado", null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            return new ReputationSource("URLhaus", Verdict.Unknown, ex.Message, null, sw.Elapsed);
        }
    }

    private async Task<ReputationSource?> TryThreatFoxAsync(string artifact, ArtifactKind kind, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var payload = System.Text.Json.JsonSerializer.Serialize(new { query = "search_ioc", search_term = artifact });
            using var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync("https://threatfox-api.abuse.ch/api/v1/", content, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return new ReputationSource("ThreatFox", Verdict.Unknown, $"HTTP {(int)resp.StatusCode}", null, sw.Elapsed);
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.TryGetProperty("query_status", out var qs) ? qs.GetString() : null;
            if (status == "ok")
            {
                var data = doc.RootElement.GetProperty("data").EnumerateArray().FirstOrDefault();
                var malware = data.TryGetProperty("malware_printable", out var mp) ? mp.GetString() : null;
                return new ReputationSource("ThreatFox", Verdict.Malicious, $"IOC conhecido — {malware ?? ""}", "https://threatfox.abuse.ch/browse/", sw.Elapsed);
            }
            return new ReputationSource("ThreatFox", Verdict.Unknown, "Não listado", null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            return new ReputationSource("ThreatFox", Verdict.Unknown, ex.Message, null, sw.Elapsed);
        }
    }

    // ─── helpers ───────────────────────────────────────────────────
    private static Verdict AggregateVerdict(List<ReputationSource> sources, int? malicious, int? total)
    {
        if (sources.Any(s => s.Verdict == Verdict.Malicious)) return Verdict.Malicious;
        if (malicious is > 0) return Verdict.Malicious;
        if (sources.Any(s => s.Verdict == Verdict.Suspicious)) return Verdict.Suspicious;
        if (sources.Any(s => s.Verdict == Verdict.Clean)) return Verdict.Clean;
        return Verdict.Unknown;
    }

    private static string Redact(string s) => s.Length <= 16 ? s : s[..8] + "…" + s[^4..];

    // Models internos
    private sealed record VtStats(int Malicious, int Suspicious, int Harmless, int Undetected, int Total);
    private sealed record VirusTotalResult(Verdict Verdict, string Detail, string? Url, TimeSpan Latency, VtStats? Stats, string[] Labels, string[] Tags, DateTimeOffset? FirstSeenUtc, DateTimeOffset? LastSeenUtc, Dictionary<string, string> Metadata);
    private sealed record MalwareBazaarResult(Verdict Verdict, string Detail, string? Url, TimeSpan Latency, string? Signature, string[] Tags, DateTimeOffset? FirstSeenUtc);
}
