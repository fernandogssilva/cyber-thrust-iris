using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Cyber Threat Intelligence — consulta paralela a múltiplas fontes:
///   • AbuseIPDB v2  (reputação IP, abuse confidence score, total reports)
///   • VirusTotal v3 (multi-engine + WHOIS + resoluções DNS)
///   • Shodan        (portas abertas, banners, serviços, vulnerabilidades/CVE)
///   • FOFA en.fofa.info (fingerprints — outros assets relacionados na internet)
///
/// Política zero-storage: nada é cacheado. Cada query vai direto à API.
/// </summary>
public sealed class CtiIntelService
{
    private readonly SessionCredentials _creds;
    private readonly HttpClient _http;

    public CtiIntelService(SessionCredentials creds)
    {
        _creds = creds;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("CyberThrust.IRIS/0.4.0 (+https://github.com/fernandogssilva/cyber-thrust-iris)");
    }

    public async Task<CtiReport> InvestigateAsync(string target, CtiTargetKind kind, CancellationToken ct = default)
    {
        target = (target ?? string.Empty).Trim();
        Log.Information("CTI investigate: {Kind} {Target}", kind, Redact(target));

        var sources = new List<CtiSourceStatus>();
        var pivots = new List<CtiPivot>();
        var vulns = new List<CtiVulnerability>();
        var meta = new Dictionary<string, string>();

        CtiReputation? reputation = null;
        CtiExposure? exposure = null;

        // ─── AbuseIPDB (apenas IP) ─────────────────────────────────────
        if (kind == CtiTargetKind.IpAddress && !string.IsNullOrWhiteSpace(_creds.AbuseIpdbApiKey))
        {
            var (ok, msg, latency, score, totalReports, country, isp, isTor, categories, lastReport) = await QueryAbuseIpdbAsync(target, ct).ConfigureAwait(false);
            sources.Add(new CtiSourceStatus("AbuseIPDB", ok, msg, latency, $"https://www.abuseipdb.com/check/{target}"));
            if (ok)
            {
                reputation = new CtiReputation(score, null, null, totalReports, isTor, country, isp, null, categories, lastReport);
            }
        }
        else if (kind == CtiTargetKind.IpAddress)
        {
            sources.Add(new CtiSourceStatus("AbuseIPDB", false, "API key não configurada", null, null));
        }

        // ─── VirusTotal ────────────────────────────────────────────────
        if (!string.IsNullOrWhiteSpace(_creds.VirusTotalApiKey))
        {
            var vt = await QueryVirusTotalAsync(target, kind, ct).ConfigureAwait(false);
            sources.Add(new CtiSourceStatus("VirusTotal", vt.Ok, vt.Message, vt.Latency, vt.Url));
            if (vt.Ok)
            {
                reputation = (reputation ?? new CtiReputation(null, null, null, null, null, null, null, null, Array.Empty<string>(), null))
                    with
                {
                    VtMaliciousEngines = vt.Malicious,
                    VtTotalEngines = vt.Total,
                    Country = reputation?.Country ?? vt.Country,
                    Asn = vt.Asn,
                    Isp = reputation?.Isp ?? vt.Asn
                };
                // Pivots: resoluções de IP/domínio
                foreach (var p in vt.RelatedIndicators)
                    pivots.Add(new CtiPivot(p.Value, p.Kind, "VirusTotal", p.Detail));
            }
        }
        else
        {
            sources.Add(new CtiSourceStatus("VirusTotal", false, "API key não configurada", null, null));
        }

        // ─── Shodan (IP e Domain) ──────────────────────────────────────
        if ((kind == CtiTargetKind.IpAddress || kind == CtiTargetKind.Domain) && !string.IsNullOrWhiteSpace(_creds.ShodanApiKey))
        {
            var sh = await QueryShodanAsync(target, kind, ct).ConfigureAwait(false);
            sources.Add(new CtiSourceStatus("Shodan", sh.Ok, sh.Message, sh.Latency, sh.Url));
            if (sh.Ok)
            {
                exposure = sh.Exposure;
                foreach (var v in sh.Vulnerabilities) vulns.Add(v);
                foreach (var d in sh.Domains) pivots.Add(new CtiPivot(d, "Domain", "Shodan related", null));
            }
        }
        else if (kind == CtiTargetKind.IpAddress || kind == CtiTargetKind.Domain)
        {
            sources.Add(new CtiSourceStatus("Shodan", false, "API key não configurada", null, null));
        }

        // ─── FOFA (Domain e IP) ────────────────────────────────────────
        if ((kind == CtiTargetKind.IpAddress || kind == CtiTargetKind.Domain) && !string.IsNullOrWhiteSpace(_creds.FofaKey))
        {
            var fofa = await QueryFofaAsync(target, kind, ct).ConfigureAwait(false);
            sources.Add(new CtiSourceStatus("FOFA", fofa.Ok, fofa.Message, fofa.Latency, fofa.Url));
            if (fofa.Ok) foreach (var p in fofa.Pivots) pivots.Add(p);
        }
        else if (kind == CtiTargetKind.IpAddress || kind == CtiTargetKind.Domain)
        {
            sources.Add(new CtiSourceStatus("FOFA", false, "Credenciais não configuradas", null, null));
        }

        var verdict = ComputeVerdict(reputation, exposure, vulns);

        return new CtiReport(
            Target: target,
            Kind: kind,
            OverallVerdict: verdict,
            Reputation: reputation,
            Exposure: exposure,
            Vulnerabilities: vulns,
            Pivots: pivots,
            Sources: sources,
            Metadata: meta,
            GeneratedUtc: DateTimeOffset.UtcNow);
    }

    // ═══════════════ AbuseIPDB ═══════════════
    private async Task<(bool Ok, string Message, TimeSpan Latency, int? Score, int? Total, string? Country, string? Isp, bool? IsTor, IReadOnlyList<string> Categories, DateTimeOffset? LastReport)> QueryAbuseIpdbAsync(string ip, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90&verbose");
            req.Headers.Add("Key", _creds.AbuseIpdbApiKey);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return (false, "API key inválida", sw.Elapsed, null, null, null, null, null, Array.Empty<string>(), null);
            if (resp.StatusCode == (System.Net.HttpStatusCode)429)
                return (false, "Rate limit (1000/dia free)", sw.Elapsed, null, null, null, null, null, Array.Empty<string>(), null);
            if (!resp.IsSuccessStatusCode)
                return (false, $"HTTP {(int)resp.StatusCode}", sw.Elapsed, null, null, null, null, null, Array.Empty<string>(), null);
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var d = doc.RootElement.GetProperty("data");
            int? score = d.TryGetProperty("abuseConfidenceScore", out var s) ? s.GetInt32() : null;
            int? total = d.TryGetProperty("totalReports", out var tr) ? tr.GetInt32() : null;
            string? country = d.TryGetProperty("countryCode", out var c) ? c.GetString() : null;
            string? isp = d.TryGetProperty("isp", out var isp_) ? isp_.GetString() : null;
            bool? isTor = d.TryGetProperty("isTor", out var tor) ? tor.GetBoolean() : null;
            DateTimeOffset? last = d.TryGetProperty("lastReportedAt", out var lr) && DateTimeOffset.TryParse(lr.GetString(), out var ldt) ? ldt : null;
            var cats = new List<string>();
            if (d.TryGetProperty("reports", out var reports) && reports.ValueKind == JsonValueKind.Array)
            {
                foreach (var r in reports.EnumerateArray().Take(20))
                {
                    if (r.TryGetProperty("categories", out var rc) && rc.ValueKind == JsonValueKind.Array)
                        foreach (var cat in rc.EnumerateArray())
                            cats.Add(AbuseCategoryName(cat.GetInt32()));
                }
            }
            var msg = score is null ? "OK" : $"{score}/100 confiança · {total ?? 0} reports";
            return (true, msg, sw.Elapsed, score, total, country, isp, isTor, cats.Distinct().Take(10).ToArray(), last);
        }
        catch (Exception ex) { Log.Warning(ex, "AbuseIPDB falhou"); return (false, ex.Message, sw.Elapsed, null, null, null, null, null, Array.Empty<string>(), null); }
    }

    private static string AbuseCategoryName(int id) => id switch
    {
        1 => "DNS Compromise", 2 => "DNS Poisoning", 3 => "Fraud Orders", 4 => "DDoS Attack",
        5 => "FTP Brute-Force", 6 => "Ping of Death", 7 => "Phishing", 8 => "Fraud VoIP",
        9 => "Open Proxy", 10 => "Web Spam", 11 => "Email Spam", 12 => "Blog Spam",
        13 => "VPN IP", 14 => "Port Scan", 15 => "Hacking", 16 => "SQL Injection",
        17 => "Spoofing", 18 => "Brute-Force", 19 => "Bad Web Bot", 20 => "Exploited Host",
        21 => "Web App Attack", 22 => "SSH", 23 => "IoT Targeted",
        _ => $"Cat#{id}"
    };

    // ═══════════════ VirusTotal ═══════════════
    private async Task<VtResult> QueryVirusTotalAsync(string artifact, CtiTargetKind kind, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var path = kind switch
            {
                CtiTargetKind.FileHash => $"https://www.virustotal.com/api/v3/files/{Uri.EscapeDataString(artifact)}",
                CtiTargetKind.Url => $"https://www.virustotal.com/api/v3/urls/{Convert.ToBase64String(Encoding.UTF8.GetBytes(artifact)).TrimEnd('=').Replace('+', '-').Replace('/', '_')}",
                CtiTargetKind.Domain => $"https://www.virustotal.com/api/v3/domains/{Uri.EscapeDataString(artifact)}",
                CtiTargetKind.IpAddress => $"https://www.virustotal.com/api/v3/ip_addresses/{Uri.EscapeDataString(artifact)}",
                _ => null
            };
            if (path is null) return new VtResult(false, "Tipo não suportado", sw.Elapsed, null, null, null, null, null, Array.Empty<(string, string, string?)>());

            using var req = new HttpRequestMessage(HttpMethod.Get, path);
            req.Headers.Add("x-apikey", _creds.VirusTotalApiKey);
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return new VtResult(true, "Desconhecido pelo VT", sw.Elapsed, $"https://www.virustotal.com/gui/search/{Uri.EscapeDataString(artifact)}", null, null, null, null, Array.Empty<(string, string, string?)>());
            if (!resp.IsSuccessStatusCode)
                return new VtResult(false, $"HTTP {(int)resp.StatusCode}", sw.Elapsed, null, null, null, null, null, Array.Empty<(string, string, string?)>());
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var attrs = doc.RootElement.GetProperty("data").GetProperty("attributes");

            int? mal = null, total = null;
            if (attrs.TryGetProperty("last_analysis_stats", out var ls))
            {
                mal = ls.TryGetProperty("malicious", out var mEl) ? mEl.GetInt32() : 0;
                int sus = ls.TryGetProperty("suspicious", out var sEl) ? sEl.GetInt32() : 0;
                int harm = ls.TryGetProperty("harmless", out var hEl) ? hEl.GetInt32() : 0;
                int und = ls.TryGetProperty("undetected", out var uEl) ? uEl.GetInt32() : 0;
                total = mal + sus + harm + und;
            }
            string? country = attrs.TryGetProperty("country", out var co) ? co.GetString() : null;
            string? asn = attrs.TryGetProperty("asn", out var asnEl) ? asnEl.ToString() : null;
            var pivots = new List<(string, string, string?)>();
            if (attrs.TryGetProperty("last_dns_records", out var dns) && dns.ValueKind == JsonValueKind.Array)
            {
                foreach (var rec in dns.EnumerateArray().Take(10))
                {
                    var type = rec.TryGetProperty("type", out var t) ? t.GetString() : null;
                    var value = rec.TryGetProperty("value", out var v) ? v.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(value))
                        pivots.Add((value, $"DNS {type ?? "?"}", $"VT DNS record"));
                }
            }
            var msg = total > 0 ? $"{mal}/{total} engines malicious" : "Sem stats";
            var url = kind switch
            {
                CtiTargetKind.FileHash => $"https://www.virustotal.com/gui/file/{artifact}",
                CtiTargetKind.Domain => $"https://www.virustotal.com/gui/domain/{artifact}",
                CtiTargetKind.IpAddress => $"https://www.virustotal.com/gui/ip-address/{artifact}",
                _ => null
            };
            return new VtResult(true, msg, sw.Elapsed, url, mal, total, country, asn, pivots);
        }
        catch (Exception ex) { Log.Warning(ex, "VT falhou"); return new VtResult(false, ex.Message, sw.Elapsed, null, null, null, null, null, Array.Empty<(string, string, string?)>()); }
    }

    // ═══════════════ Shodan ═══════════════
    private async Task<ShodanResult> QueryShodanAsync(string target, CtiTargetKind kind, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            string url;
            if (kind == CtiTargetKind.IpAddress)
                url = $"https://api.shodan.io/shodan/host/{Uri.EscapeDataString(target)}?key={_creds.ShodanApiKey}";
            else // Domain
                url = $"https://api.shodan.io/dns/domain/{Uri.EscapeDataString(target)}?key={_creds.ShodanApiKey}";

            using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return new ShodanResult(false, "API key inválida", sw.Elapsed, null, null, Array.Empty<CtiVulnerability>(), Array.Empty<string>());
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return new ShodanResult(true, "Sem dados Shodan", sw.Elapsed, $"https://www.shodan.io/host/{target}", null, Array.Empty<CtiVulnerability>(), Array.Empty<string>());
            if (!resp.IsSuccessStatusCode)
                return new ShodanResult(false, $"HTTP {(int)resp.StatusCode}", sw.Elapsed, null, null, Array.Empty<CtiVulnerability>(), Array.Empty<string>());

            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            CtiExposure? exposure = null;
            var vulns = new List<CtiVulnerability>();
            var domains = new List<string>();

            if (kind == CtiTargetKind.IpAddress)
            {
                var ports = new List<CtiOpenPort>();
                if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                {
                    foreach (var svc in data.EnumerateArray())
                    {
                        int port = svc.TryGetProperty("port", out var p) ? p.GetInt32() : 0;
                        string? transport = svc.TryGetProperty("transport", out var tr) ? tr.GetString() : null;
                        string? product = svc.TryGetProperty("product", out var pr) ? pr.GetString() : null;
                        string? version = svc.TryGetProperty("version", out var vr) ? vr.GetString() : null;
                        string? module = svc.TryGetProperty("_shodan", out var sh) && sh.TryGetProperty("module", out var mo) ? mo.GetString() : null;
                        string? banner = svc.TryGetProperty("data", out var ba) ? Truncate(ba.GetString() ?? "", 200) : null;
                        var cpes = new List<string>();
                        if (svc.TryGetProperty("cpe23", out var cpe23) && cpe23.ValueKind == JsonValueKind.Array)
                            foreach (var c in cpe23.EnumerateArray()) cpes.Add(c.GetString() ?? "");
                        ports.Add(new CtiOpenPort(port, transport, module, product, version, banner, module, cpes));

                        // Vulnerabilidades por serviço
                        if (svc.TryGetProperty("vulns", out var vt) && vt.ValueKind == JsonValueKind.Object)
                        {
                            foreach (var v in vt.EnumerateObject())
                            {
                                var cveId = v.Name;
                                double? cvss = v.Value.TryGetProperty("cvss", out var cv) && cv.ValueKind == JsonValueKind.Number ? cv.GetDouble() : null;
                                string? summary = v.Value.TryGetProperty("summary", out var su) ? Truncate(su.GetString() ?? "", 300) : null;
                                bool? verified = v.Value.TryGetProperty("verified", out var ve) ? ve.GetBoolean() : null;
                                string sev = cvss switch { >= 9 => "CRITICAL", >= 7 => "HIGH", >= 4 => "MEDIUM", >= 0.1 => "LOW", _ => "UNKNOWN" };
                                vulns.Add(new CtiVulnerability(cveId, cvss, sev, summary, verified, $"https://nvd.nist.gov/vuln/detail/{cveId}"));
                            }
                        }
                    }
                }
                var hostnames = new List<string>();
                if (root.TryGetProperty("hostnames", out var hns) && hns.ValueKind == JsonValueKind.Array)
                    foreach (var h in hns.EnumerateArray()) hostnames.Add(h.GetString() ?? "");
                if (root.TryGetProperty("domains", out var dms) && dms.ValueKind == JsonValueKind.Array)
                    foreach (var d in dms.EnumerateArray()) domains.Add(d.GetString() ?? "");
                var tags = new List<string>();
                if (root.TryGetProperty("tags", out var tagsArr) && tagsArr.ValueKind == JsonValueKind.Array)
                    foreach (var t in tagsArr.EnumerateArray()) tags.Add(t.GetString() ?? "");

                exposure = new CtiExposure(
                    Hostname: hostnames.FirstOrDefault(),
                    Country: root.TryGetProperty("country_name", out var cn) ? cn.GetString() : null,
                    City: root.TryGetProperty("city", out var ci) ? ci.GetString() : null,
                    Asn: root.TryGetProperty("asn", out var asn) ? asn.GetString() : null,
                    Org: root.TryGetProperty("org", out var org) ? org.GetString() : null,
                    Os: root.TryGetProperty("os", out var os) && os.ValueKind != JsonValueKind.Null ? os.GetString() : null,
                    OpenPortsCount: ports.Count,
                    OpenPorts: ports,
                    Hostnames: hostnames.Distinct().ToArray(),
                    Domains: domains.Distinct().ToArray(),
                    Tags: tags.ToArray(),
                    LastUpdateUtc: root.TryGetProperty("last_update", out var lu) && DateTimeOffset.TryParse(lu.GetString(), out var ldt) ? ldt : null);
            }
            else // Domain
            {
                // /dns/domain retorna sub-records de domínio
                if (root.TryGetProperty("subdomains", out var subs) && subs.ValueKind == JsonValueKind.Array)
                    foreach (var s in subs.EnumerateArray().Take(20)) domains.Add($"{s.GetString()}.{target}");
                if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                    foreach (var rec in data.EnumerateArray().Take(20))
                    {
                        var val = rec.TryGetProperty("value", out var v) ? v.GetString() : null;
                        if (!string.IsNullOrWhiteSpace(val)) domains.Add(val);
                    }
            }

            return new ShodanResult(true, exposure != null ? $"{exposure.OpenPortsCount} portas · {vulns.Count} CVEs" : $"{domains.Count} subdomínios", sw.Elapsed, kind == CtiTargetKind.IpAddress ? $"https://www.shodan.io/host/{target}" : $"https://www.shodan.io/domain/{target}", exposure, vulns, domains.Distinct().Take(20).ToArray());
        }
        catch (Exception ex) { Log.Warning(ex, "Shodan falhou"); return new ShodanResult(false, ex.Message, sw.Elapsed, null, null, Array.Empty<CtiVulnerability>(), Array.Empty<string>()); }
    }

    // ═══════════════ FOFA (en.fofa.info) ═══════════════
    private async Task<FofaResult> QueryFofaAsync(string target, CtiTargetKind kind, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // FOFA aceita queries tipo: ip="x.x.x.x" ou domain="example.com"
            var fofaQuery = kind switch
            {
                CtiTargetKind.IpAddress => $"ip=\"{target}\"",
                CtiTargetKind.Domain => $"domain=\"{target}\"",
                _ => target
            };
            var qbase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(fofaQuery));
            var url = $"https://en.fofa.info/api/v1/search/all?key={_creds.FofaKey}&qbase64={qbase64}&size=20&fields=ip,port,host,title,server,domain,country_name";
            if (!string.IsNullOrWhiteSpace(_creds.FofaEmail))
                url += $"&email={Uri.EscapeDataString(_creds.FofaEmail)}";

            using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return new FofaResult(false, $"HTTP {(int)resp.StatusCode}", sw.Elapsed, null, Array.Empty<CtiPivot>());
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.True)
            {
                var errmsg = doc.RootElement.TryGetProperty("errmsg", out var em) ? em.GetString() : "erro genérico";
                return new FofaResult(false, errmsg ?? "erro", sw.Elapsed, null, Array.Empty<CtiPivot>());
            }
            var pivots = new List<CtiPivot>();
            if (doc.RootElement.TryGetProperty("results", out var results) && results.ValueKind == JsonValueKind.Array)
            {
                foreach (var row in results.EnumerateArray().Take(20))
                {
                    if (row.ValueKind != JsonValueKind.Array) continue;
                    var arr = row.EnumerateArray().ToArray();
                    var ip = arr.Length > 0 ? arr[0].GetString() : null;
                    var port = arr.Length > 1 ? arr[1].GetString() : null;
                    var host = arr.Length > 2 ? arr[2].GetString() : null;
                    var title = arr.Length > 3 ? arr[3].GetString() : null;
                    var server = arr.Length > 4 ? arr[4].GetString() : null;
                    var domain = arr.Length > 5 ? arr[5].GetString() : null;
                    var detail = $"{port} · {server ?? "?"} · {Truncate(title ?? "", 60)}";
                    if (!string.IsNullOrWhiteSpace(host)) pivots.Add(new CtiPivot(host, "Host", "FOFA", detail));
                    else if (!string.IsNullOrWhiteSpace(domain)) pivots.Add(new CtiPivot(domain, "Domain", "FOFA", detail));
                    else if (!string.IsNullOrWhiteSpace(ip)) pivots.Add(new CtiPivot(ip, "IP", "FOFA", detail));
                }
            }
            var size = doc.RootElement.TryGetProperty("size", out var sz) ? sz.GetInt32() : pivots.Count;
            return new FofaResult(true, $"{size} resultados", sw.Elapsed, "https://en.fofa.info/result?qbase64=" + qbase64, pivots);
        }
        catch (Exception ex) { Log.Warning(ex, "FOFA falhou"); return new FofaResult(false, ex.Message, sw.Elapsed, null, Array.Empty<CtiPivot>()); }
    }

    // ═══════════════ helpers ═══════════════
    private static Verdict ComputeVerdict(CtiReputation? rep, CtiExposure? exp, IReadOnlyList<CtiVulnerability> vulns)
    {
        if (rep?.AbuseConfidenceScore >= 75) return Verdict.Malicious;
        if (rep?.VtMaliciousEngines is > 5) return Verdict.Malicious;
        if (vulns.Any(v => v.Severity == "CRITICAL")) return Verdict.Malicious;
        if (rep?.AbuseConfidenceScore >= 25) return Verdict.Suspicious;
        if (rep?.VtMaliciousEngines is > 0) return Verdict.Suspicious;
        if (vulns.Count > 0) return Verdict.Suspicious;
        if (rep is not null || exp is not null) return Verdict.Clean;
        return Verdict.Unknown;
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
    private static string Redact(string s) => s.Length <= 16 ? s : s[..8] + "…" + s[^4..];

    // Result records
    private sealed record VtResult(bool Ok, string Message, TimeSpan Latency, string? Url, int? Malicious, int? Total, string? Country, string? Asn, IReadOnlyList<(string Value, string Kind, string? Detail)> RelatedIndicators);
    private sealed record ShodanResult(bool Ok, string Message, TimeSpan Latency, string? Url, CtiExposure? Exposure, IReadOnlyList<CtiVulnerability> Vulnerabilities, IReadOnlyList<string> Domains);
    private sealed record FofaResult(bool Ok, string Message, TimeSpan Latency, string? Url, IReadOnlyList<CtiPivot> Pivots);
}
