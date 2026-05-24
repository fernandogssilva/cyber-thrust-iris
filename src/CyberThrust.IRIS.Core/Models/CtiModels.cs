namespace CyberThrust.IRIS.Core.Models;

/// <summary>Tipo do alvo do CTI: domínio, IP ou hash de arquivo.</summary>
public enum CtiTargetKind { Domain, IpAddress, Url, FileHash }

/// <summary>Relatório agregado de Cyber Threat Intelligence de múltiplas fontes.</summary>
public sealed record CtiReport(
    string Target,
    CtiTargetKind Kind,
    Verdict OverallVerdict,
    CtiReputation? Reputation,
    CtiExposure? Exposure,
    IReadOnlyList<CtiVulnerability> Vulnerabilities,
    IReadOnlyList<CtiPivot> Pivots,
    IReadOnlyList<CtiSourceStatus> Sources,
    IReadOnlyDictionary<string, string> Metadata,
    DateTimeOffset GeneratedUtc);

/// <summary>Score de reputação consolidado.</summary>
public sealed record CtiReputation(
    int? AbuseConfidenceScore,     // 0..100 do AbuseIPDB
    int? VtMaliciousEngines,        // engines VT que marcam malicioso
    int? VtTotalEngines,
    int? AbuseTotalReports,
    bool? IsTorExitNode,
    string? Country,
    string? Isp,
    string? Asn,
    IReadOnlyList<string> Categories,
    DateTimeOffset? LastReportUtc);

/// <summary>Dados de exposição na internet (Shodan).</summary>
public sealed record CtiExposure(
    string? Hostname,
    string? Country,
    string? City,
    string? Asn,
    string? Org,
    string? Os,
    int? OpenPortsCount,
    IReadOnlyList<CtiOpenPort> OpenPorts,
    IReadOnlyList<string> Hostnames,
    IReadOnlyList<string> Domains,
    IReadOnlyList<string> Tags,
    DateTimeOffset? LastUpdateUtc);

public sealed record CtiOpenPort(
    int Port,
    string? Transport,            // tcp/udp
    string? ServiceName,
    string? Product,
    string? Version,
    string? Banner,
    string? Module,
    IReadOnlyList<string> Cpes);

/// <summary>Vulnerabilidade conhecida (CVE) associada ao alvo.</summary>
public sealed record CtiVulnerability(
    string CveId,
    double? CvssScore,
    string? Severity,             // CRITICAL/HIGH/MEDIUM/LOW
    string? Summary,
    bool? VerifiedExploit,        // tem PoC ativo?
    string? ReferenceUrl);

/// <summary>Pivot — outro asset relacionado descoberto.</summary>
public sealed record CtiPivot(
    string Indicator,             // IP, domain, hash
    string Kind,                  // tipo
    string Source,                // "FOFA", "VirusTotal", "Shodan related"
    string? Detail);

public sealed record CtiSourceStatus(
    string Provider,
    bool Ok,
    string? Message,
    TimeSpan? Latency,
    string? Url);
