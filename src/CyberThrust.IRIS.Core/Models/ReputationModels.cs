namespace CyberThrust.IRIS.Core.Models;

/// <summary>Tipo do artefato a consultar.</summary>
public enum ArtifactKind { FileHash, Url, Domain, IpAddress }

/// <summary>Resultado consolidado de múltiplas fontes de reputação.</summary>
public sealed record ArtifactReputationReport(
    string Artifact,
    ArtifactKind Kind,
    Verdict Verdict,
    int? MaliciousCount,
    int? SuspiciousCount,
    int? HarmlessCount,
    int? UndetectedCount,
    int? TotalEngines,
    IReadOnlyList<ReputationSource> Sources,
    IReadOnlyList<string> ThreatLabels,
    IReadOnlyList<string> Tags,
    DateTimeOffset? FirstSeenUtc,
    DateTimeOffset? LastSeenUtc,
    IReadOnlyDictionary<string, string> Metadata)
{
    public double DetectionRatio => (TotalEngines is > 0 && MaliciousCount.HasValue)
        ? MaliciousCount.Value * 100.0 / TotalEngines.Value
        : 0;
}

public enum Verdict { Unknown, Clean, Suspicious, Malicious }

public sealed record ReputationSource(string Provider, Verdict Verdict, string? Detail, string? Url, TimeSpan? Latency);
