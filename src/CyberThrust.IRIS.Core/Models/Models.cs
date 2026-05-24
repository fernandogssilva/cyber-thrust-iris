using CyberThrust.IRIS.Core.Errors;

namespace CyberThrust.IRIS.Core.Models;

// ─── Identidade ────────────────────────────────────────────────────────────
public sealed record IrisIdentity(string ObjectId, string Upn, string DisplayName, IReadOnlyList<string> Roles, IReadOnlyList<string> Scopes, DateTimeOffset TokenExpiresUtc);

// ─── Plataforma ───────────────────────────────────────────────────────────
public enum HostPlatform { Windows, Linux, MacOs, Esxi, Other }

public sealed record FalconHost(string Aid, string Hostname, HostPlatform Platform, string OsVersion, string LocalIp, string ExternalIp, string Status, DateTimeOffset LastSeenUtc, IReadOnlyList<string> Tags);

// ─── Detection ─────────────────────────────────────────────────────────────
public enum Severity { Informational, Low, Medium, High, Critical }

public sealed record FalconDetection(string DetectionId, string Aid, string Hostname, Severity Severity, string Tactic, string Technique, string Description, DateTimeOffset TimestampUtc, IReadOnlyDictionary<string, string> Context);

/// <summary>Alerta unificado do Falcon — vem da Alerts API v2 e cobre TODOS os produtos:
/// EDR (epp), Identity Protection (idp), NG-SIEM (ngsiem), Mobile (mobile),
/// Cloud Security (cloud), OverWatch (overwatch), XDR (xdr).</summary>
public sealed record FalconAlert(
    string CompositeId,
    string Product,              // epp / idp / ngsiem / mobile / cloud / overwatch / xdr
    string Vendor,               // crowdstrike
    string Name,
    string Description,
    Severity Severity,
    string Status,               // new / in_progress / true_positive / false_positive / ignored / closed
    string Tactic,
    string Technique,
    string TacticId,
    string TechniqueId,
    string Aid,
    string Hostname,
    string UserName,             // populado em alertas IDP
    string AssignedToName,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    IReadOnlyDictionary<string, string> Extra);

/// <summary>Filtros para a query de alerts.</summary>
public sealed record FalconAlertsFilter(
    string[]? Products = null,           // epp, idp, ngsiem, mobile, cloud, overwatch, xdr
    Severity[]? MinSeverities = null,    // só severidades >= a alguma da lista
    string[]? Statuses = null,           // new, in_progress, true_positive, false_positive
    TimeSpan? LookBack = null,           // ex: 24h, 7d
    int Limit = 200);

// ─── RTR ─────────────────────────────────────────────────────────────
public sealed record RtrSessionInfo(string SessionId, string Aid, DateTimeOffset CreatedUtc, DateTimeOffset ExpiresUtc);
public sealed record RtrCommandResult(string Aid, string SessionId, bool Complete, string? Stdout, string? Stderr, int? ExitCode, string? TaskId);

// ─── Falcon Capability Probe ──────────────────────────────────────────────
public sealed record FalconCapability(
    bool InsightXdr,
    bool IdentityProtection,
    bool Spotlight,
    bool Discover,
    bool Surface,
    bool LogScale,
    bool Forensics,
    bool Fusion,
    bool DataReplicator,
    bool RtrAdmin,
    string CloudRegion)
{
    public IEnumerable<string> Licensed => GetType().GetProperties()
        .Where(p => p.PropertyType == typeof(bool) && (bool)p.GetValue(this)!)
        .Select(p => p.Name);
}

// ─── Forensics ─────────────────────────────────────────────────────────────
public enum ForensicsToolKind { Kape, Velociraptor, Uac, Custom }
public sealed record ForensicsCollectionOptions(ForensicsToolKind Tool, IReadOnlyList<string> Targets, IReadOnlyList<string> Modules, string ExfilUri, int TimeoutSeconds = 1800);
public sealed record ForensicsJob(string JobId, string Aid, ForensicsToolKind Tool, JobState State, string? ArtifactUri, IrisError? LastError, DateTimeOffset StartedUtc, DateTimeOffset? FinishedUtc, double PercentComplete);

// ─── Memory ─────────────────────────────────────────────────────────────
public enum MemoryToolKind { FalconXmemdump, WinPmem, MagnetDumpIt, FtkImager }
public sealed record MemoryCaptureOptions(MemoryToolKind Tool, string ExfilUri, bool Compress = true, int TimeoutSeconds = 1800);
public sealed record MemoryJob(string JobId, string Aid, MemoryToolKind Tool, JobState State, string? ArtifactUri, long? BytesCaptured, IrisError? LastError, DateTimeOffset StartedUtc, DateTimeOffset? FinishedUtc, double PercentComplete);
public sealed record MemoryAnalysisReport(string ArtifactPath, IReadOnlyList<MemoryFinding> Findings, IReadOnlyList<string> SuspiciousProcesses, IReadOnlyDictionary<string, string> Metadata);
public sealed record MemoryFinding(string Plugin, Severity Severity, string Message, IReadOnlyDictionary<string, string> Data);

// ─── Job genérico ─────────────────────────────────────────────────────────
public enum JobState { Queued, Running, Succeeded, Failed, Canceled }
public sealed record JobProgress(double Percent, string Stage, string? Message = null);

// ─── Attack Graph ─────────────────────────────────────────────────────────
public enum NodeKind { Ioc, User, Host, Process, NetworkEndpoint, File, RegistryKey, Detection, LateralMove }
public sealed record AttackNode(string Id, NodeKind Kind, string Label, Severity Severity, IReadOnlyDictionary<string, string> Metadata);
public sealed record AttackEdge(string Source, string Target, string Relationship, DateTimeOffset? TimestampUtc, IReadOnlyDictionary<string, string>? Metadata = null);
public sealed record AttackGraph(string IncidentId, IReadOnlyList<AttackNode> Nodes, IReadOnlyList<AttackEdge> Edges);

// ─── Incident ─────────────────────────────────────────────────────────────
public sealed record Incident(string Id, string Title, Severity Severity, string Status, DateTimeOffset CreatedUtc, IReadOnlyList<string> Aids, IReadOnlyList<string> DetectionIds, IReadOnlyList<string> Tactics, IReadOnlyList<string> Techniques);

// ─── Health Check ─────────────────────────────────────────────────────────
public enum HealthStatus { Pass, Warn, Fail, Skipped }
public sealed record HealthResult(string Name, string Category, HealthStatus Status, string Message, IrisError? Error = null, TimeSpan? Duration = null, IReadOnlyDictionary<string, string>? Data = null);
