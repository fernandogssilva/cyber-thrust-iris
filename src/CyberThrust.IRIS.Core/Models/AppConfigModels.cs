namespace CyberThrust.IRIS.Core.Models;

/// <summary>Snapshot serializável do arquivo appsettings.local.json (sem secrets em log).</summary>
public sealed class AppConfigSnapshot
{
    public EntraConfigSection EntraId { get; set; } = new();
    public FalconConfigSection Falcon { get; set; } = new();
    public ExfilConfigSection Exfil { get; set; } = new();
    public ThreatIntelConfigSection ThreatIntel { get; set; } = new();
}

public sealed class ThreatIntelConfigSection
{
    public string VirusTotalApiKey { get; set; } = string.Empty;
    public string AbuseIpdbApiKey { get; set; } = string.Empty;
    public string ShodanApiKey { get; set; } = string.Empty;
    public string FofaEmail { get; set; } = string.Empty;
    public string FofaKey { get; set; } = string.Empty;
}

public sealed class EntraConfigSection
{
    public string TenantId { get; set; } = "common";
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = "http://localhost";
    public string[] Scopes { get; set; } = ["User.Read"];
    public bool UseBroker { get; set; } = false;
}

public sealed class FalconConfigSection
{
    public string Cloud { get; set; } = "us-1";
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public int HttpTimeoutSeconds { get; set; } = 30;
    public int MaxRetries { get; set; } = 3;
}

public sealed class ExfilConfigSection
{
    public string PresignedUrlTemplate { get; set; } = string.Empty;
}

/// <summary>Resultado de um teste de conexão.</summary>
public sealed record ConnectionTestResult(bool Success, string Message, TimeSpan? Latency = null, string? Code = null);
