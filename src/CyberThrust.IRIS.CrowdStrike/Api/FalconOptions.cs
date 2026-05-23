namespace CyberThrust.IRIS.CrowdStrike.Api;

/// <summary>Configuração CrowdStrike Falcon — preenchida via appsettings.local.json.</summary>
public sealed class FalconOptions
{
    public const string SectionName = "Falcon";

    /// <summary>us-1, us-2, eu-1 ou us-gov-1.</summary>
    public string Cloud { get; set; } = "us-1";
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public int HttpTimeoutSeconds { get; set; } = 30;
    public int MaxRetries { get; set; } = 3;

    public string BaseUrl => Cloud.ToLowerInvariant() switch
    {
        "us-1" => "https://api.crowdstrike.com",
        "us-2" => "https://api.us-2.crowdstrike.com",
        "eu-1" => "https://api.eu-1.crowdstrike.com",
        "us-gov-1" => "https://api.laggar.gcw.crowdstrike.com",
        _ => "https://api.crowdstrike.com"
    };
}
