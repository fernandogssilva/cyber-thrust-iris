namespace CyberThrust.IRIS.EntraID;

/// <summary>Configuração de autenticação Entra ID — preenchida via appsettings.local.json.</summary>
public sealed class EntraOptions
{
    public const string SectionName = "EntraId";

    public string TenantId { get; set; } = "common";
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = "http://localhost";
    public string[] Scopes { get; set; } = ["User.Read"];
    public bool UseBroker { get; set; } = true;
    public string CacheFileName { get; set; } = "iris.msal.cache.bin";
}
