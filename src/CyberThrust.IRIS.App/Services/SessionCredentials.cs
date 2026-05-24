using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Credenciais carregadas APENAS em memória durante a sessão.
/// Política IRIS v0.3.1+ : por padrão, NADA é persistido em disco.
///
/// O usuário insere credenciais na tela Settings → ficam aqui.
/// Quando o app fecha → memória é limpa, credenciais somem.
/// </summary>
public sealed class SessionCredentials
{
    private EntraConfigSection _entra = new();
    private FalconConfigSection _falcon = new();
    private ThreatIntelConfigSection _ti = new();

    public event Action? Changed;

    public EntraConfigSection Entra
    {
        get => _entra;
        set { _entra = value ?? new(); Changed?.Invoke(); }
    }

    public FalconConfigSection Falcon
    {
        get => _falcon;
        set { _falcon = value ?? new(); Changed?.Invoke(); }
    }

    public ThreatIntelConfigSection ThreatIntel
    {
        get => _ti;
        set { _ti = value ?? new(); Changed?.Invoke(); }
    }

    public string VirusTotalApiKey
    {
        get => _ti.VirusTotalApiKey;
        set { _ti.VirusTotalApiKey = value ?? string.Empty; Changed?.Invoke(); }
    }

    public string AbuseIpdbApiKey
    {
        get => _ti.AbuseIpdbApiKey;
        set { _ti.AbuseIpdbApiKey = value ?? string.Empty; Changed?.Invoke(); }
    }

    public string ShodanApiKey
    {
        get => _ti.ShodanApiKey;
        set { _ti.ShodanApiKey = value ?? string.Empty; Changed?.Invoke(); }
    }

    public string FofaEmail
    {
        get => _ti.FofaEmail;
        set { _ti.FofaEmail = value ?? string.Empty; Changed?.Invoke(); }
    }

    public string FofaKey
    {
        get => _ti.FofaKey;
        set { _ti.FofaKey = value ?? string.Empty; Changed?.Invoke(); }
    }

    public string MalwareBazaarApiKey { get; set; } = string.Empty;

    public bool HasFalconCredentials => !string.IsNullOrWhiteSpace(_falcon.ClientId) && !string.IsNullOrWhiteSpace(_falcon.ClientSecret);
    public bool HasEntraCredentials => !string.IsNullOrWhiteSpace(_entra.ClientId) && !_entra.ClientId.StartsWith("00000000", StringComparison.Ordinal);
    public bool HasAnyCtiCredentials => !string.IsNullOrWhiteSpace(_ti.VirusTotalApiKey) || !string.IsNullOrWhiteSpace(_ti.AbuseIpdbApiKey) || !string.IsNullOrWhiteSpace(_ti.ShodanApiKey) || !string.IsNullOrWhiteSpace(_ti.FofaKey);

    /// <summary>Limpa toda a memória de credenciais. Chamado em logout ou shutdown.</summary>
    public void Clear()
    {
        _entra = new();
        _falcon = new();
        _ti = new();
        Changed?.Invoke();
    }

    public AppConfigSnapshot ToSnapshot() => new()
    {
        EntraId = _entra,
        Falcon = _falcon,
        Exfil = new ExfilConfigSection(),
        ThreatIntel = _ti
    };

    public void LoadFrom(AppConfigSnapshot snap)
    {
        _entra = snap.EntraId ?? new();
        _falcon = snap.Falcon ?? new();
        _ti = snap.ThreatIntel ?? new();
        Changed?.Invoke();
    }
}
