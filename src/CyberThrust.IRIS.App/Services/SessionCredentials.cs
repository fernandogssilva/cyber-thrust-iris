using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Credenciais carregadas APENAS em memória durante a sessão.
/// Política IRIS v0.3.1+ : por padrão, NADA é persistido em disco.
///
/// O usuário insere credenciais na tela Settings → ficam aqui.
/// Quando o app fecha → memória é limpa, credenciais somem.
///
/// Se o usuário marcar "Persistir entre sessões" na UI, então grava no
/// appsettings.local.json (opt-in explícito, não default).
/// </summary>
public sealed class SessionCredentials
{
    private EntraConfigSection _entra = new();
    private FalconConfigSection _falcon = new();
    private string _virusTotalApiKey = string.Empty;
    private string _malwareBazaarApiKey = string.Empty;

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

    public string VirusTotalApiKey
    {
        get => _virusTotalApiKey;
        set { _virusTotalApiKey = value ?? string.Empty; Changed?.Invoke(); }
    }

    public string MalwareBazaarApiKey
    {
        get => _malwareBazaarApiKey;
        set { _malwareBazaarApiKey = value ?? string.Empty; Changed?.Invoke(); }
    }

    public bool HasFalconCredentials => !string.IsNullOrWhiteSpace(_falcon.ClientId) && !string.IsNullOrWhiteSpace(_falcon.ClientSecret);
    public bool HasEntraCredentials => !string.IsNullOrWhiteSpace(_entra.ClientId) && !_entra.ClientId.StartsWith("00000000", StringComparison.Ordinal);

    /// <summary>Limpa toda a memória de credenciais. Chamado em logout ou shutdown.</summary>
    public void Clear()
    {
        _entra = new();
        _falcon = new();
        _virusTotalApiKey = string.Empty;
        _malwareBazaarApiKey = string.Empty;
        Changed?.Invoke();
    }

    /// <summary>Snapshot somente leitura — útil para passar a outros services sem expor o campo mutável.</summary>
    public AppConfigSnapshot ToSnapshot() => new()
    {
        EntraId = _entra,
        Falcon = _falcon,
        Exfil = new ExfilConfigSection()
    };

    public void LoadFrom(AppConfigSnapshot snap)
    {
        _entra = snap.EntraId ?? new();
        _falcon = snap.Falcon ?? new();
        Changed?.Invoke();
    }
}
