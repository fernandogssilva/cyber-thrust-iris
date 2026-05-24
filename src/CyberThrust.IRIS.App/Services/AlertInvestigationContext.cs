using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Contexto de investigação compartilhado (singleton em memória) que transporta
/// dados da detecção selecionada entre as views de Detecções → RTR / Forense / Memória.
/// Implementa a política de Zero-Storage: nenhum dado é persistido em disco.
///
/// Carrega IOCs extraídos do alerta (hash, processo, IP, usuário, cmdline) para
/// que os filtros do RTR e os scripts de coleta sejam pré-parametrizados.
/// </summary>
public sealed class AlertInvestigationContext
{
    /// <summary>Alerta completo da Falcon Alerts API que está sendo investigado.</summary>
    public FalconAlert? Alert { get; set; }

    /// <summary>AID do agente Falcon do endpoint-alvo (pré-fill RTR / Forense / Memória).</summary>
    public string? Aid { get; set; }

    /// <summary>Nome amigável do host para exibição nos formulários.</summary>
    public string? Hostname { get; set; }

    /// <summary>Endereço IP do endpoint (preferindo external_ip → local_ip → ip_address).</summary>
    public string? IpAddress { get; set; }

    /// <summary>SHA256 do artefato (se o alerta carregar hash).</summary>
    public string? Sha256 { get; set; }

    /// <summary>MD5 do artefato (fallback se não tiver SHA256).</summary>
    public string? Md5 { get; set; }

    /// <summary>Caminho do processo / arquivo que disparou o alerta.</summary>
    public string? FilePath { get; set; }

    /// <summary>Nome do processo (apenas o filename, sem path).</summary>
    public string? ProcessName { get; set; }

    /// <summary>Command line do processo.</summary>
    public string? CommandLine { get; set; }

    /// <summary>Usuário associado ao alerta (UPN / SAM / display name).</summary>
    public string? UserName { get; set; }

    /// <summary>Domínio referenciado (DNS query / URL).</summary>
    public string? Domain { get; set; }

    /// <summary>Ferramenta forense a pré-selecionar ao abrir a tela Forense.</summary>
    public ForensicsToolKind? PreferredForensicsTool { get; set; }

    /// <summary>Script-id a pré-executar ao abrir o Console RTR (ex: "process-tree", "memdump-xrtr").</summary>
    public string? PreferredRtrScriptId { get; set; }

    /// <summary>True quando há contexto de investigação ativo com AID preenchido.</summary>
    public bool HasContext => !string.IsNullOrWhiteSpace(Aid);

    /// <summary>Popula o contexto a partir de um alerta selecionado. Extrai IOCs do dict Extra.</summary>
    public void SetFromAlert(FalconAlert alert)
    {
        Alert       = alert;
        Aid         = alert.Aid;
        Hostname    = alert.Hostname;
        UserName    = alert.UserName;

        // IOCs do dict Extra (populado por FalconClient.ListAlertsAsync)
        var x = alert.Extra ?? new Dictionary<string, string>();
        Sha256      = Pick(x, "sha256");
        Md5         = Pick(x, "md5");
        FilePath    = Pick(x, "filepath");
        ProcessName = Pick(x, "filename");
        CommandLine = Pick(x, "cmdline", "commandline");
        IpAddress   = Pick(x, "external_ip", "local_ip", "ip_address");
        Domain      = Pick(x, "domain");

        PreferredForensicsTool = null;
        PreferredRtrScriptId   = null;
    }

    /// <summary>Limpa o contexto (chamado após navegação ou ao fechar o painel).</summary>
    public void Clear()
    {
        Alert = null;
        Aid = Hostname = IpAddress = Sha256 = Md5 = FilePath = ProcessName =
            CommandLine = UserName = Domain = null;
        PreferredForensicsTool = null;
        PreferredRtrScriptId   = null;
    }

    private static string? Pick(IReadOnlyDictionary<string, string> dict, params string[] keys)
    {
        foreach (var k in keys)
            if (dict.TryGetValue(k, out var v) && !string.IsNullOrWhiteSpace(v))
                return v;
        return null;
    }
}
