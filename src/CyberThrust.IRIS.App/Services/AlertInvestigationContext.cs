using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Contexto de investigação compartilhado (singleton em memória) que transporta
/// dados da detecção selecionada entre as views de Detecções → RTR / Forense / Memória.
/// Implementa a política de Zero-Storage: nenhum dado é persistido em disco.
/// </summary>
public sealed class AlertInvestigationContext
{
    /// <summary>Alerta completo da Falcon Alerts API que está sendo investigado.</summary>
    public FalconAlert? Alert { get; set; }

    /// <summary>AID do agente Falcon do endpoint-alvo (pré-fill RTR / Forense / Memória).</summary>
    public string? Aid { get; set; }

    /// <summary>Nome amigável do host para exibição nos formulários.</summary>
    public string? Hostname { get; set; }

    /// <summary>Ferramenta forense a pré-selecionar ao abrir a tela Forense.</summary>
    public ForensicsToolKind? PreferredForensicsTool { get; set; }

    /// <summary>True quando há contexto de investigação ativo com AID preenchido.</summary>
    public bool HasContext => !string.IsNullOrWhiteSpace(Aid);

    /// <summary>Popula o contexto a partir de um alerta selecionado.</summary>
    public void SetFromAlert(FalconAlert alert)
    {
        Alert = alert;
        Aid = alert.Aid;
        Hostname = alert.Hostname;
        PreferredForensicsTool = null;
    }

    /// <summary>Limpa o contexto (chamado após navegação ou ao fechar o painel).</summary>
    public void Clear()
    {
        Alert = null;
        Aid = null;
        Hostname = null;
        PreferredForensicsTool = null;
    }
}
