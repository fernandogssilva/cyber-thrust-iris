using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

/// <summary>
/// Detecções unificadas — layout Next-Gen SIEM + painel lateral de investigação.
/// Clicar em qualquer linha abre o painel com todos os campos do alerta e as
/// ações de resposta: Conter Host, RTR, Velociraptor, atualizar status, encaminhar incidente.
/// </summary>
public partial class AlertsViewModel : ViewModelBase
{
    private readonly IFalconClient _falcon;
    private readonly INavigationService _nav;
    private readonly AppConfigStore _cfg;
    private readonly AlertInvestigationContext _context;

    public ObservableCollection<AlertRowVm> Alerts { get; } = new();
    public ICollectionView AlertsView { get; }

    // ─── Filtros ──────────────────────────────────────────────────────────────
    public ObservableCollection<string> ProductOptions  { get; } = new(new[] { "(Todos)", "epp", "idp", "ngsiem", "mobile", "cloud", "overwatch", "xdr" });
    public ObservableCollection<string> SeverityOptions { get; } = new(new[] { "(Todas)", "Critical", "High", "Medium", "Low", "Informational" });
    public ObservableCollection<string> StatusOptions   { get; } = new(new[] { "(Todos)", "new", "in_progress", "true_positive", "false_positive", "ignored", "closed" });
    public ObservableCollection<string> TimeOptions     { get; } = new(new[] { "Última 1 hora", "Últimas 24 horas", "Últimos 7 dias", "Últimos 30 dias", "Últimos 90 dias", "Tudo" });

    [ObservableProperty] private string _selectedProduct  = "(Todos)";
    [ObservableProperty] private string _selectedSeverity = "(Todas)";
    [ObservableProperty] private string _selectedStatus   = "(Todos)";
    [ObservableProperty] private string _selectedTime     = "Últimas 24 horas";
    [ObservableProperty] private string _searchText       = string.Empty;

    [ObservableProperty] private int    _totalCount;
    [ObservableProperty] private string _resultsLabel  = "0 resultados";
    [ObservableProperty] private string _statusLine    = "Pronto.";
    [ObservableProperty] private bool   _showConfigBanner;
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private bool   _hasError;

    // ─── Painel de detalhes + IR ──────────────────────────────────────────────
    [ObservableProperty] private AlertRowVm? _selectedAlertRow;
    [ObservableProperty] private bool   _hasSelectedAlert;
    [ObservableProperty] private bool   _isActionBusy;
    [ObservableProperty] private string _actionMessage = string.Empty;
    [ObservableProperty] private bool   _actionIsSuccess;
    [ObservableProperty] private Brush  _actionMessageColor = Brushes.Transparent;

    public AlertsViewModel(IFalconClient falcon, INavigationService nav, AppConfigStore cfg, AlertInvestigationContext context)
    {
        _falcon  = falcon;
        _nav     = nav;
        _cfg     = cfg;
        _context = context;
        AlertsView = CollectionViewSource.GetDefaultView(Alerts);
        AlertsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(AlertRowVm.DateGroup)));
        _ = LoadCommand.ExecuteAsync(null);
    }

    partial void OnSelectedAlertRowChanged(AlertRowVm? value)
    {
        HasSelectedAlert      = value is not null;
        ActionMessage         = string.Empty;
        ActionIsSuccess       = false;
        ActionMessageColor    = Brushes.Transparent;
    }

    partial void OnSearchTextChanged(string value) => AlertsView.Refresh();

    // ─── Carregar detecções ───────────────────────────────────────────────────
    [RelayCommand]
    private async Task Load()
    {
        IsBusy = true; BusyMessage = "Consultando /alerts/queries/alerts/v2…";
        HasError = false; LastError = null;
        var snap = _cfg.Load();
        ShowConfigBanner = string.IsNullOrWhiteSpace(snap.Falcon.ClientId) || string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret);
        if (ShowConfigBanner) { IsBusy = false; StatusLine = "Falcon não configurado."; return; }

        try
        {
            var filter = new FalconAlertsFilter(
                Products: SelectedProduct == "(Todos)" ? null : new[] { SelectedProduct },
                MinSeverities: SelectedSeverity switch
                {
                    "Critical"      => new[] { Severity.Critical },
                    "High"          => new[] { Severity.High },
                    "Medium"        => new[] { Severity.Medium },
                    "Low"           => new[] { Severity.Low },
                    "Informational" => new[] { Severity.Informational },
                    _               => null
                },
                Statuses: SelectedStatus == "(Todos)" ? null : new[] { SelectedStatus },
                LookBack: SelectedTime switch
                {
                    "Última 1 hora"    => TimeSpan.FromHours(1),
                    "Últimas 24 horas" => TimeSpan.FromHours(24),
                    "Últimos 7 dias"   => TimeSpan.FromDays(7),
                    "Últimos 30 dias"  => TimeSpan.FromDays(30),
                    "Últimos 90 dias"  => TimeSpan.FromDays(90),
                    _                  => null
                },
                Limit: 1000);

            var r = await _falcon.ListAlertsAsync(filter).ConfigureAwait(true);
            if (r.IsFailure)
            {
                HasError = true; LastError = r.Error!.ToString(); StatusLine = "Falha na API."; return;
            }

            Alerts.Clear();
            foreach (var a in r.Value!) Alerts.Add(AlertRowVm.From(a));
            TotalCount    = Alerts.Count;
            ResultsLabel  = $"{Alerts.Count} resultados ({Alerts.Count} total)";
            AlertsView.Filter = obj => obj is AlertRowVm row && row.MatchesSearch(SearchText);

            var byProduct = Alerts
                .GroupBy(x => string.IsNullOrWhiteSpace(x.Alert.Product) ? "?" : x.Alert.Product)
                .OrderByDescending(g => g.Count())
                .Select(g => $"{g.Key}={g.Count()}");
            StatusLine = $"Atualizado às {DateTime.Now:HH:mm:ss} · {string.Join(" · ", byProduct)}";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Alerts.Load falhou");
            HasError = true; LastError = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ClearFilters()
    {
        SelectedProduct  = "(Todos)";
        SelectedSeverity = "(Todas)";
        SelectedStatus   = "(Todos)";
        SelectedTime     = "Últimas 24 horas";
        SearchText       = string.Empty;
    }

    [RelayCommand] private void GoToSettings() => _nav.NavigateTo("settings");

    // ─── Painel de detalhes — controle ───────────────────────────────────────
    [RelayCommand] private void CloseDetail() { SelectedAlertRow = null; }

    // ─── Ações de IR — Contenção de host ─────────────────────────────────────
    [RelayCommand]
    private async Task ContainHost()
    {
        var aid = SelectedAlertRow?.Alert.Aid;
        if (string.IsNullOrWhiteSpace(aid))
        {
            SetActionResult(false, "AID não disponível. Apenas alertas de Endpoint (EPP) têm agente Falcon associado.");
            return;
        }
        IsActionBusy = true;
        SetActionResult(false, "Isolando host via Network Containment…");
        var r = await _falcon.ContainHostAsync(aid).ConfigureAwait(true);
        IsActionBusy = false;
        SetActionResult(r.IsSuccess,
            r.IsSuccess
                ? $"✅  Host '{SelectedAlertRow?.SourceEndpoint}' isolado com sucesso. Tráfego de rede bloqueado."
                : $"❌  Falha ao isolar host: {r.Error}");
    }

    [RelayCommand]
    private async Task LiftContainment()
    {
        var aid = SelectedAlertRow?.Alert.Aid;
        if (string.IsNullOrWhiteSpace(aid))
        {
            SetActionResult(false, "AID não disponível para este alerta.");
            return;
        }
        IsActionBusy = true;
        SetActionResult(false, "Levantando contenção…");
        var r = await _falcon.LiftContainmentAsync(aid).ConfigureAwait(true);
        IsActionBusy = false;
        SetActionResult(r.IsSuccess,
            r.IsSuccess
                ? $"✅  Contenção levantada — '{SelectedAlertRow?.SourceEndpoint}' reintegrado à rede."
                : $"❌  Falha: {r.Error}");
    }

    // ─── Ações de IR — Navegar para ferramentas ───────────────────────────────
    [RelayCommand]
    private void OpenRtr()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        _nav.NavigateTo("rtr");
    }

    [RelayCommand]
    private void RunVelociraptor()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        _context.PreferredForensicsTool = ForensicsToolKind.Velociraptor;
        _nav.NavigateTo("forensics");
    }

    [RelayCommand]
    private void OpenForensics()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        _nav.NavigateTo("forensics");
    }

    [RelayCommand]
    private void OpenMemory()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        _nav.NavigateTo("memory");
    }

    // ─── Ações de IR — Atualizar status na Falcon ─────────────────────────────
    [RelayCommand]
    private async Task UpdateStatus(string status)
    {
        var compositeId = SelectedAlertRow?.Alert.CompositeId;
        if (string.IsNullOrWhiteSpace(compositeId)) return;
        IsActionBusy = true;
        SetActionResult(false, $"Atualizando status para '{TranslateStatus(status)}'…");
        var r = await _falcon.UpdateAlertStatusAsync(compositeId, status).ConfigureAwait(true);
        IsActionBusy = false;
        SetActionResult(r.IsSuccess,
            r.IsSuccess
                ? $"✅  Status atualizado para: {TranslateStatus(status)}"
                : $"❌  Falha ao atualizar status: {r.Error}");
        if (r.IsSuccess)
            _ = LoadCommand.ExecuteAsync(null); // reload silencioso para refletir novo status na grade
    }

    // ─── Ações de IR — Encaminhar para Incidente ──────────────────────────────
    [RelayCommand]
    private async Task EscalateToIncident()
    {
        if (SelectedAlertRow is null) return;
        // Marca como Em Progresso para sinalizar ao analista no Falcon Console
        var compositeId = SelectedAlertRow.Alert.CompositeId;
        if (!string.IsNullOrWhiteSpace(compositeId))
        {
            IsActionBusy = true;
            SetActionResult(false, "Marcando alerta como Em Progresso…");
            await _falcon.UpdateAlertStatusAsync(compositeId, "in_progress").ConfigureAwait(true);
            IsActionBusy = false;
        }
        SetActionResult(true,
            "✅  Alerta marcado como Em Progresso.\n" +
            "O Falcon agrupa automaticamente alertas correlacionados em Incidentes.\n" +
            "Acesse Incidentes (Ctrl+2) para acompanhar o agrupamento.");
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private void SetActionResult(bool isSuccess, string message)
    {
        ActionIsSuccess    = isSuccess;
        ActionMessage      = message;
        ActionMessageColor = isSuccess ? new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0x7F))
                                       : new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52));
    }

    private static string TranslateStatus(string s) => s switch
    {
        "new"            => "Novo",
        "in_progress"    => "Em Progresso",
        "true_positive"  => "Verdadeiro Positivo",
        "false_positive" => "Falso Positivo",
        "ignored"        => "Ignorado",
        "closed"         => "Fechado",
        _                => s
    };
}

// ─── Row VM ────────────────────────────────────────────────────────────────────
/// <summary>Linha do DataGrid com formatação NG-SIEM-like.</summary>
public sealed class AlertRowVm
{
    public FalconAlert Alert { get; }
    public Brush SeverityBrush { get; }
    public string SeverityLabel { get; }
    public string DetectTime    => Alert.CreatedUtc.ToLocalTime().ToString("HH:mm:ss");
    public string DateGroup     => Alert.CreatedUtc.ToLocalTime().ToString("dd 'de' MMMM 'de' yyyy", new CultureInfo("pt-BR"));
    public string DetectionName => string.IsNullOrWhiteSpace(Alert.Name) ? Alert.Description : Alert.Name;
    public string Category      => Alert.Product?.ToLowerInvariant() switch
    {
        "epp"       => "Endpoint",
        "idp"       => "Identity",
        "ngsiem"    => "NG-SIEM",
        "mobile"    => "Mobile",
        "cloud"     => "Cloud",
        "overwatch" => "OverWatch",
        "xdr"       => "XDR",
        _           => Alert.Product ?? ""
    };
    public string AccountName    => string.IsNullOrWhiteSpace(Alert.UserName) ? "—" : Alert.UserName;
    public string SourceEndpoint => string.IsNullOrWhiteSpace(Alert.Hostname) ? "—" : Alert.Hostname;
    public string AssignedTo     => string.IsNullOrWhiteSpace(Alert.AssignedToName) ? "Não atribuído" : Alert.AssignedToName;
    public string StatusLabel    => Alert.Status switch
    {
        "new"            => "Novo",
        "in_progress"    => "Em progresso",
        "true_positive"  => "Verdadeiro positivo",
        "false_positive" => "Falso positivo",
        "ignored"        => "Ignorado",
        "closed"         => "Fechado",
        _                => Alert.Status ?? ""
    };
    public string TacticTechnique
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Alert.Tactic) && string.IsNullOrWhiteSpace(Alert.Technique)) return "";
            return $"{Alert.Tactic} · {Alert.Technique}".Trim(' ', '·');
        }
    }
    public string MitreDisplay
    {
        get
        {
            var tactic    = Alert.Tactic;
            var technique = Alert.Technique;
            var techId    = Alert.TechniqueId;
            if (string.IsNullOrWhiteSpace(tactic) && string.IsNullOrWhiteSpace(technique)) return "—";
            return !string.IsNullOrWhiteSpace(techId)
                ? $"{tactic} · {techId} {technique}"
                : $"{tactic} · {technique}";
        }
    }
    public string CompositeIdShort => Alert.CompositeId.Length > 12 ? Alert.CompositeId[..12] + "…" : Alert.CompositeId;
    public string AidShort => string.IsNullOrWhiteSpace(Alert.Aid) ? "—" : (Alert.Aid.Length > 12 ? Alert.Aid[..12] + "…" : Alert.Aid);
    public bool HasAid     => !string.IsNullOrWhiteSpace(Alert.Aid);
    public bool IsSelected { get; set; }

    private AlertRowVm(FalconAlert a)
    {
        Alert = a;
        SeverityLabel = a.Severity.ToString();
        SeverityBrush = a.Severity switch
        {
            Severity.Critical      => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
            Severity.High          => new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)),
            Severity.Medium        => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
            Severity.Low           => new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
            _                      => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
        };
    }

    public bool MatchesSearch(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return true;
        text = text.Trim().ToLowerInvariant();
        return (DetectionName?.ToLowerInvariant().Contains(text) ?? false)
            || (SourceEndpoint?.ToLowerInvariant().Contains(text) ?? false)
            || (AccountName?.ToLowerInvariant().Contains(text) ?? false)
            || (TacticTechnique?.ToLowerInvariant().Contains(text) ?? false)
            || (Category?.ToLowerInvariant().Contains(text) ?? false);
    }

    public static AlertRowVm From(FalconAlert a) => new(a);
}
