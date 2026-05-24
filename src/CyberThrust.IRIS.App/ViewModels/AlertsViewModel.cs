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
/// Detecções unificadas — replica visualmente o Next-Gen SIEM Detections do Falcon Console:
/// DataGrid denso com colunas Severity | Detect time | Detection name | Category | Account |
/// Source endpoint | Country | Destination application | IP reputation | Assigned to | Status.
/// Multi-select, agrupamento por data, filtros chip no topo.
/// </summary>
public partial class AlertsViewModel : ViewModelBase
{
    private readonly IFalconClient _falcon;
    private readonly INavigationService _nav;
    private readonly AppConfigStore _cfg;

    public ObservableCollection<AlertRowVm> Alerts { get; } = new();
    public ICollectionView AlertsView { get; }

    // ─── Filtros (chips) ──────────────────────────────────────────
    public ObservableCollection<string> ProductOptions { get; } = new(new[] { "(Todos)", "epp", "idp", "ngsiem", "mobile", "cloud", "overwatch", "xdr" });
    public ObservableCollection<string> SeverityOptions { get; } = new(new[] { "(Todas)", "Critical", "High", "Medium", "Low", "Informational" });
    public ObservableCollection<string> StatusOptions { get; } = new(new[] { "(Todos)", "new", "in_progress", "true_positive", "false_positive", "ignored", "closed" });
    public ObservableCollection<string> TimeOptions { get; } = new(new[] { "Última 1 hora", "Últimas 24 horas", "Últimos 7 dias", "Últimos 30 dias", "Últimos 90 dias", "Tudo" });

    [ObservableProperty] private string _selectedProduct = "(Todos)";
    [ObservableProperty] private string _selectedSeverity = "(Todas)";
    [ObservableProperty] private string _selectedStatus = "(Todos)";
    [ObservableProperty] private string _selectedTime = "Últimas 24 horas";
    [ObservableProperty] private string _searchText = string.Empty;

    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private string _resultsLabel = "0 resultados";
    [ObservableProperty] private string _statusLine = "Pronto.";
    [ObservableProperty] private bool _showConfigBanner;
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private bool _hasError;

    public AlertsViewModel(IFalconClient falcon, INavigationService nav, AppConfigStore cfg)
    {
        _falcon = falcon;
        _nav = nav;
        _cfg = cfg;
        AlertsView = CollectionViewSource.GetDefaultView(Alerts);
        AlertsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(AlertRowVm.DateGroup)));
        _ = LoadCommand.ExecuteAsync(null);
    }

    partial void OnSearchTextChanged(string value) => AlertsView.Refresh();

    [RelayCommand]
    private async Task Load()
    {
        IsBusy = true; BusyMessage = "Consultando /alerts/queries/alerts/v2…"; HasError = false; LastError = null;
        var snap = _cfg.Load();
        ShowConfigBanner = string.IsNullOrWhiteSpace(snap.Falcon.ClientId) || string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret);
        if (ShowConfigBanner) { IsBusy = false; StatusLine = "Falcon não configurado."; return; }

        try
        {
            var filter = new FalconAlertsFilter(
                Products: SelectedProduct == "(Todos)" ? null : new[] { SelectedProduct },
                MinSeverities: SelectedSeverity switch
                {
                    "Critical" => new[] { Severity.Critical },
                    "High" => new[] { Severity.High },
                    "Medium" => new[] { Severity.Medium },
                    "Low" => new[] { Severity.Low },
                    "Informational" => new[] { Severity.Informational },
                    _ => null
                },
                Statuses: SelectedStatus == "(Todos)" ? null : new[] { SelectedStatus },
                LookBack: SelectedTime switch
                {
                    "Última 1 hora" => TimeSpan.FromHours(1),
                    "Últimas 24 horas" => TimeSpan.FromHours(24),
                    "Últimos 7 dias" => TimeSpan.FromDays(7),
                    "Últimos 30 dias" => TimeSpan.FromDays(30),
                    "Últimos 90 dias" => TimeSpan.FromDays(90),
                    _ => null
                },
                Limit: 1000);

            var r = await _falcon.ListAlertsAsync(filter).ConfigureAwait(true);
            if (r.IsFailure)
            {
                HasError = true; LastError = r.Error!.ToString();
                StatusLine = "Falha na API.";
                return;
            }
            Alerts.Clear();
            foreach (var a in r.Value!) Alerts.Add(AlertRowVm.From(a));
            TotalCount = Alerts.Count;
            ResultsLabel = $"{Alerts.Count} resultados ({Alerts.Count} total)";
            // Aplica search local
            AlertsView.Filter = obj => obj is AlertRowVm row && row.MatchesSearch(SearchText);

            var byProduct = Alerts.GroupBy(x => string.IsNullOrWhiteSpace(x.Alert.Product) ? "?" : x.Alert.Product)
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
        SelectedProduct = "(Todos)";
        SelectedSeverity = "(Todas)";
        SelectedStatus = "(Todos)";
        SelectedTime = "Últimas 24 horas";
        SearchText = string.Empty;
    }

    [RelayCommand] private void GoToSettings() => _nav.NavigateTo("settings");
}

/// <summary>Linha do DataGrid com formatação NG-SIEM-like.</summary>
public sealed class AlertRowVm
{
    public FalconAlert Alert { get; }
    public Brush SeverityBrush { get; }
    public string SeverityLabel { get; }
    public string DetectTime => Alert.CreatedUtc.ToLocalTime().ToString("HH:mm:ss");
    public string DateGroup => Alert.CreatedUtc.ToLocalTime().ToString("dd 'de' MMMM 'de' yyyy", new CultureInfo("pt-BR"));
    public string DetectionName => string.IsNullOrWhiteSpace(Alert.Name) ? Alert.Description : Alert.Name;
    public string Category => Alert.Product?.ToLowerInvariant() switch
    {
        "epp" => "Endpoint",
        "idp" => "Identity",
        "ngsiem" => "NG-SIEM",
        "mobile" => "Mobile",
        "cloud" => "Cloud",
        "overwatch" => "OverWatch",
        "xdr" => "XDR",
        _ => Alert.Product ?? ""
    };
    public string AccountName => string.IsNullOrWhiteSpace(Alert.UserName) ? "—" : Alert.UserName;
    public string SourceEndpoint => string.IsNullOrWhiteSpace(Alert.Hostname) ? "—" : Alert.Hostname;
    public string AssignedTo => string.IsNullOrWhiteSpace(Alert.AssignedToName) ? "Não atribuído" : Alert.AssignedToName;
    public string StatusLabel => Alert.Status switch
    {
        "new" => "Novo",
        "in_progress" => "Em progresso",
        "true_positive" => "Verdadeiro positivo",
        "false_positive" => "Falso positivo",
        "ignored" => "Ignorado",
        "closed" => "Fechado",
        _ => Alert.Status ?? ""
    };
    public string TacticTechnique
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Alert.Tactic) && string.IsNullOrWhiteSpace(Alert.Technique)) return "";
            return $"{Alert.Tactic} · {Alert.Technique}".Trim(' ', '·');
        }
    }
    public bool IsSelected { get; set; }

    private AlertRowVm(FalconAlert a)
    {
        Alert = a;
        SeverityLabel = a.Severity.ToString();
        SeverityBrush = a.Severity switch
        {
            Severity.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
            Severity.High => new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)),
            Severity.Medium => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
            Severity.Low => new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
            _ => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
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
