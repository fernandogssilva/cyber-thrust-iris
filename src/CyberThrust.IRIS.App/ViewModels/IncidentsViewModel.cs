using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class IncidentsViewModel : ViewModelBase
{
    private readonly IFalconClient _falcon;
    private readonly INavigationService _nav;
    private readonly AppConfigStore _cfg;

    public ObservableCollection<AlertCardVm> Alerts { get; } = new();

    // ─── Filtros ──────────────────────────────────────────────────
    public ObservableCollection<string> ProductOptions { get; } = new(new[]
    {
        "(Todos)", "epp", "idp", "ngsiem", "mobile", "cloud", "overwatch", "xdr"
    });
    public ObservableCollection<string> SeverityOptions { get; } = new(new[]
    {
        "(Todas)", "Critical", "High", "Medium", "Low", "Informational"
    });
    public ObservableCollection<string> StatusOptions { get; } = new(new[]
    {
        "(Todos)", "new", "in_progress", "true_positive", "false_positive", "ignored", "closed"
    });
    public ObservableCollection<string> PeriodOptions { get; } = new(new[]
    {
        "24 horas", "7 dias", "30 dias", "90 dias", "Tudo"
    });

    [ObservableProperty] private string _selectedProduct = "(Todos)";
    [ObservableProperty] private string _selectedSeverity = "(Todas)";
    [ObservableProperty] private string _selectedStatus = "(Todos)";
    [ObservableProperty] private string _selectedPeriod = "24 horas";

    // ─── KPIs ─────────────────────────────────────────────────────
    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _newCount;
    [ObservableProperty] private int _inProgressCount;

    [ObservableProperty] private string _statusLine = "Pronto.";
    [ObservableProperty] private bool _showConfigBanner;
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private bool _hasError;

    public IncidentsViewModel(IFalconClient falcon, INavigationService nav, AppConfigStore cfg)
    {
        _falcon = falcon;
        _nav = nav;
        _cfg = cfg;
        _ = LoadCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private async Task Load()
    {
        IsBusy = true; BusyMessage = "Consultando Falcon Alerts API v2…"; HasError = false; LastError = null;

        // Verifica config
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
                LookBack: SelectedPeriod switch
                {
                    "24 horas" => TimeSpan.FromHours(24),
                    "7 dias" => TimeSpan.FromDays(7),
                    "30 dias" => TimeSpan.FromDays(30),
                    "90 dias" => TimeSpan.FromDays(90),
                    _ => null
                },
                Limit: 500);

            var r = await _falcon.ListAlertsAsync(filter).ConfigureAwait(true);
            if (r.IsFailure)
            {
                HasError = true;
                LastError = r.Error!.ToString();
                StatusLine = "Falha ao consultar alertas.";
                Log.Warning("Alerts API falhou: {Err}", r.Error);
                return;
            }

            Alerts.Clear();
            foreach (var a in r.Value!) Alerts.Add(AlertCardVm.From(a));

            TotalCount = Alerts.Count;
            CriticalCount = Alerts.Count(x => x.Alert.Severity == Severity.Critical);
            HighCount = Alerts.Count(x => x.Alert.Severity == Severity.High);
            NewCount = Alerts.Count(x => x.Alert.Status == "new");
            InProgressCount = Alerts.Count(x => x.Alert.Status == "in_progress");

            // Breakdown por produto
            var byProduct = Alerts.GroupBy(x => string.IsNullOrWhiteSpace(x.Alert.Product) ? "(sem product)" : x.Alert.Product)
                                  .Select(g => $"{g.Key}={g.Count()}")
                                  .OrderByDescending(s => s);
            StatusLine = $"{Alerts.Count} alertas · {string.Join(" · ", byProduct)} · atualizado às {DateTime.Now:HH:mm:ss}";
            Log.Information("Alerts carregados: {N}", Alerts.Count);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Incidents.Load");
            HasError = true; LastError = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void GoToSettings() => _nav.NavigateTo("settings");
}

/// <summary>VM wrapper com cor da severity e label do produto.</summary>
public sealed class AlertCardVm
{
    public FalconAlert Alert { get; }
    public Brush SeverityBrush { get; }
    public Brush ProductBrush { get; }
    public string ProductLabel { get; }

    public string Severity => Alert.Severity.ToString();
    public string Hostname => string.IsNullOrWhiteSpace(Alert.Hostname) ? "—" : Alert.Hostname;
    public string Identity => string.IsNullOrWhiteSpace(Alert.UserName) ? "" : "👤 " + Alert.UserName;
    public string Name => string.IsNullOrWhiteSpace(Alert.Name) ? Alert.Description : Alert.Name;
    public string MitreLine
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Alert.Tactic) && string.IsNullOrWhiteSpace(Alert.Technique)) return "";
            return $"{Alert.Tactic} · {Alert.Technique}".Trim(' ', '·');
        }
    }
    public string AgeLabel
    {
        get
        {
            var d = DateTimeOffset.UtcNow - Alert.CreatedUtc;
            if (d.TotalMinutes < 1) return "agora";
            if (d.TotalMinutes < 60) return $"{(int)d.TotalMinutes}m";
            if (d.TotalHours < 24) return $"{(int)d.TotalHours}h";
            return $"{(int)d.TotalDays}d";
        }
    }
    public string StatusLabel => Alert.Status switch
    {
        "new" => "NOVO",
        "in_progress" => "EM PROGRESSO",
        "true_positive" => "VERDADEIRO POSITIVO",
        "false_positive" => "FALSO POSITIVO",
        "ignored" => "IGNORADO",
        "closed" => "FECHADO",
        _ => Alert.Status?.ToUpper() ?? ""
    };

    private AlertCardVm(FalconAlert a)
    {
        Alert = a;
        SeverityBrush = a.Severity switch
        {
            Core.Models.Severity.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
            Core.Models.Severity.High => new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)),
            Core.Models.Severity.Medium => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
            Core.Models.Severity.Low => new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
            _ => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
        };
        (ProductLabel, ProductBrush) = a.Product?.ToLowerInvariant() switch
        {
            "epp" => ("EDR", new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF))),
            "idp" => ("IDENTITY", new SolidColorBrush(Color.FromRgb(0x7C, 0x4D, 0xFF))),
            "ngsiem" => ("NG-SIEM", new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76))),
            "mobile" => ("MOBILE", new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40))),
            "cloud" => ("CLOUD", new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52))),
            "overwatch" => ("OVERWATCH", new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80))),
            "xdr" => ("XDR", new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF))),
            _ => (a.Product?.ToUpper() ?? "OUTRO", new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9)))
        };
    }

    public static AlertCardVm From(FalconAlert a) => new(a);
}
