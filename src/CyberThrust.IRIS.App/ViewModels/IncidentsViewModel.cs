using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

/// <summary>
/// Incidentes — agrupamentos de detecções relacionadas via Falcon Incidents API v1.
/// Cada Incident combina N alerts/detections, hosts e tactics, e tem fine_score (0-100)
/// que pondera severidade global. NÃO é a lista de alerts individuais (que vive em AlertsViewModel).
/// </summary>
public partial class IncidentsViewModel : ViewModelBase
{
    private readonly IFalconClient _falcon;
    private readonly INavigationService _nav;
    private readonly AppConfigStore _cfg;

    public ObservableCollection<IncidentCardVm> Incidents { get; } = new();

    public ObservableCollection<string> TimeOptions { get; } = new(new[] { "Últimas 24 horas", "Últimos 7 dias", "Últimos 30 dias", "Últimos 90 dias", "Tudo" });
    public ObservableCollection<string> StatusOptions { get; } = new(new[] { "(Todos)", "new", "reopened", "in_progress", "closed" });

    [ObservableProperty] private string _selectedTime = "Últimos 7 dias";
    [ObservableProperty] private string _selectedStatus = "(Todos)";

    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _newCount;
    [ObservableProperty] private int _inProgressCount;
    [ObservableProperty] private int _closedCount;
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
        IsBusy = true; BusyMessage = "Consultando /incidents/queries/incidents/v1…"; HasError = false; LastError = null;
        var snap = _cfg.Load();
        ShowConfigBanner = string.IsNullOrWhiteSpace(snap.Falcon.ClientId) || string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret);
        if (ShowConfigBanner) { IsBusy = false; StatusLine = "Falcon não configurado."; return; }

        try
        {
            var lookBack = SelectedTime switch
            {
                "Últimas 24 horas" => TimeSpan.FromHours(24),
                "Últimos 7 dias" => TimeSpan.FromDays(7),
                "Últimos 30 dias" => TimeSpan.FromDays(30),
                "Últimos 90 dias" => TimeSpan.FromDays(90),
                _ => (TimeSpan?)null
            };
            var r = await _falcon.ListIncidentsAsync(lookBack, limit: 200).ConfigureAwait(true);
            if (r.IsFailure)
            {
                HasError = true; LastError = r.Error!.ToString();
                StatusLine = "Falha na Incidents API.";
                return;
            }
            var all = r.Value!;
            if (SelectedStatus != "(Todos)")
                all = all.Where(x => x.Status == SelectedStatus).ToArray();

            Incidents.Clear();
            foreach (var i in all) Incidents.Add(IncidentCardVm.From(i));

            TotalCount = Incidents.Count;
            CriticalCount = Incidents.Count(x => x.Incident.Severity == Severity.Critical || x.Incident.Severity == Severity.High);
            NewCount = Incidents.Count(x => x.Incident.Status == "new" || x.Incident.Status == "reopened");
            InProgressCount = Incidents.Count(x => x.Incident.Status == "in_progress");
            ClosedCount = Incidents.Count(x => x.Incident.Status == "closed");

            StatusLine = $"{Incidents.Count} incidentes · atualizado às {DateTime.Now:HH:mm:ss}";
            Log.Information("Incidents carregados: {N}", Incidents.Count);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Incidents.Load falhou");
            HasError = true; LastError = ex.Message;
        }
        finally { IsBusy = false; }
    }

    [RelayCommand] private void GoToSettings() => _nav.NavigateTo("settings");
    [RelayCommand] private void GoToAlerts() => _nav.NavigateTo("alerts");
}

public sealed class IncidentCardVm
{
    public FalconIncident Incident { get; }
    public Brush SeverityBrush { get; }
    public string SeverityLabel => Incident.Severity.ToString();
    public string FineScoreLabel => $"{Incident.FineScore}/100";
    public string Name => string.IsNullOrWhiteSpace(Incident.Name) ? $"Incident {Incident.IncidentId[..Math.Min(8, Incident.IncidentId.Length)]}" : Incident.Name;
    public string HostsLabel => $"{Incident.HostsCount} host{(Incident.HostsCount == 1 ? "" : "s")} · {Incident.DetectionsCount} detecções";
    public string TacticsCsv => Incident.Tactics.Count == 0 ? "—" : string.Join(" · ", Incident.Tactics.Distinct().Take(4));
    public string TechniquesCsv => Incident.Techniques.Count == 0 ? "" : string.Join(" · ", Incident.Techniques.Distinct().Take(4));
    public string HostsCsv => Incident.Hostnames.Count == 0 ? "—" : string.Join(", ", Incident.Hostnames.Take(3)) + (Incident.Hostnames.Count > 3 ? $" +{Incident.Hostnames.Count - 3}" : "");
    public string AssignedTo => string.IsNullOrWhiteSpace(Incident.AssignedToName) ? "Não atribuído" : Incident.AssignedToName;
    public string StatusLabel => Incident.Status switch
    {
        "new" => "NOVO",
        "reopened" => "REABERTO",
        "in_progress" => "EM PROGRESSO",
        "closed" => "FECHADO",
        _ => Incident.Status?.ToUpper() ?? ""
    };
    public string AgeLabel
    {
        get
        {
            var d = DateTimeOffset.UtcNow - Incident.CreatedUtc;
            if (d.TotalMinutes < 60) return $"{(int)d.TotalMinutes}m";
            if (d.TotalHours < 24) return $"{(int)d.TotalHours}h";
            return $"{(int)d.TotalDays}d";
        }
    }

    private IncidentCardVm(FalconIncident i)
    {
        Incident = i;
        SeverityBrush = i.Severity switch
        {
            Severity.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
            Severity.High => new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)),
            Severity.Medium => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
            Severity.Low => new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
            _ => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
        };
    }

    public static IncidentCardVm From(FalconIncident i) => new(i);
}
