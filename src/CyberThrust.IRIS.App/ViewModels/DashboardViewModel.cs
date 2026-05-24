using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    private readonly IFalconClient _falcon;
    private readonly INavigationService _nav;
    private readonly AppConfigStore _configStore;

    [ObservableProperty] private FalconCapability? _capability;
    public ObservableCollection<DetectionCardVm> RecentDetections { get; } = new();
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _fleetHostCount;
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private bool _hasError;
    [ObservableProperty] private string _statusLine = "Carregando…";
    [ObservableProperty] private bool _showConfigBanner;

    public DashboardViewModel(IFalconClient falcon, INavigationService nav, AppConfigStore configStore)
    {
        _falcon = falcon;
        _nav = nav;
        _configStore = configStore;
        _ = RefreshCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private async Task Refresh()
    {
        IsBusy = true; BusyMessage = "Carregando dashboard…"; LastError = null; HasError = false;
        try
        {
            // Detecta config inválida — mostra banner
            var snap = _configStore.Load();
            ShowConfigBanner = string.IsNullOrWhiteSpace(snap.Falcon.ClientId) || string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret);
            if (ShowConfigBanner)
            {
                StatusLine = "Falcon não configurado — preencha credenciais em Configurações.";
                return;
            }

            StatusLine = "Conectando ao Falcon…";
            var cap = await _falcon.ProbeCapabilitiesAsync().ConfigureAwait(true);
            if (cap.IsSuccess) { Capability = cap.Value; StatusLine = $"Conectado · cloud={cap.Value!.CloudRegion} · módulos: {string.Join(", ", cap.Value.Licensed)}"; }
            else { StatusLine = $"Capability probe falhou: {cap.Error}"; }

            StatusLine += " · carregando detecções…";
            var det = await _falcon.ListRecentDetectionsAsync(50).ConfigureAwait(true);
            if (det.IsFailure)
            {
                LastError = det.Error!.ToString();
                HasError = true;
                StatusLine = $"Erro ao listar detecções: {det.Error.CodeString}";
                return;
            }

            RecentDetections.Clear();
            foreach (var d in det.Value!) RecentDetections.Add(DetectionCardVm.From(d));
            CriticalCount = RecentDetections.Count(x => x.Detection.Severity == Severity.Critical);
            HighCount = RecentDetections.Count(x => x.Detection.Severity == Severity.High);
            MediumCount = RecentDetections.Count(x => x.Detection.Severity == Severity.Medium);

            var hosts = await _falcon.SearchHostsAsync("status:'normal'").ConfigureAwait(true);
            if (hosts.IsSuccess) FleetHostCount = hosts.Value!.Count;

            StatusLine = $"Atualizado às {DateTime.Now:HH:mm:ss} · {RecentDetections.Count} detecções · {FleetHostCount} hosts";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Falha no Dashboard.Refresh");
            LastError = ex.Message;
            HasError = true;
            StatusLine = "Falha no refresh — veja logs.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void GoToSettings() => _nav.NavigateTo("settings");

    [RelayCommand]
    private async Task Investigate(DetectionCardVm? card)
    {
        if (card is null) return;
        MessageBox.Show($"Drill-down para detection {card.Detection.DetectionId}\n\nHost: {card.Detection.Hostname}\nTactic: {card.Detection.Tactic}\nTechnique: {card.Detection.Technique}\n\n(Tela de investigação detalhada será adicionada na v0.4)",
            "Investigar", MessageBoxButton.OK, MessageBoxImage.Information);
        await Task.CompletedTask;
    }

    [RelayCommand]
    private async Task IsolateHost(DetectionCardVm? card)
    {
        if (card is null) return;
        var reply = MessageBox.Show($"Isolar host {card.Detection.Hostname} ({card.Detection.Aid[..8]}…)?\n\nEsta ação coloca o host em containment via Falcon — ele perde conectividade exceto com o Falcon Console.",
            "Confirmar isolamento", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (reply != MessageBoxResult.Yes) return;
        IsBusy = true; BusyMessage = "Isolando host…";
        try
        {
            var r = await _falcon.ContainHostAsync(card.Detection.Aid).ConfigureAwait(true);
            if (r.IsSuccess)
                MessageBox.Show($"✓ Host {card.Detection.Hostname} isolado com sucesso.", "OK", MessageBoxButton.OK, MessageBoxImage.Information);
            else
                MessageBox.Show($"✗ Falha ao isolar: {r.Error}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
        }
    }
}

/// <summary>VM wrapper que adiciona cor de severidade ao card.</summary>
public sealed class DetectionCardVm
{
    public FalconDetection Detection { get; }
    public Brush SeverityColor { get; }
    public string Severity => Detection.Severity.ToString();
    public string Hostname => Detection.Hostname;
    public string Description => Detection.Description;
    public string Tactic => string.IsNullOrWhiteSpace(Detection.Tactic) ? "—" : Detection.Tactic;
    public string Technique => string.IsNullOrWhiteSpace(Detection.Technique) ? "—" : Detection.Technique;
    public DateTimeOffset TimestampUtc => Detection.TimestampUtc;

    private DetectionCardVm(FalconDetection d)
    {
        Detection = d;
        SeverityColor = d.Severity switch
        {
            Core.Models.Severity.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
            Core.Models.Severity.High => new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)),
            Core.Models.Severity.Medium => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
            Core.Models.Severity.Low => new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
            _ => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
        };
    }

    public static DetectionCardVm From(FalconDetection d) => new(d);
}
