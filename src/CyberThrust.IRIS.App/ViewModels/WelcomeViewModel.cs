using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class WelcomeViewModel : ViewModelBase
{
    private readonly INavigationService _nav;
    private readonly IFalconClient _falcon;
    private readonly SessionCredentials _creds;
    private readonly ThreatIntelFeedService _feed;
    private readonly AppConfigStore _cfg;

    // ─── Greeting ──────────────────────────────────────────────────
    [ObservableProperty] private string _greeting = string.Empty;
    [ObservableProperty] private string _currentDateTime = string.Empty;
    [ObservableProperty] private string _operatorLine = "Operador anônimo (faça login para identificar)";

    // ─── Capability cards ──────────────────────────────────────────
    [ObservableProperty] private string _entraStatus = "Não configurado";
    [ObservableProperty] private Brush _entraStatusBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40));
    [ObservableProperty] private string _entraStatusDetail = "Configure Tenant + Client ID em Configurações";

    [ObservableProperty] private string _falconStatus = "Não conectado";
    [ObservableProperty] private Brush _falconStatusBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40));
    [ObservableProperty] private string _falconStatusDetail = "Configure ClientID/Secret em Configurações";

    [ObservableProperty] private string _threatIntelStatus = "Verificando…";
    [ObservableProperty] private Brush _threatIntelStatusBrush = new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9));
    [ObservableProperty] private string _threatIntelStatusDetail = "URLhaus · ThreatFox · MalwareBazaar (abuse.ch)";

    [ObservableProperty] private string _reputationStatus = "VirusTotal opcional";
    [ObservableProperty] private Brush _reputationStatusBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40));
    [ObservableProperty] private string _reputationStatusDetail = "Configure API key VirusTotal para análise extra";

    // ─── KPI Falcon (se autenticado) ───────────────────────────────
    [ObservableProperty] private bool _hasFalconKpis;
    [ObservableProperty] private int _kpiHosts;
    [ObservableProperty] private int _kpiDetections;
    [ObservableProperty] private int _kpiCritical;
    [ObservableProperty] private int _kpiPutFiles;
    [ObservableProperty] private string _kpiLastUpdate = "—";
    [ObservableProperty] private string _kpiCloud = "—";

    // ─── Live Threat Feed (URLhaus, ThreatFox, MalwareBazaar) ─────
    public ObservableCollection<ThreatIocItem> LiveFeed { get; } = new();
    [ObservableProperty] private bool _isLoadingFeed = true;
    [ObservableProperty] private string _feedLastUpdate = "Carregando…";

    public WelcomeViewModel(INavigationService nav, IFalconClient falcon, SessionCredentials creds, ThreatIntelFeedService feed, AppConfigStore cfg)
    {
        _nav = nav;
        _falcon = falcon;
        _creds = creds;
        _feed = feed;
        _cfg = cfg;

        UpdateGreeting();
        UpdateStatusCards();

        _ = LoadAsync();
    }

    private void UpdateGreeting()
    {
        var hour = DateTime.Now.Hour;
        Greeting = hour switch
        {
            >= 5 and < 12 => "Bom dia",
            >= 12 and < 18 => "Boa tarde",
            >= 18 and < 24 => "Boa noite",
            _ => "Trabalhando na madrugada"
        };
        CurrentDateTime = DateTime.Now.ToString("dddd, dd 'de' MMMM 'de' yyyy · HH:mm", new System.Globalization.CultureInfo("pt-BR"));
    }

    private void UpdateStatusCards()
    {
        var snap = _cfg.Load();

        // Entra
        if (!string.IsNullOrWhiteSpace(snap.EntraId.ClientId) && !snap.EntraId.ClientId.StartsWith("00000000"))
        {
            EntraStatus = "Configurado";
            EntraStatusBrush = new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76));
            EntraStatusDetail = $"Tenant: {snap.EntraId.TenantId}";
        }

        // Falcon
        if (!string.IsNullOrWhiteSpace(snap.Falcon.ClientId) && !string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret))
        {
            FalconStatus = "Configurado";
            FalconStatusBrush = new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76));
            FalconStatusDetail = $"Cloud: {snap.Falcon.Cloud}";
        }

        // VirusTotal
        if (!string.IsNullOrWhiteSpace(_creds.VirusTotalApiKey))
        {
            ReputationStatus = "VirusTotal ativo";
            ReputationStatusBrush = new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76));
            ReputationStatusDetail = "+ MalwareBazaar · URLhaus · ThreatFox (open)";
        }
    }

    private async Task LoadAsync()
    {
        // 1) Threat Intel Feed (sempre disponível, sem auth)
        IsLoadingFeed = true;
        try
        {
            var items = await _feed.GetCombinedFeedAsync(perSource: 4).ConfigureAwait(true);
            LiveFeed.Clear();
            foreach (var i in items.Take(12)) LiveFeed.Add(i);
            if (LiveFeed.Count > 0)
            {
                ThreatIntelStatus = "Online";
                ThreatIntelStatusBrush = new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76));
                FeedLastUpdate = $"Atualizado às {DateTime.Now:HH:mm:ss} · {LiveFeed.Count} IOCs (últimas 24h)";
            }
            else
            {
                ThreatIntelStatus = "Sem conexão";
                ThreatIntelStatusBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52));
                FeedLastUpdate = "Falha ao carregar feed (verifique conectividade)";
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Welcome feed falhou");
            FeedLastUpdate = "Falha: " + ex.Message;
        }
        finally
        {
            IsLoadingFeed = false;
        }

        // 2) Falcon KPIs (só se configurado)
        var snap = _cfg.Load();
        if (string.IsNullOrWhiteSpace(snap.Falcon.ClientId) || string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret))
        {
            HasFalconKpis = false;
            return;
        }

        try
        {
            var cap = await _falcon.ProbeCapabilitiesAsync().ConfigureAwait(true);
            if (cap.IsSuccess)
            {
                KpiCloud = cap.Value!.CloudRegion;
                FalconStatus = $"Conectado ({KpiCloud})";
                FalconStatusBrush = new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76));
                FalconStatusDetail = $"Módulos: {string.Join(", ", cap.Value.Licensed)}";
            }

            var det = await _falcon.ListRecentDetectionsAsync(50).ConfigureAwait(true);
            if (det.IsSuccess)
            {
                KpiDetections = det.Value!.Count;
                KpiCritical = det.Value.Count(x => x.Severity == Core.Models.Severity.Critical || x.Severity == Core.Models.Severity.High);
            }

            var hosts = await _falcon.SearchHostsAsync("status:'normal'").ConfigureAwait(true);
            if (hosts.IsSuccess) KpiHosts = hosts.Value!.Count;

            HasFalconKpis = true;
            KpiLastUpdate = DateTime.Now.ToString("HH:mm:ss");
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Welcome Falcon KPIs falhou");
        }
    }

    [RelayCommand] private void GoToSettings() => _nav.NavigateTo("settings");
    [RelayCommand] private void GoToReputation() => _nav.NavigateTo("reputation");
    [RelayCommand] private void GoToDashboard() => _nav.NavigateTo("dashboard");
    [RelayCommand] private void GoToHealth() => _nav.NavigateTo("health");
    [RelayCommand] private void GoToLogin() => _nav.NavigateTo("login");
    [RelayCommand] private async Task Refresh() { UpdateGreeting(); UpdateStatusCards(); await LoadAsync(); }
}
