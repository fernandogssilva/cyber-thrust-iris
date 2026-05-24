using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class ReputationViewModel : ViewModelBase
{
    private readonly ArtifactReputationClient _client;
    private readonly SessionCredentials _creds;

    [ObservableProperty] private string _artifactInput = string.Empty;
    [ObservableProperty] private ArtifactKind _selectedKind = ArtifactKind.FileHash;
    public ObservableCollection<ArtifactKind> KindOptions { get; } = new(new[] { ArtifactKind.FileHash, ArtifactKind.Url, ArtifactKind.Domain, ArtifactKind.IpAddress });

    [ObservableProperty] private ArtifactReputationReport? _report;
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private bool _hasVirusTotalKey;
    [ObservableProperty] private bool _hasReport;

    // Indicadores visuais
    [ObservableProperty] private string _verdictLabel = "—";
    [ObservableProperty] private Brush _verdictBrush = new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9));
    [ObservableProperty] private string _detectionRatioText = "—";
    [ObservableProperty] private double _detectionRatioPercent;

    public ReputationViewModel(ArtifactReputationClient client, SessionCredentials creds)
    {
        _client = client;
        _creds = creds;
        HasVirusTotalKey = !string.IsNullOrWhiteSpace(_creds.VirusTotalApiKey);
        _creds.Changed += () => HasVirusTotalKey = !string.IsNullOrWhiteSpace(_creds.VirusTotalApiKey);
    }

    [RelayCommand]
    private async Task Analyze()
    {
        if (string.IsNullOrWhiteSpace(ArtifactInput)) return;
        IsBusy = true; BusyMessage = $"Consultando reputação de {SelectedKind}…";
        ErrorMessage = null; HasReport = false;
        try
        {
            var report = await _client.QueryAsync(ArtifactInput.Trim(), SelectedKind).ConfigureAwait(true);
            Report = report;
            HasReport = true;
            VerdictLabel = report.Verdict.ToString().ToUpper();
            VerdictBrush = report.Verdict switch
            {
                Verdict.Malicious => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
                Verdict.Suspicious => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
                Verdict.Clean => new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76)),
                _ => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
            };
            DetectionRatioPercent = report.DetectionRatio;
            DetectionRatioText = report.TotalEngines is > 0
                ? $"{report.MaliciousCount}/{report.TotalEngines} engines marcam como malicioso"
                : "Estatísticas indisponíveis (sem VirusTotal API key)";
            Log.Information("ArtifactReputation done: {V} ({Mal}/{Tot})", report.Verdict, report.MaliciousCount, report.TotalEngines);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "ReputationViewModel.Analyze falhou");
            ErrorMessage = $"[IRIS-NET-5004] {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
