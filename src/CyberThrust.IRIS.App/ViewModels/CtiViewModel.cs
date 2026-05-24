using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class CtiViewModel : ViewModelBase
{
    private readonly CtiIntelService _cti;
    private readonly SessionCredentials _creds;

    [ObservableProperty] private string _target = string.Empty;
    [ObservableProperty] private CtiTargetKind _selectedKind = CtiTargetKind.Domain;
    public ObservableCollection<CtiTargetKind> KindOptions { get; } = new(new[] { CtiTargetKind.Domain, CtiTargetKind.IpAddress, CtiTargetKind.Url, CtiTargetKind.FileHash });

    [ObservableProperty] private CtiReport? _report;
    [ObservableProperty] private bool _hasReport;
    [ObservableProperty] private string? _errorMessage;

    [ObservableProperty] private string _verdictLabel = "—";
    [ObservableProperty] private Brush _verdictBrush = new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9));
    [ObservableProperty] private bool _hasReputation;
    [ObservableProperty] private bool _hasExposure;
    [ObservableProperty] private bool _hasVulnerabilities;
    [ObservableProperty] private bool _hasPivots;

    // Status das 4 fontes
    [ObservableProperty] private bool _abuseConfigured;
    [ObservableProperty] private bool _vtConfigured;
    [ObservableProperty] private bool _shodanConfigured;
    [ObservableProperty] private bool _fofaConfigured;

    public CtiViewModel(CtiIntelService cti, SessionCredentials creds)
    {
        _cti = cti;
        _creds = creds;
        UpdateConfigStatus();
        _creds.Changed += UpdateConfigStatus;
    }

    private void UpdateConfigStatus()
    {
        AbuseConfigured = !string.IsNullOrWhiteSpace(_creds.AbuseIpdbApiKey);
        VtConfigured = !string.IsNullOrWhiteSpace(_creds.VirusTotalApiKey);
        ShodanConfigured = !string.IsNullOrWhiteSpace(_creds.ShodanApiKey);
        FofaConfigured = !string.IsNullOrWhiteSpace(_creds.FofaKey);
    }

    [RelayCommand]
    private async Task Investigate()
    {
        if (string.IsNullOrWhiteSpace(Target)) return;
        IsBusy = true; BusyMessage = $"Consultando {SelectedKind} em 4 fontes…";
        ErrorMessage = null; HasReport = false;
        try
        {
            var report = await _cti.InvestigateAsync(Target.Trim(), SelectedKind).ConfigureAwait(true);
            Report = report;
            HasReport = true;
            HasReputation = report.Reputation is not null;
            HasExposure = report.Exposure is not null;
            HasVulnerabilities = report.Vulnerabilities.Count > 0;
            HasPivots = report.Pivots.Count > 0;
            VerdictLabel = report.OverallVerdict.ToString().ToUpper();
            VerdictBrush = report.OverallVerdict switch
            {
                Verdict.Malicious => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
                Verdict.Suspicious => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
                Verdict.Clean => new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76)),
                _ => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
            };
            Log.Information("CTI report: {Target} ({Kind}) → {Verdict} | {Sources} fontes | {Vulns} CVEs | {Pivots} pivots",
                report.Target, report.Kind, report.OverallVerdict, report.Sources.Count, report.Vulnerabilities.Count, report.Pivots.Count);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "CTI Investigate falhou");
            ErrorMessage = $"[IRIS-NET-5004] {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
