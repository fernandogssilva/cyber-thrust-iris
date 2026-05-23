using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class HealthCheckViewModel : ViewModelBase
{
    private readonly HealthCheckService _svc;
    public ObservableCollection<HealthResult> Results { get; } = new();
    [ObservableProperty] private int _passCount;
    [ObservableProperty] private int _warnCount;
    [ObservableProperty] private int _failCount;
    [ObservableProperty] private int _skippedCount;
    [ObservableProperty] private double _completedPercent;

    public HealthCheckViewModel(HealthCheckService svc)
    {
        _svc = svc;
        _ = RunCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private async Task Run()
    {
        IsBusy = true; BusyMessage = "Executando self-validation…";
        Results.Clear();
        PassCount = WarnCount = FailCount = SkippedCount = 0;
        CompletedPercent = 0;
        var total = 0;
        await foreach (var r in _svc.RunAllAsync())
        {
            total++;
            Results.Add(r);
            switch (r.Status)
            {
                case HealthStatus.Pass: PassCount++; break;
                case HealthStatus.Warn: WarnCount++; break;
                case HealthStatus.Fail: FailCount++; break;
                case HealthStatus.Skipped: SkippedCount++; break;
            }
            CompletedPercent = Math.Min(100, total * 100.0 / 12);
        }
        CompletedPercent = 100;
        IsBusy = false;
    }
}
