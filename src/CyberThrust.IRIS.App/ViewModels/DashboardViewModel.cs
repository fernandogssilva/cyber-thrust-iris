using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    private readonly IFalconClient _falcon;
    [ObservableProperty] private FalconCapability? _capability;
    public ObservableCollection<FalconDetection> RecentDetections { get; } = new();
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private string? _lastError;

    public DashboardViewModel(IFalconClient falcon)
    {
        _falcon = falcon;
        _ = RefreshCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private async Task Refresh()
    {
        IsBusy = true; BusyMessage = "Carregando dashboard…"; LastError = null;
        try
        {
            var cap = await _falcon.ProbeCapabilitiesAsync().ConfigureAwait(true);
            if (cap.IsSuccess) Capability = cap.Value;

            var det = await _falcon.ListRecentDetectionsAsync(50).ConfigureAwait(true);
            if (det.IsFailure) { LastError = det.Error!.ToString(); return; }

            RecentDetections.Clear();
            foreach (var d in det.Value!) RecentDetections.Add(d);
            CriticalCount = RecentDetections.Count(x => x.Severity == Severity.Critical);
            HighCount = RecentDetections.Count(x => x.Severity == Severity.High);
            MediumCount = RecentDetections.Count(x => x.Severity == Severity.Medium);
        }
        finally
        {
            IsBusy = false;
        }
    }
}
