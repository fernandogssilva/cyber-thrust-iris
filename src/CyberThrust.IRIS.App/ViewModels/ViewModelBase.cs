using CommunityToolkit.Mvvm.ComponentModel;

namespace CyberThrust.IRIS.App.ViewModels;

public abstract partial class ViewModelBase : ObservableObject
{
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string? _busyMessage;
    [ObservableProperty] private double _progressPercent;
}
