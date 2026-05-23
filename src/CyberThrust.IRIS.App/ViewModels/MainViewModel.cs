using System.Windows.Controls;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private readonly INavigationService _nav;
    private readonly IAuthenticator _auth;
    private readonly IFalconClient _falcon;

    [ObservableProperty] private UserControl? _currentView;
    [ObservableProperty] private string _userDisplay = "Não autenticado";
    [ObservableProperty] private string _statusText = "Pronto.";
    [ObservableProperty] private string _entraStatus = "Offline";
    [ObservableProperty] private Brush _entraStatusColor = Brushes.OrangeRed;
    [ObservableProperty] private string _falconStatus = "Desconhecido";
    [ObservableProperty] private Brush _falconStatusColor = Brushes.OrangeRed;

    public MainViewModel(INavigationService nav, IAuthenticator auth, IFalconClient falcon)
    {
        _nav = nav;
        _auth = auth;
        _falcon = falcon;
        _nav.CurrentViewChanged += (_, _) => CurrentView = _nav.CurrentView;
    }

    public async Task InitializeAsync()
    {
        _nav.NavigateTo("login");
        var silent = await _auth.SignInSilentAsync().ConfigureAwait(true);
        if (silent.IsSuccess)
        {
            UserDisplay = silent.Value!.DisplayName;
            EntraStatus = "Conectado"; EntraStatusColor = Brushes.LimeGreen;
            await ProbeFalconAsync().ConfigureAwait(true);
            _nav.NavigateTo("dashboard");
        }
    }

    [RelayCommand]
    private void Nav(string viewKey) => _nav.NavigateTo(viewKey);

    [RelayCommand]
    private async Task SignOut()
    {
        await _auth.SignOutAsync().ConfigureAwait(true);
        UserDisplay = "Não autenticado";
        EntraStatus = "Offline"; EntraStatusColor = Brushes.OrangeRed;
        FalconStatus = "—"; FalconStatusColor = Brushes.OrangeRed;
        _nav.NavigateTo("login");
    }

    public async Task OnSignedInAsync(string display)
    {
        UserDisplay = display;
        EntraStatus = "Conectado"; EntraStatusColor = Brushes.LimeGreen;
        await ProbeFalconAsync().ConfigureAwait(true);
        _nav.NavigateTo("dashboard");
    }

    private async Task ProbeFalconAsync()
    {
        StatusText = "Detectando módulos Falcon licenciados…";
        var probe = await _falcon.ProbeCapabilitiesAsync().ConfigureAwait(true);
        if (probe.IsSuccess)
        {
            FalconStatus = $"OK ({probe.Value!.CloudRegion})";
            FalconStatusColor = Brushes.LimeGreen;
            StatusText = $"Módulos licenciados: {string.Join(", ", probe.Value!.Licensed)}";
        }
        else
        {
            FalconStatus = probe.Error!.CodeString;
            FalconStatusColor = Brushes.OrangeRed;
            StatusText = $"Falcon indisponível: {probe.Error}";
        }
    }
}
