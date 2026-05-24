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
    private readonly AppConfigStore _cfg;

    [ObservableProperty] private UserControl? _currentView;
    [ObservableProperty] private string _userDisplay = "Operador anônimo";
    [ObservableProperty] private string _statusText = "Centro de operações pronto.";
    [ObservableProperty] private string _entraStatus = "Não configurado";
    [ObservableProperty] private Brush _entraStatusColor = Brushes.Gold;
    [ObservableProperty] private string _falconStatus = "Não configurado";
    [ObservableProperty] private Brush _falconStatusColor = Brushes.Gold;
    [ObservableProperty] private bool _showSignInButton = false;

    public MainViewModel(INavigationService nav, IAuthenticator auth, IFalconClient falcon, AppConfigStore cfg)
    {
        _nav = nav;
        _auth = auth;
        _falcon = falcon;
        _cfg = cfg;
        _nav.CurrentViewChanged += (_, _) => CurrentView = _nav.CurrentView;
    }

    public async Task InitializeAsync()
    {
        // v0.3.2+: tela inicial é Welcome (SOC Operations Center).
        // Login só é solicitado se o usuário clicar — não é mais obrigatório no arranque.
        Serilog.Log.Information("MainViewModel.InitializeAsync → navigateTo(home)");
        _nav.NavigateTo("home");

        // Status bar reflete configuração atual
        UpdateStatusFromConfig();
        await Task.CompletedTask;
    }

    private void UpdateStatusFromConfig()
    {
        var snap = _cfg.Load();
        var entraOk = !string.IsNullOrWhiteSpace(snap.EntraId.ClientId) && !snap.EntraId.ClientId.StartsWith("00000000");
        var falconOk = !string.IsNullOrWhiteSpace(snap.Falcon.ClientId) && !string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret);

        EntraStatus = entraOk ? "Configurado" : "Não configurado";
        EntraStatusColor = entraOk ? Brushes.LimeGreen : Brushes.Gold;

        FalconStatus = falconOk ? $"Configurado ({snap.Falcon.Cloud})" : "Não configurado";
        FalconStatusColor = falconOk ? Brushes.LimeGreen : Brushes.Gold;

        ShowSignInButton = entraOk;
        StatusText = entraOk && falconOk
            ? "Pronto. Centro de operações conectado."
            : "Pronto. Configure as integrações em Configurações (Ctrl+8).";
    }

    /// <summary>Chamado após login bem-sucedido para tentar uma re-autenticação silenciosa em sessões futuras.</summary>
    public async Task TrySilentAsync()
    {
        try
        {
            var silent = await _auth.SignInSilentAsync().ConfigureAwait(true);
            if (silent.IsSuccess)
            {
                UserDisplay = silent.Value!.DisplayName;
                EntraStatus = "Conectado"; EntraStatusColor = Brushes.LimeGreen;
                await ProbeFalconAsync().ConfigureAwait(true);
            }
        }
        catch { /* silencioso — usuário precisa fazer login manual */ }
    }

    [RelayCommand]
    private void Nav(string viewKey) => _nav.NavigateTo(viewKey);

    [RelayCommand]
    private async Task Refresh()
    {
        UpdateStatusFromConfig();
        await ProbeFalconAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task SignOut()
    {
        await _auth.SignOutAsync().ConfigureAwait(true);
        UserDisplay = "Operador anônimo";
        UpdateStatusFromConfig();
        _nav.NavigateTo("home");
    }

    [RelayCommand]
    private void SignIn() => _nav.NavigateTo("login");

    public async Task OnSignedInAsync(string display)
    {
        UserDisplay = display;
        EntraStatus = "Conectado"; EntraStatusColor = Brushes.LimeGreen;
        await ProbeFalconAsync().ConfigureAwait(true);
        _nav.NavigateTo("dashboard");
    }

    private async Task ProbeFalconAsync()
    {
        var snap = _cfg.Load();
        if (string.IsNullOrWhiteSpace(snap.Falcon.ClientId) || string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret))
            return;

        StatusText = "Detectando módulos Falcon licenciados…";
        var probe = await _falcon.ProbeCapabilitiesAsync().ConfigureAwait(true);
        if (probe.IsSuccess)
        {
            FalconStatus = $"Conectado ({probe.Value!.CloudRegion})";
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
