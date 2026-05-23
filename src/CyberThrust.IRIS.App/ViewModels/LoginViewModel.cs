using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.Core.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class LoginViewModel : ViewModelBase
{
    private readonly IAuthenticator _auth;
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string? _errorCode;

    public LoginViewModel(IAuthenticator auth) => _auth = auth;

    [RelayCommand]
    private async Task SignIn()
    {
        IsBusy = true;
        BusyMessage = "Abrindo Microsoft Entra ID…";
        ErrorMessage = null;
        ErrorCode = null;
        try
        {
            var r = await _auth.SignInInteractiveAsync().ConfigureAwait(true);
            if (r.IsFailure)
            {
                ErrorCode = r.Error!.CodeString;
                ErrorMessage = r.Error!.Message;
                return;
            }
            var main = App.Services.GetRequiredService<MainViewModel>();
            await main.OnSignedInAsync(r.Value!.DisplayName).ConfigureAwait(true);
        }
        finally
        {
            IsBusy = false;
        }
    }
}
