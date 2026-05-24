using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class SettingsView : UserControl
{
    private SettingsViewModel? _vm;

    public SettingsView()
    {
        InitializeComponent();
        _vm = App.Services.GetRequiredService<SettingsViewModel>();
        DataContext = _vm;
        // Carrega o secret no PasswordBox manualmente (não pode bindar PasswordBox.Password)
        FalconSecretBox.Password = _vm.FalconClientSecret;
    }

    private void FalconSecretBox_PasswordChanged(object sender, System.Windows.RoutedEventArgs e)
    {
        if (_vm is not null && sender is PasswordBox pb)
            _vm.FalconClientSecret = pb.Password;
    }
}
