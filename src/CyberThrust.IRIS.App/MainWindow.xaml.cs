using System.Windows;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace CyberThrust.IRIS.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        Log.Debug("MainWindow ctor begin");
        InitializeComponent();
        Log.Debug("MainWindow ctor end (InitializeComponent ok)");
        Loaded += async (_, _) =>
        {
            Log.Information("MainWindow Loaded — resolvendo MainViewModel");
            try
            {
                var vm = App.Services.GetRequiredService<MainViewModel>();
                DataContext = vm;
                Log.Information("MainViewModel atribuído ao DataContext, chamando InitializeAsync");
                await vm.InitializeAsync();
                Log.Information("MainViewModel.InitializeAsync completo");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Falha em MainWindow.Loaded");
                MessageBox.Show($"Falha ao iniciar shell.\n\n[IRIS-UI-6003] {ex.GetType().Name}: {ex.Message}", "CyberThrust.IRIS", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        };
    }
}
