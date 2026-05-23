using System.Windows;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try
            {
                var vm = App.Services.GetRequiredService<MainViewModel>();
                DataContext = vm;
                await vm.InitializeAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Falha ao iniciar shell.\n\n{ex.Message}", "CyberThrust.IRIS", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        };
    }
}
