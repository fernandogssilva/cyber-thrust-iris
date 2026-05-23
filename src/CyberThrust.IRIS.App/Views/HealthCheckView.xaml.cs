using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class HealthCheckView : UserControl
{
    public HealthCheckView()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<HealthCheckViewModel>();
    }
}
