using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class AlertsView : UserControl
{
    public AlertsView()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<AlertsViewModel>();
    }
}
