using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class WelcomeView : UserControl
{
    public WelcomeView()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<WelcomeViewModel>();
    }
}
