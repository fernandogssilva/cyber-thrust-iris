using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class CtiView : UserControl
{
    public CtiView()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<CtiViewModel>();
    }
}
