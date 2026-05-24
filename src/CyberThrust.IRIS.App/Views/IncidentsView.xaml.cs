using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class IncidentsView : UserControl
{
    public IncidentsView()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<IncidentsViewModel>();
    }
}
