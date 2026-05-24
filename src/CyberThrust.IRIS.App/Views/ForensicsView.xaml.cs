using System.Collections.Specialized;
using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class ForensicsView : UserControl
{
    public ForensicsView()
    {
        InitializeComponent();
        var vm = App.Services.GetRequiredService<ForensicsViewModel>();
        DataContext = vm;
        vm.Terminal.CollectionChanged += Terminal_CollectionChanged;
    }

    private void Terminal_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
            () => TerminalScroll.ScrollToBottom());
    }
}
