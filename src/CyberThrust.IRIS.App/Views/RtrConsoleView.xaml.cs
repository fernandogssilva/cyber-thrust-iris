using System.Collections.Specialized;
using System.Windows.Controls;
using System.Windows.Input;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class RtrConsoleView : UserControl
{
    public RtrConsoleView()
    {
        InitializeComponent();

        // Resolve VM from DI (same pattern as all other views in this project)
        var vm = App.Services.GetRequiredService<RtrConsoleViewModel>();
        DataContext = vm;

        // Auto-scroll terminal output whenever a new line is appended
        vm.Terminal.CollectionChanged += Terminal_CollectionChanged;

        // Allow Enter key to execute the current command
        CmdInput.KeyDown += CmdInput_KeyDown;
    }

    private void Terminal_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        // Run on Dispatcher so the layout has already updated before we scroll
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
        {
            TerminalScroll.ScrollToBottom();
        });
    }

    private void CmdInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && DataContext is RtrConsoleViewModel vm && vm.SendCommand.CanExecute(null))
        {
            vm.SendCommand.Execute(null);
            e.Handled = true;
        }
    }
}
