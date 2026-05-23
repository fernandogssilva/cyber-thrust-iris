using System.Windows;

namespace CyberThrust.IRIS.App.Views;

public partial class SplashWindow : Window
{
    public SplashWindow() => InitializeComponent();
    public void Report(string message)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => Status.Text = message); return; }
        Status.Text = message;
    }
}
