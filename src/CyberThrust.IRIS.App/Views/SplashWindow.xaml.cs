using System.Windows;
using CyberThrust.IRIS.App.Services;

namespace CyberThrust.IRIS.App.Views;

public partial class SplashWindow : Window
{
    public SplashWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => DwmDarkTitleBar.Apply(this);
    }

    public void Report(string message)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => Status.Text = message); return; }
        Status.Text = message;
    }
}
