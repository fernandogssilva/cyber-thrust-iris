using System.Windows.Controls;
namespace CyberThrust.IRIS.App.Views;
public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        ConfigPath.Text = AppContext.BaseDirectory;
    }
}
