using System.IO;
using System.Windows.Controls;
using CyberThrust.IRIS.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace CyberThrust.IRIS.App.Views;

public partial class AttackTreeView : UserControl
{
    private AttackTreeViewModel? _vm;

    public AttackTreeView()
    {
        InitializeComponent();
        _vm = App.Services.GetRequiredService<AttackTreeViewModel>();
        DataContext = _vm;
        Loaded += async (_, _) =>
        {
            await Browser.EnsureCoreWebView2Async();
            var html = Path.Combine(AppContext.BaseDirectory, "WebAssets", "graph", "attack-graph.html");
            if (File.Exists(html))
            {
                Browser.CoreWebView2.Navigate(new Uri(html).AbsoluteUri);
                _vm.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(AttackTreeViewModel.GraphJson) && !string.IsNullOrEmpty(_vm.GraphJson))
                        Browser.CoreWebView2.ExecuteScriptAsync($"window.loadGraph({_vm.GraphJson});");
                };
            }
        };
    }
}
