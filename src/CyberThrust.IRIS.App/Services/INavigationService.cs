using System.Windows.Controls;

namespace CyberThrust.IRIS.App.Services;

public interface INavigationService
{
    UserControl? CurrentView { get; }
    event EventHandler? CurrentViewChanged;
    void NavigateTo(string viewKey);
}

public sealed class NavigationService : INavigationService
{
    private UserControl? _current;
    public UserControl? CurrentView
    {
        get => _current;
        private set
        {
            _current = value;
            CurrentViewChanged?.Invoke(this, EventArgs.Empty);
        }
    }
    public event EventHandler? CurrentViewChanged;

    public void NavigateTo(string viewKey)
    {
        CurrentView = viewKey switch
        {
            "home" or "welcome" => Resolve<Views.WelcomeView>(),
            "dashboard" => Resolve<Views.DashboardView>(),
            "incidents" => Resolve<Views.IncidentsView>(),
            "alerts" or "detections" => Resolve<Views.AlertsView>(),
            "rtr" => Resolve<Views.RtrConsoleView>(),
            "forensics" => Resolve<Views.ForensicsView>(),
            "memory" => Resolve<Views.MemoryView>(),
            "graph" or "attacktree" or "attack-tree" or "ataque" => Resolve<Views.AttackTreeView>(),
            "health" => Resolve<Views.HealthCheckView>(),
            "settings" => Resolve<Views.SettingsView>(),
            "reputation" => Resolve<Views.ReputationView>(),
            "cti" => Resolve<Views.CtiView>(),
            "login" => Resolve<Views.LoginView>(),
            _ => CurrentView
        };
    }

    private static UserControl Resolve<T>() where T : UserControl, new() => new T();
}
