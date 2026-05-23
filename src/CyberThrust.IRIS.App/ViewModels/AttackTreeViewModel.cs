using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Graph;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class AttackTreeViewModel : ViewModelBase
{
    private readonly IGraphProvider _graph;
    [ObservableProperty] private string? _graphJson;
    [ObservableProperty] private string? _errorMessage;

    public AttackTreeViewModel(IGraphProvider graph)
    {
        _graph = graph;
        _ = ReloadCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private async Task Reload()
    {
        IsBusy = true; BusyMessage = "Construindo grafo de ataque…"; ErrorMessage = null;
        try
        {
            var r = await _graph.BuildAttackGraphAsync(incidentId: "live").ConfigureAwait(true);
            if (r.IsFailure) { ErrorMessage = r.Error!.ToString(); return; }
            GraphJson = AttackGraphBuilder.ToCytoscapeJson(r.Value!);
        }
        finally
        {
            IsBusy = false;
        }
    }
}
