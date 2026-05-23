using System.Text.Json;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.Graph;

/// <summary>
/// Constrói o grafo de ataque IOC → User → Host → Process → Network → Lateral Movement.
/// O resultado é entregue como JSON pronto para Cytoscape.js (hospedado no WebView2).
/// </summary>
public sealed class AttackGraphBuilder : IGraphProvider
{
    private readonly IFalconClient _falcon;
    private readonly ILogger<AttackGraphBuilder> _log;

    public AttackGraphBuilder(IFalconClient falcon, ILogger<AttackGraphBuilder> log)
    {
        _falcon = falcon;
        _log = log;
    }

    public async Task<Result<AttackGraph>> BuildAttackGraphAsync(string incidentId, CancellationToken ct = default)
    {
        try
        {
            // MVP: usa detections recentes como base. Próxima iteração: incident-API + LogScale.
            var det = await _falcon.ListRecentDetectionsAsync(50, ct).ConfigureAwait(false);
            if (det.IsFailure) return Result<AttackGraph>.Fail(det.Error!);

            var nodes = new List<AttackNode>();
            var edges = new List<AttackEdge>();
            foreach (var d in det.Value!)
            {
                var iocId = $"ioc:{d.DetectionId}";
                var hostId = $"host:{d.Aid}";
                nodes.Add(new AttackNode(iocId, NodeKind.Detection, d.Description, d.Severity, new Dictionary<string, string> { ["tactic"] = d.Tactic, ["technique"] = d.Technique }));
                if (nodes.All(n => n.Id != hostId))
                    nodes.Add(new AttackNode(hostId, NodeKind.Host, d.Hostname, d.Severity, new Dictionary<string, string> { ["aid"] = d.Aid }));
                edges.Add(new AttackEdge(iocId, hostId, "observed-on", d.TimestampUtc, null));
            }

            return Result<AttackGraph>.Ok(new AttackGraph(incidentId, nodes, edges));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Falha ao construir attack graph.");
            return Result<AttackGraph>.Fail(IrisErrorCode.SysUnknown, ex.Message, ex);
        }
    }

    public Task<Result<AttackGraph>> BuildLateralMovementGraphAsync(string aid, TimeSpan lookback, CancellationToken ct = default)
    {
        // Placeholder: requer Identity Protection + LogScale. Por enquanto retorna grafo vazio para a UI saber renderizar "no data".
        return Task.FromResult(Result<AttackGraph>.Ok(new AttackGraph($"lateral:{aid}", Array.Empty<AttackNode>(), Array.Empty<AttackEdge>())));
    }

    /// <summary>Serializa o grafo no formato Cytoscape.js esperado pelo HTML embarcado.</summary>
    public static string ToCytoscapeJson(AttackGraph g)
    {
        var elements = new List<object>();
        foreach (var n in g.Nodes)
        {
            elements.Add(new
            {
                data = new { id = n.Id, label = n.Label, kind = n.Kind.ToString(), severity = n.Severity.ToString() }
            });
        }
        foreach (var e in g.Edges)
        {
            elements.Add(new
            {
                data = new { id = $"{e.Source}->{e.Target}", source = e.Source, target = e.Target, label = e.Relationship }
            });
        }
        return JsonSerializer.Serialize(new { elements }, new JsonSerializerOptions { WriteIndented = false });
    }
}
