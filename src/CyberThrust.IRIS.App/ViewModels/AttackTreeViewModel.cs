using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Graph;

namespace CyberThrust.IRIS.App.ViewModels;

/// <summary>
/// Árvore de Ataque — visualização Cytoscape do passo-a-passo de uma detecção:
/// parent process → process → user → host → C2 endpoint → domain referenced.
/// Lê o contexto de investigação (AlertInvestigationContext) e constrói o grafo
/// a partir dos IOCs do alerta selecionado em Detecções.
/// </summary>
public partial class AttackTreeViewModel : ViewModelBase
{
    private readonly IGraphProvider _graphProvider;
    private readonly INavigationService _nav;
    private readonly AlertInvestigationContext _ctx;

    [ObservableProperty] private string? _graphJson;
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string  _title          = "Árvore de Ataque";
    [ObservableProperty] private string  _subtitle       = "Selecione uma detecção em Detecções (Ctrl+A) e clique \"Árvore de Ataque\" no menu de contexto.";
    [ObservableProperty] private bool    _hasGraph;
    [ObservableProperty] private string  _alertContext   = string.Empty;

    public AttackTreeViewModel(IGraphProvider graph, INavigationService nav, AlertInvestigationContext ctx)
    {
        _graphProvider = graph;
        _nav           = nav;
        _ctx           = ctx;
        _ = ReloadCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private async Task Reload()
    {
        IsBusy = true; BusyMessage = "Construindo grafo de ataque…"; ErrorMessage = null; HasGraph = false;
        try
        {
            // 1. Se há contexto de investigação ativo, constrói grafo específico do alerta
            if (_ctx.HasContext && _ctx.Alert is not null)
            {
                var graph = BuildAlertGraph(_ctx.Alert);
                GraphJson = AttackGraphBuilder.ToCytoscapeJson(graph);
                HasGraph  = graph.Nodes.Count > 0;
                Title     = $"Cadeia de Ataque — {_ctx.Alert.Name}";
                Subtitle  = $"Host: {_ctx.Hostname ?? "—"}   ·   Tactic: {_ctx.Alert.Tactic}   ·   Technique: {_ctx.Alert.Technique}";
                AlertContext = $"Severidade: {_ctx.Alert.Severity} · Created: {_ctx.Alert.CreatedUtc.ToLocalTime():dd/MM HH:mm:ss}";
                return;
            }

            // 2. Sem contexto: fallback para grafo "live" agregado do provider
            var r = await _graphProvider.BuildAttackGraphAsync(incidentId: "live").ConfigureAwait(true);
            if (r.IsFailure)
            {
                ErrorMessage = r.Error!.ToString();
                return;
            }
            GraphJson = AttackGraphBuilder.ToCytoscapeJson(r.Value!);
            HasGraph  = r.Value!.Nodes.Count > 0;
            Title     = "Árvore de Ataque — Visão Agregada";
            Subtitle  = "Sem alerta selecionado. Mostrando grafo agregado dos últimos incidentes.";
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand] private void BackToAlerts() => _nav.NavigateTo("alerts");

    /// <summary>Constrói o grafo a partir do alerta selecionado, conectando os IOCs em sequência:
    /// (User) → (Host) → (Parent Process) → (Process) → (Network Endpoint) → (Domain).
    /// Cada nó tem metadata com cmdline, hash, IP completo etc. para tooltip no Cytoscape.</summary>
    private static AttackGraph BuildAlertGraph(FalconAlert alert)
    {
        var nodes = new List<AttackNode>();
        var edges = new List<AttackEdge>();
        var x = alert.Extra ?? new Dictionary<string, string>();
        var t = alert.CreatedUtc;

        // Node IDs (cada um único)
        string? userId = null, hostId = null, parentId = null, procId = null, fileId = null, ipId = null, domainId = null, urlId = null, alertId;

        alertId = "alert:" + alert.CompositeId;
        nodes.Add(new AttackNode(alertId, NodeKind.Detection, alert.Name, alert.Severity,
            new Dictionary<string, string>
            {
                ["Composite ID"] = alert.CompositeId,
                ["Tactic"]       = alert.Tactic,
                ["Technique"]    = alert.Technique,
                ["Technique ID"] = alert.TechniqueId,
                ["Status"]       = alert.Status,
                ["Description"]  = alert.Description
            }));

        // User
        if (!string.IsNullOrWhiteSpace(alert.UserName))
        {
            userId = "user:" + alert.UserName;
            nodes.Add(new AttackNode(userId, NodeKind.User, alert.UserName, Severity.Informational,
                new Dictionary<string, string>
                {
                    ["Username"] = alert.UserName,
                    ["Domain"]   = x.GetValueOrDefault("logon_domain") ?? "",
                    ["UPN"]      = x.GetValueOrDefault("user_principal") ?? ""
                }));
        }

        // Host
        if (!string.IsNullOrWhiteSpace(alert.Hostname) || !string.IsNullOrWhiteSpace(alert.Aid))
        {
            hostId = "host:" + (alert.Aid ?? alert.Hostname);
            nodes.Add(new AttackNode(hostId, NodeKind.Host, alert.Hostname ?? "host", alert.Severity,
                new Dictionary<string, string>
                {
                    ["Hostname"]    = alert.Hostname ?? "",
                    ["AID"]         = alert.Aid ?? "",
                    ["Local IP"]    = x.GetValueOrDefault("local_ip") ?? "",
                    ["External IP"] = x.GetValueOrDefault("external_ip") ?? "",
                    ["OS"]          = x.GetValueOrDefault("device_os") ?? ""
                }));
            if (userId is not null)
                edges.Add(new AttackEdge(userId, hostId, "logged_on", t,
                    new Dictionary<string, string> { ["timestamp"] = t.ToString("HH:mm:ss") }));
        }

        // Parent process
        var parentImage = x.GetValueOrDefault("parent_image");
        var parentCmd   = x.GetValueOrDefault("parent_cmdline");
        if (!string.IsNullOrWhiteSpace(parentImage))
        {
            parentId = "parent:" + parentImage;
            nodes.Add(new AttackNode(parentId, NodeKind.Process, parentImage, Severity.Informational,
                new Dictionary<string, string>
                {
                    ["Image"]    = parentImage,
                    ["Cmdline"]  = parentCmd ?? "",
                    ["Role"]     = "Parent"
                }));
            if (hostId is not null)
                edges.Add(new AttackEdge(hostId, parentId, "executed", t,
                    new Dictionary<string, string> { ["timestamp"] = t.ToString("HH:mm:ss") }));
        }

        // Process que disparou o alerta
        var procImage = x.GetValueOrDefault("filename") ?? x.GetValueOrDefault("filepath");
        var procCmd   = x.GetValueOrDefault("cmdline") ?? x.GetValueOrDefault("commandline");
        if (!string.IsNullOrWhiteSpace(procImage))
        {
            procId = "proc:" + procImage;
            nodes.Add(new AttackNode(procId, NodeKind.Process, procImage, alert.Severity,
                new Dictionary<string, string>
                {
                    ["Image"]    = procImage,
                    ["Cmdline"]  = procCmd ?? "",
                    ["Path"]     = x.GetValueOrDefault("filepath") ?? "",
                    ["PID"]      = x.GetValueOrDefault("process_id") ?? "",
                    ["Role"]     = "Child / Suspect"
                }));
            edges.Add(new AttackEdge(parentId ?? hostId ?? alertId, procId, "spawned", t,
                new Dictionary<string, string> { ["cmdline"] = procCmd ?? "" }));
        }

        // File hash
        var sha = x.GetValueOrDefault("sha256");
        if (!string.IsNullOrWhiteSpace(sha))
        {
            fileId = "hash:" + sha;
            nodes.Add(new AttackNode(fileId, NodeKind.File, "SHA256: " + sha[..Math.Min(16, sha.Length)] + "…", alert.Severity,
                new Dictionary<string, string>
                {
                    ["SHA256"]   = sha,
                    ["MD5"]      = x.GetValueOrDefault("md5") ?? "",
                    ["Filename"] = x.GetValueOrDefault("filename") ?? ""
                }));
            if (procId is not null)
                edges.Add(new AttackEdge(procId, fileId, "loaded", t, null));
        }

        // Network endpoint
        var extIp = x.GetValueOrDefault("ip_address") ?? x.GetValueOrDefault("external_ip");
        if (!string.IsNullOrWhiteSpace(extIp))
        {
            ipId = "ip:" + extIp;
            nodes.Add(new AttackNode(ipId, NodeKind.NetworkEndpoint, extIp, alert.Severity,
                new Dictionary<string, string> { ["IP"] = extIp }));
            if (procId is not null)
                edges.Add(new AttackEdge(procId, ipId, "connected_to", t, null));
        }

        // Domain
        var dom = x.GetValueOrDefault("domain");
        if (!string.IsNullOrWhiteSpace(dom))
        {
            domainId = "domain:" + dom;
            nodes.Add(new AttackNode(domainId, NodeKind.NetworkEndpoint, dom, alert.Severity,
                new Dictionary<string, string> { ["Domain"] = dom }));
            edges.Add(new AttackEdge(procId ?? hostId ?? alertId, domainId, "resolved", t, null));
        }

        // URL
        var url = x.GetValueOrDefault("url");
        if (!string.IsNullOrWhiteSpace(url))
        {
            urlId = "url:" + url;
            nodes.Add(new AttackNode(urlId, NodeKind.NetworkEndpoint, url, alert.Severity,
                new Dictionary<string, string> { ["URL"] = url }));
            edges.Add(new AttackEdge(procId ?? hostId ?? alertId, urlId, "accessed", t, null));
        }

        // Conecta o alerta ao processo suspeito
        if (procId is not null)
            edges.Add(new AttackEdge(procId, alertId, "triggered", t,
                new Dictionary<string, string>
                {
                    ["Tactic"]    = alert.Tactic,
                    ["Technique"] = alert.Technique
                }));
        else if (hostId is not null)
            edges.Add(new AttackEdge(hostId, alertId, "triggered", t, null));

        return new AttackGraph(IncidentId: alert.CompositeId, Nodes: nodes, Edges: edges);
    }
}
