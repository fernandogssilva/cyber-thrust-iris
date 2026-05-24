using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

/// <summary>
/// Detecções unificadas — layout Next-Gen SIEM + painel lateral de investigação.
/// Clicar em qualquer linha abre o painel com todos os campos do alerta e as
/// ações de resposta: Conter Host, RTR, Velociraptor, atualizar status, encaminhar incidente.
/// </summary>
public partial class AlertsViewModel : ViewModelBase
{
    private readonly IFalconClient _falcon;
    private readonly INavigationService _nav;
    private readonly AppConfigStore _cfg;
    private readonly AlertInvestigationContext _context;
    private readonly IpIntelService _ipIntel;
    private readonly ArtifactReputationClient _rep;

    public ObservableCollection<AlertRowVm> Alerts { get; } = new();
    public ICollectionView AlertsView { get; }

    // ─── Filtros ──────────────────────────────────────────────────────────────
    public ObservableCollection<string> ProductOptions  { get; } = new(new[] { "(Todos)", "epp", "idp", "ngsiem", "mobile", "cloud", "overwatch", "xdr" });
    public ObservableCollection<string> SeverityOptions { get; } = new(new[] { "(Todas)", "Critical", "High", "Medium", "Low", "Informational" });
    public ObservableCollection<string> StatusOptions   { get; } = new(new[] { "(Todos)", "new", "in_progress", "true_positive", "false_positive", "ignored", "closed" });
    public ObservableCollection<string> TimeOptions     { get; } = new(new[] { "Última 1 hora", "Últimas 24 horas", "Últimos 7 dias", "Últimos 30 dias", "Últimos 90 dias", "Tudo" });

    [ObservableProperty] private string _selectedProduct  = "(Todos)";
    [ObservableProperty] private string _selectedSeverity = "(Todas)";
    [ObservableProperty] private string _selectedStatus   = "(Todos)";
    [ObservableProperty] private string _selectedTime     = "Últimas 24 horas";
    [ObservableProperty] private string _searchText       = string.Empty;

    [ObservableProperty] private int    _totalCount;
    [ObservableProperty] private string _resultsLabel  = "0 resultados";
    [ObservableProperty] private string _statusLine    = "Pronto.";
    [ObservableProperty] private bool   _showConfigBanner;
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private bool   _hasError;

    // ─── Painel de detalhes + IR ──────────────────────────────────────────────
    [ObservableProperty] private AlertRowVm? _selectedAlertRow;
    [ObservableProperty] private bool   _hasSelectedAlert;
    [ObservableProperty] private bool   _isActionBusy;
    [ObservableProperty] private string _actionMessage = string.Empty;
    [ObservableProperty] private bool   _actionIsSuccess;
    [ObservableProperty] private Brush  _actionMessageColor = Brushes.Transparent;

    // ─── Investigação enriquecida ────────────────────────────────────────────
    [ObservableProperty] private DeviceProfile? _deviceProfile;
    [ObservableProperty] private bool _isEnriching;
    [ObservableProperty] private string _enrichmentStatus = string.Empty;
    public ObservableCollection<RelatedAlert> RelatedAlerts { get; } = new();
    public ObservableCollection<IocChip>      Iocs          { get; } = new();
    public ObservableCollection<IpIntelCard>  IpCards       { get; } = new();
    [ObservableProperty] private bool _hasDeviceProfile;
    [ObservableProperty] private bool _hasRelatedAlerts;
    [ObservableProperty] private bool _hasIocs;
    [ObservableProperty] private bool _hasIpCards;

    public AlertsViewModel(IFalconClient falcon, INavigationService nav, AppConfigStore cfg, AlertInvestigationContext context, IpIntelService ipIntel, ArtifactReputationClient rep)
    {
        _falcon  = falcon;
        _nav     = nav;
        _cfg     = cfg;
        _context = context;
        _ipIntel = ipIntel;
        _rep     = rep;
        AlertsView = CollectionViewSource.GetDefaultView(Alerts);
        AlertsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(AlertRowVm.DateGroup)));
        _ = LoadCommand.ExecuteAsync(null);
    }

    partial void OnSelectedAlertRowChanged(AlertRowVm? value)
    {
        HasSelectedAlert      = value is not null;
        ActionMessage         = string.Empty;
        ActionIsSuccess       = false;
        ActionMessageColor    = Brushes.Transparent;

        DeviceProfile      = null;
        HasDeviceProfile   = false;
        RelatedAlerts.Clear(); HasRelatedAlerts = false;
        Iocs.Clear();          HasIocs          = false;
        IpCards.Clear();       HasIpCards       = false;

        if (value is not null)
            _ = EnrichAsync(value);
    }

    // ─── Enrichment automático — device + alertas relacionados + IOCs + IP intel ────────
    private async Task EnrichAsync(AlertRowVm row)
    {
        // 1. IOCs do dict Extra (extraídos pelo FalconClient.ListAlertsAsync)
        BuildIocChips(row.Alert);

        // 2. IP intel + reputation (qualquer IP que apareça no Extra ou em DeviceProfile)
        _ = EnrichIpsAsync(row.Alert);

        var aid = row.Alert.Aid;
        if (string.IsNullOrWhiteSpace(aid)) return; // IDP/NG-SIEM podem não ter AID

        IsEnriching      = true;
        EnrichmentStatus = "Enriquecendo: device profile + alertas correlacionados…";

        try
        {
            // Em paralelo: device profile + related alerts (24h, mesmo AID)
            var deviceTask = _falcon.GetDeviceProfileAsync(aid);
            var relatedTask = _falcon.ListAlertsAsync(new FalconAlertsFilter(
                LookBack: TimeSpan.FromHours(24),
                Aid: aid,
                Limit: 50));

            await Task.WhenAll(deviceTask, relatedTask).ConfigureAwait(true);

            if (deviceTask.Result.IsSuccess)
            {
                DeviceProfile    = deviceTask.Result.Value;
                HasDeviceProfile = DeviceProfile is not null;
            }
            if (relatedTask.Result.IsSuccess)
            {
                foreach (var a in relatedTask.Result.Value!.Where(x => x.CompositeId != row.Alert.CompositeId).Take(20))
                {
                    RelatedAlerts.Add(new RelatedAlert(
                        a.CompositeId, a.Name, a.Severity, a.Status,
                        a.Tactic, a.Technique, a.CreatedUtc));
                }
                HasRelatedAlerts = RelatedAlerts.Count > 0;
            }
            EnrichmentStatus = $"✓ {(HasDeviceProfile ? "device" : "device falhou")} · {RelatedAlerts.Count} correlacionados · {Iocs.Count} IOCs";
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Enrichment falhou para AID {Aid}", aid);
            EnrichmentStatus = "Falha no enriquecimento (logs).";
        }
        finally
        {
            IsEnriching = false;
        }
    }

    // ─── Enriquece IPs com geo/ISP (ip-api.com) + reputação (VT/MalwareBazaar/ThreatFox) ─
    private async Task EnrichIpsAsync(FalconAlert alert)
    {
        if (alert.Extra is null) return;
        var ipKeys = new[] { "local_ip", "external_ip", "ip_address" };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ipsToLookup = new List<(string label, string ip)>();
        foreach (var k in ipKeys)
        {
            if (alert.Extra.TryGetValue(k, out var ip) && !string.IsNullOrWhiteSpace(ip) && seen.Add(ip))
            {
                var label = k switch
                {
                    "local_ip"     => "IP local (origem)",
                    "external_ip"  => "IP externo (origem)",
                    "ip_address"   => "IP do evento",
                    _              => k
                };
                ipsToLookup.Add((label, ip.Trim()));
            }
        }
        if (ipsToLookup.Count == 0) return;

        // Lookup geo+ISP em paralelo
        var lookupTasks = ipsToLookup.Select(x => (x.label, x.ip, task: _ipIntel.LookupAsync(x.ip))).ToList();
        await Task.WhenAll(lookupTasks.Select(t => t.task)).ConfigureAwait(true);

        foreach (var (label, ip, task) in lookupTasks)
        {
            var intel = task.Result;
            // Reputação em background (não bloqueia) — atualiza o card quando responder
            var card = new IpIntelCard(
                Label: label,
                Ip: ip,
                Country: intel.IsPrivate ? "RFC 1918" : intel.Country,
                CountryCode: intel.CountryCode,
                Region: intel.Region,
                City: intel.City,
                Isp: intel.Isp,
                Org: intel.Org,
                AsNumber: intel.AsNumber,
                IsPrivate: intel.IsPrivate,
                ReputationVerdict: intel.IsPrivate ? "—" : "consultando…",
                ReputationDetail: intel.IsPrivate ? "Rede interna — sem consulta externa" : null,
                MaliciousVotes: 0,
                TotalEngines: 0);
            IpCards.Add(card);
        }
        HasIpCards = IpCards.Count > 0;

        // Reputação async (não bloqueia UI inicial — atualiza chips no lugar)
        for (int i = 0; i < IpCards.Count; i++)
        {
            var idx = i;
            var c = IpCards[idx];
            if (c.IsPrivate) continue;
            try
            {
                var rep = await _rep.QueryAsync(c.Ip, ArtifactKind.IpAddress).ConfigureAwait(true);
                var firstSource = rep.Sources.FirstOrDefault();
                var detail = string.Join(" · ", rep.ThreatLabels.Take(3));
                if (string.IsNullOrWhiteSpace(detail) && firstSource is not null)
                    detail = $"{firstSource.Provider}: {firstSource.Detail ?? firstSource.Verdict.ToString()}";
                IpCards[idx] = c with
                {
                    ReputationVerdict = rep.Verdict.ToString(),
                    ReputationDetail  = detail,
                    MaliciousVotes    = rep.MaliciousCount ?? 0,
                    TotalEngines      = rep.TotalEngines ?? 0
                };
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Reputation IP lookup falhou: {Ip}", c.Ip);
            }
        }
    }

    private void BuildIocChips(FalconAlert alert)
    {
        Iocs.Clear();
        if (alert.Extra is null) { HasIocs = false; return; }
        void Add(string key, string label, string icon, string copyValue)
        {
            if (alert.Extra.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v))
                Iocs.Add(new IocChip(label, icon, v, copyValue));
        }
        Add("sha256",         "SHA256",          "🔐", alert.Extra["sha256"]);
        Add("md5",            "MD5",             "🔐", alert.Extra.TryGetValue("md5",  out var m)  ? m  : "");
        Add("filepath",       "Caminho",         "📁", alert.Extra.TryGetValue("filepath", out var fp) ? fp : "");
        Add("filename",       "Processo",        "⚙",  alert.Extra.TryGetValue("filename", out var fn) ? fn : "");
        Add("cmdline",        "Cmdline",         "💻", alert.Extra.TryGetValue("cmdline",  out var cl) ? cl : "");
        Add("parent_image",   "Parent",          "⬆",  alert.Extra.TryGetValue("parent_image", out var pi) ? pi : "");
        Add("parent_cmdline", "Parent cmd",      "⬆",  alert.Extra.TryGetValue("parent_cmdline", out var pc) ? pc : "");
        Add("local_ip",       "IP local",        "🌐", alert.Extra.TryGetValue("local_ip", out var li) ? li : "");
        Add("external_ip",    "IP externo",      "🌍", alert.Extra.TryGetValue("external_ip", out var ei) ? ei : "");
        Add("ip_address",     "IP",              "🌐", alert.Extra.TryGetValue("ip_address", out var ia) ? ia : "");
        Add("domain",         "Domínio",         "🌐", alert.Extra.TryGetValue("domain", out var dm) ? dm : "");
        Add("url",            "URL",             "🔗", alert.Extra.TryGetValue("url", out var url) ? url : "");
        HasIocs = Iocs.Count > 0;
    }

    partial void OnSearchTextChanged(string value) => AlertsView.Refresh();

    // ─── Carregar detecções ───────────────────────────────────────────────────
    [RelayCommand]
    private async Task Load()
    {
        IsBusy = true; BusyMessage = "Consultando /alerts/queries/alerts/v2…";
        HasError = false; LastError = null;
        var snap = _cfg.Load();
        ShowConfigBanner = string.IsNullOrWhiteSpace(snap.Falcon.ClientId) || string.IsNullOrWhiteSpace(snap.Falcon.ClientSecret);
        if (ShowConfigBanner) { IsBusy = false; StatusLine = "Falcon não configurado."; return; }

        try
        {
            var filter = new FalconAlertsFilter(
                Products: SelectedProduct == "(Todos)" ? null : new[] { SelectedProduct },
                MinSeverities: SelectedSeverity switch
                {
                    "Critical"      => new[] { Severity.Critical },
                    "High"          => new[] { Severity.High },
                    "Medium"        => new[] { Severity.Medium },
                    "Low"           => new[] { Severity.Low },
                    "Informational" => new[] { Severity.Informational },
                    _               => null
                },
                Statuses: SelectedStatus == "(Todos)" ? null : new[] { SelectedStatus },
                LookBack: SelectedTime switch
                {
                    "Última 1 hora"    => TimeSpan.FromHours(1),
                    "Últimas 24 horas" => TimeSpan.FromHours(24),
                    "Últimos 7 dias"   => TimeSpan.FromDays(7),
                    "Últimos 30 dias"  => TimeSpan.FromDays(30),
                    "Últimos 90 dias"  => TimeSpan.FromDays(90),
                    _                  => null
                },
                Limit: 1000);

            var r = await _falcon.ListAlertsAsync(filter).ConfigureAwait(true);
            if (r.IsFailure)
            {
                HasError = true; LastError = r.Error!.ToString(); StatusLine = "Falha na API."; return;
            }

            Alerts.Clear();
            foreach (var a in r.Value!) Alerts.Add(AlertRowVm.From(a));
            TotalCount    = Alerts.Count;
            ResultsLabel  = $"{Alerts.Count} resultados ({Alerts.Count} total)";
            AlertsView.Filter = obj => obj is AlertRowVm row && row.MatchesSearch(SearchText);

            var byProduct = Alerts
                .GroupBy(x => string.IsNullOrWhiteSpace(x.Alert.Product) ? "?" : x.Alert.Product)
                .OrderByDescending(g => g.Count())
                .Select(g => $"{g.Key}={g.Count()}");
            StatusLine = $"Atualizado às {DateTime.Now:HH:mm:ss} · {string.Join(" · ", byProduct)}";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Alerts.Load falhou");
            HasError = true; LastError = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ClearFilters()
    {
        SelectedProduct  = "(Todos)";
        SelectedSeverity = "(Todas)";
        SelectedStatus   = "(Todos)";
        SelectedTime     = "Últimas 24 horas";
        SearchText       = string.Empty;
    }

    [RelayCommand] private void GoToSettings() => _nav.NavigateTo("settings");

    // ─── Painel de detalhes — controle ───────────────────────────────────────
    [RelayCommand] private void CloseDetail() { SelectedAlertRow = null; }

    // ─── Ações de IR — Contenção de host ─────────────────────────────────────
    [RelayCommand]
    private async Task ContainHost()
    {
        var aid = SelectedAlertRow?.Alert.Aid;
        if (string.IsNullOrWhiteSpace(aid))
        {
            SetActionResult(false, "AID não disponível. Apenas alertas de Endpoint (EPP) têm agente Falcon associado.");
            return;
        }
        IsActionBusy = true;
        SetActionResult(false, "Isolando host via Network Containment…");
        var r = await _falcon.ContainHostAsync(aid).ConfigureAwait(true);
        IsActionBusy = false;
        SetActionResult(r.IsSuccess,
            r.IsSuccess
                ? $"✅  Host '{SelectedAlertRow?.SourceEndpoint}' isolado com sucesso. Tráfego de rede bloqueado."
                : $"❌  Falha ao isolar host: {r.Error}");
    }

    [RelayCommand]
    private async Task LiftContainment()
    {
        var aid = SelectedAlertRow?.Alert.Aid;
        if (string.IsNullOrWhiteSpace(aid))
        {
            SetActionResult(false, "AID não disponível para este alerta.");
            return;
        }
        IsActionBusy = true;
        SetActionResult(false, "Levantando contenção…");
        var r = await _falcon.LiftContainmentAsync(aid).ConfigureAwait(true);
        IsActionBusy = false;
        SetActionResult(r.IsSuccess,
            r.IsSuccess
                ? $"✅  Contenção levantada — '{SelectedAlertRow?.SourceEndpoint}' reintegrado à rede."
                : $"❌  Falha: {r.Error}");
    }

    // ─── Ações de IR — Navegar para ferramentas ───────────────────────────────
    [RelayCommand]
    private void OpenRtr()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        // Auto-pick script de investigação baseado nos IOCs disponíveis
        var ext = SelectedAlertRow.Alert.Extra ?? new Dictionary<string, string>();
        if (ext.ContainsKey("filename") || ext.ContainsKey("cmdline"))
            _context.PreferredRtrScriptId = "process-tree";
        else if (ext.ContainsKey("logon_domain") || !string.IsNullOrWhiteSpace(SelectedAlertRow.Alert.UserName))
            _context.PreferredRtrScriptId = "logon-history";
        else if (ext.ContainsKey("ip_address") || ext.ContainsKey("domain") || ext.ContainsKey("url"))
            _context.PreferredRtrScriptId = "connections";
        else
            _context.PreferredRtrScriptId = "sys-info";
        _nav.NavigateTo("rtr");
    }

    // ─── Context menu (right-click) — atalhos cross-módulo ────────────────────
    [RelayCommand]
    private void RtrInvestigateProcess(AlertRowVm? row)
    {
        row ??= SelectedAlertRow;
        if (row is null) return;
        _context.SetFromAlert(row.Alert);
        _context.PreferredRtrScriptId = "process-tree";   // script já parametrizado por {PROCESS}
        _nav.NavigateTo("rtr");
    }

    [RelayCommand]
    private void RtrInvestigateUser(AlertRowVm? row)
    {
        row ??= SelectedAlertRow;
        if (row is null) return;
        _context.SetFromAlert(row.Alert);
        _context.PreferredRtrScriptId = "logon-history";
        _nav.NavigateTo("rtr");
    }

    [RelayCommand]
    private void RtrInvestigateConnections(AlertRowVm? row)
    {
        row ??= SelectedAlertRow;
        if (row is null) return;
        _context.SetFromAlert(row.Alert);
        _context.PreferredRtrScriptId = "connections";
        _nav.NavigateTo("rtr");
    }

    [RelayCommand]
    private void OpenReputation(AlertRowVm? row)
    {
        row ??= SelectedAlertRow;
        if (row is null) return;
        _context.SetFromAlert(row.Alert);
        _nav.NavigateTo("reputation");
    }

    [RelayCommand]
    private void OpenAttackTree(AlertRowVm? row)
    {
        row ??= SelectedAlertRow;
        if (row is null) return;
        _context.SetFromAlert(row.Alert);
        _nav.NavigateTo("attacktree");
    }

    [RelayCommand]
    private void CopyToClipboard(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        try { System.Windows.Clipboard.SetText(value); SetActionResult(true, $"📋  Copiado: {Truncate(value, 40)}"); }
        catch (Exception ex) { Log.Warning(ex, "Clipboard set falhou"); }
    }

    private static string Truncate(string s, int max) => s.Length > max ? s[..max] + "…" : s;

    [RelayCommand]
    private void RunVelociraptor()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        _context.PreferredForensicsTool = ForensicsToolKind.Velociraptor;
        _nav.NavigateTo("forensics");
    }

    [RelayCommand]
    private void OpenForensics()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        _nav.NavigateTo("forensics");
    }

    [RelayCommand]
    private void OpenMemory()
    {
        if (SelectedAlertRow is null) return;
        _context.SetFromAlert(SelectedAlertRow.Alert);
        _nav.NavigateTo("memory");
    }

    // ─── Ações de IR — Atualizar status na Falcon ─────────────────────────────
    [RelayCommand]
    private async Task UpdateStatus(string status)
    {
        var compositeId = SelectedAlertRow?.Alert.CompositeId;
        if (string.IsNullOrWhiteSpace(compositeId)) return;
        IsActionBusy = true;
        SetActionResult(false, $"Atualizando status para '{TranslateStatus(status)}'…");
        var r = await _falcon.UpdateAlertStatusAsync(compositeId, status).ConfigureAwait(true);
        IsActionBusy = false;
        SetActionResult(r.IsSuccess,
            r.IsSuccess
                ? $"✅  Status atualizado para: {TranslateStatus(status)}"
                : $"❌  Falha ao atualizar status: {r.Error}");
        if (r.IsSuccess)
            _ = LoadCommand.ExecuteAsync(null); // reload silencioso para refletir novo status na grade
    }

    // ─── Ações de IR — Encaminhar para Incidente ──────────────────────────────
    [RelayCommand]
    private async Task EscalateToIncident()
    {
        if (SelectedAlertRow is null) return;
        // Marca como Em Progresso para sinalizar ao analista no Falcon Console
        var compositeId = SelectedAlertRow.Alert.CompositeId;
        if (!string.IsNullOrWhiteSpace(compositeId))
        {
            IsActionBusy = true;
            SetActionResult(false, "Marcando alerta como Em Progresso…");
            await _falcon.UpdateAlertStatusAsync(compositeId, "in_progress").ConfigureAwait(true);
            IsActionBusy = false;
        }
        SetActionResult(true,
            "✅  Alerta marcado como Em Progresso.\n" +
            "O Falcon agrupa automaticamente alertas correlacionados em Incidentes.\n" +
            "Acesse Incidentes (Ctrl+2) para acompanhar o agrupamento.");
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private void SetActionResult(bool isSuccess, string message)
    {
        ActionIsSuccess    = isSuccess;
        ActionMessage      = message;
        ActionMessageColor = isSuccess ? new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0x7F))
                                       : new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52));
    }

    private static string TranslateStatus(string s) => s switch
    {
        "new"            => "Novo",
        "in_progress"    => "Em Progresso",
        "true_positive"  => "Verdadeiro Positivo",
        "false_positive" => "Falso Positivo",
        "ignored"        => "Ignorado",
        "closed"         => "Fechado",
        _                => s
    };
}

// ─── Row VM ────────────────────────────────────────────────────────────────────
/// <summary>Linha do DataGrid com formatação NG-SIEM-like.</summary>
public sealed class AlertRowVm
{
    public FalconAlert Alert { get; }
    public Brush SeverityBrush { get; }
    public string SeverityLabel { get; }
    public string DetectTime    => Alert.CreatedUtc.ToLocalTime().ToString("HH:mm:ss");
    public string DateGroup     => Alert.CreatedUtc.ToLocalTime().ToString("dd 'de' MMMM 'de' yyyy", new CultureInfo("pt-BR"));
    public string DetectionName => string.IsNullOrWhiteSpace(Alert.Name) ? Alert.Description : Alert.Name;
    public string Category      => Alert.Product?.ToLowerInvariant() switch
    {
        "epp"       => "Endpoint",
        "idp"       => "Identity",
        "ngsiem"    => "NG-SIEM",
        "mobile"    => "Mobile",
        "cloud"     => "Cloud",
        "overwatch" => "OverWatch",
        "xdr"       => "XDR",
        _           => Alert.Product ?? ""
    };
    public string AccountName    => string.IsNullOrWhiteSpace(Alert.UserName) ? "—" : Alert.UserName;
    public string SourceEndpoint => string.IsNullOrWhiteSpace(Alert.Hostname) ? "—" : Alert.Hostname;
    public string AssignedTo     => string.IsNullOrWhiteSpace(Alert.AssignedToName) ? "Não atribuído" : Alert.AssignedToName;
    public string StatusLabel    => Alert.Status switch
    {
        "new"            => "Novo",
        "in_progress"    => "Em progresso",
        "true_positive"  => "Verdadeiro positivo",
        "false_positive" => "Falso positivo",
        "ignored"        => "Ignorado",
        "closed"         => "Fechado",
        _                => Alert.Status ?? ""
    };
    public string TacticTechnique
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Alert.Tactic) && string.IsNullOrWhiteSpace(Alert.Technique)) return "";
            return $"{Alert.Tactic} · {Alert.Technique}".Trim(' ', '·');
        }
    }
    public string MitreDisplay
    {
        get
        {
            var tactic    = Alert.Tactic;
            var technique = Alert.Technique;
            var techId    = Alert.TechniqueId;
            if (string.IsNullOrWhiteSpace(tactic) && string.IsNullOrWhiteSpace(technique)) return "—";
            return !string.IsNullOrWhiteSpace(techId)
                ? $"{tactic} · {techId} {technique}"
                : $"{tactic} · {technique}";
        }
    }
    public string CompositeIdShort => Alert.CompositeId.Length > 12 ? Alert.CompositeId[..12] + "…" : Alert.CompositeId;
    public string AidShort => string.IsNullOrWhiteSpace(Alert.Aid) ? "—" : (Alert.Aid.Length > 12 ? Alert.Aid[..12] + "…" : Alert.Aid);
    public bool HasAid     => !string.IsNullOrWhiteSpace(Alert.Aid);
    public bool IsSelected { get; set; }

    private AlertRowVm(FalconAlert a)
    {
        Alert = a;
        SeverityLabel = a.Severity.ToString();
        SeverityBrush = a.Severity switch
        {
            Severity.Critical      => new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x80)),
            Severity.High          => new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)),
            Severity.Medium        => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)),
            Severity.Low           => new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
            _                      => new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9))
        };
    }

    public bool MatchesSearch(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return true;
        text = text.Trim().ToLowerInvariant();
        return (DetectionName?.ToLowerInvariant().Contains(text) ?? false)
            || (SourceEndpoint?.ToLowerInvariant().Contains(text) ?? false)
            || (AccountName?.ToLowerInvariant().Contains(text) ?? false)
            || (TacticTechnique?.ToLowerInvariant().Contains(text) ?? false)
            || (Category?.ToLowerInvariant().Contains(text) ?? false);
    }

    public static AlertRowVm From(FalconAlert a) => new(a);
}

/// <summary>IOC chip exibido no painel de investigação. Clicável para copiar.</summary>
public sealed record IocChip(string Label, string Icon, string Value, string CopyValue)
{
    public string Display => Value.Length > 38 ? Value[..38] + "…" : Value;
}

/// <summary>Card de IP enriquecido: geo + ISP + reputação. Exibido como bloco no painel.</summary>
public sealed record IpIntelCard(
    string  Label,
    string  Ip,
    string  Country,
    string  CountryCode,
    string  Region,
    string  City,
    string  Isp,
    string  Org,
    string  AsNumber,
    bool    IsPrivate,
    string  ReputationVerdict,
    string? ReputationDetail,
    int     MaliciousVotes,
    int     TotalEngines)
{
    public string Geo        => IsPrivate ? "Rede interna (RFC 1918)" : $"{City}, {Region}, {Country} ({CountryCode})";
    public string DetectionRatio => TotalEngines > 0 ? $"{MaliciousVotes}/{TotalEngines}" : "—";
    public string VerdictIcon => ReputationVerdict switch
    {
        "Malicious"  => "🔴",
        "Suspicious" => "🟡",
        "Clean"      => "🟢",
        _            => "⚪"
    };
}

