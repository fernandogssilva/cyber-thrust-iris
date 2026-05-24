using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.CrowdStrike.Api;

public sealed class FalconClient : IFalconClient
{
    private readonly HttpClient _http;
    private readonly FalconCapabilityProbe _probe;
    private readonly ILogger<FalconClient> _log;
    private FalconCapability? _capCache;

    public FalconClient(HttpClient http, FalconCapabilityProbe probe, ILogger<FalconClient> log)
    {
        _http = http;
        _probe = probe;
        _log = log;
    }

    public async Task<Result<FalconCapability>> ProbeCapabilitiesAsync(CancellationToken ct = default)
    {
        var r = await _probe.ProbeAsync(ct).ConfigureAwait(false);
        if (r.IsSuccess) _capCache = r.Value;
        return r;
    }

    public Task<Result<IReadOnlyList<FalconDetection>>> ListRecentDetectionsAsync(int limit = 100, CancellationToken ct = default)
        => Result.Try<IReadOnlyList<FalconDetection>>(async () =>
        {
            // Falcon 2.0 endpoint /alerts/queries/alerts/v2 (substitui /detects)
            using var ids = await _http.GetAsync($"/alerts/queries/alerts/v2?limit={limit}&sort=created_timestamp.desc", ct).ConfigureAwait(false);
            await EnsureSuccessAsync(ids, ct).ConfigureAwait(false);
            using var idsDoc = JsonDocument.Parse(await ids.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var idArr = idsDoc.RootElement.GetProperty("resources").EnumerateArray().Select(e => e.GetString()!).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
            if (idArr.Length == 0) return Array.Empty<FalconDetection>();

            // ⚠️ Alerts API v2 EXIGE "composite_ids" (não "ids") — confirmado em api.us-2.crowdstrike.com.
            //    Caso contrário: HTTP 400 "at least one identifier should be present in the request".
            var payload = JsonSerializer.Serialize(new { composite_ids = idArr });
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync("/alerts/entities/alerts/v2", content, ct).ConfigureAwait(false);
            await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));

            var list = new List<FalconDetection>();
            foreach (var d in doc.RootElement.GetProperty("resources").EnumerateArray())
            {
                list.Add(new FalconDetection(
                    DetectionId: d.GetPropertyOrEmpty("composite_id"),
                    Aid: d.GetPropertyOrEmpty("agent_id"),
                    Hostname: ExtractHostname(d),
                    Severity: MapSeverity(d.TryGetProperty("severity", out var sv) && sv.ValueKind == JsonValueKind.Number ? sv.GetInt32() : 0),
                    Tactic: ExtractMitre(d, "tactic"),
                    Technique: ExtractMitre(d, "technique"),
                    Description: d.GetPropertyOrEmpty("description"),
                    TimestampUtc: d.TryGetProperty("created_timestamp", out var ts) && DateTimeOffset.TryParse(ts.GetString(), out var dto) ? dto : DateTimeOffset.UtcNow,
                    Context: new Dictionary<string, string>()));
            }
            return list.AsReadOnly();
        }, IrisErrorCode.CsApiServerError);

    public Task<Result<IReadOnlyList<FalconAlert>>> ListAlertsAsync(FalconAlertsFilter filter, CancellationToken ct = default)
        => Result.Try<IReadOnlyList<FalconAlert>>(async () =>
        {
            // Constrói FQL filter
            var clauses = new List<string>();
            if (filter.Products is { Length: > 0 })
                clauses.Add("(" + string.Join(",", filter.Products.Select(p => $"product:'{p}'")) + ")");
            if (filter.Statuses is { Length: > 0 })
                clauses.Add("(" + string.Join(",", filter.Statuses.Select(s => $"status:'{s}'")) + ")");
            if (filter.MinSeverities is { Length: > 0 })
            {
                var minScore = filter.MinSeverities.Min(s => s switch
                {
                    Severity.Critical => 90, Severity.High => 70, Severity.Medium => 40, Severity.Low => 20, _ => 0
                });
                clauses.Add($"severity:>={minScore}");
            }
            if (filter.LookBack is { } lb)
            {
                var since = DateTimeOffset.UtcNow.Subtract(lb).ToString("yyyy-MM-ddTHH:mm:ssZ");
                clauses.Add($"created_timestamp:>='{since}'");
            }
            if (!string.IsNullOrWhiteSpace(filter.Aid))
                clauses.Add($"agent_id:'{filter.Aid}'");
            var fql = clauses.Count == 0 ? "" : "&filter=" + Uri.EscapeDataString(string.Join("+", clauses));

            using var ids = await _http.GetAsync($"/alerts/queries/alerts/v2?limit={filter.Limit}&sort=created_timestamp.desc{fql}", ct).ConfigureAwait(false);
            await EnsureSuccessAsync(ids, ct).ConfigureAwait(false);
            using var idsDoc = JsonDocument.Parse(await ids.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var idArr = idsDoc.RootElement.GetProperty("resources").EnumerateArray().Select(e => e.GetString()!).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
            if (idArr.Length == 0) return Array.Empty<FalconAlert>();

            // Detalhes em batches de 100. Alerts API v2 EXIGE "composite_ids" no body.
            var list = new List<FalconAlert>();
            for (int i = 0; i < idArr.Length; i += 100)
            {
                var batch = idArr.Skip(i).Take(100).ToArray();
                var payload = JsonSerializer.Serialize(new { composite_ids = batch });
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var resp = await _http.PostAsync("/alerts/entities/alerts/v2", content, ct).ConfigureAwait(false);
                await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
                foreach (var d in doc.RootElement.GetProperty("resources").EnumerateArray())
                {
                    // display_name é o nome amigável (NG-SIEM/IDP), name é o técnico (EDR pattern)
                    var displayName = d.GetPropertyOrEmpty("display_name");
                    var techName = d.GetPropertyOrEmpty("name");
                    var finalName = !string.IsNullOrWhiteSpace(displayName) ? displayName : techName;

                    // Enriquecimento — extrai IOCs e contexto do alerta para Extra dict
                    var extra = new Dictionary<string, string>();
                    void TryAdd(string key, string srcKey)
                    {
                        var v = d.GetPropertyOrEmpty(srcKey);
                        if (!string.IsNullOrWhiteSpace(v)) extra[key] = v;
                    }
                    TryAdd("sha256",          "sha256");
                    TryAdd("md5",             "md5");
                    TryAdd("sha1",            "sha1");
                    TryAdd("filepath",        "filepath");
                    TryAdd("filename",        "filename");
                    TryAdd("cmdline",         "cmdline");
                    TryAdd("commandline",     "commandline");
                    TryAdd("process_id",      "process_id");
                    TryAdd("parent_image",    "parent_image_file_name");
                    TryAdd("parent_cmdline",  "parent_command_line");
                    TryAdd("ip_address",      "ip_address");
                    TryAdd("local_ip",        "local_ip");
                    TryAdd("external_ip",     "external_ip");
                    TryAdd("domain",          "domain");
                    TryAdd("url",             "url");
                    TryAdd("falcon_host_link","falcon_host_link");
                    TryAdd("logon_domain",    "logon_domain");
                    TryAdd("user_id",         "user_id");
                    TryAdd("user_principal",  "user_principal");
                    TryAdd("device_os",       "device_os");
                    TryAdd("device_country",  "device_country");
                    // parent_details é um objeto aninhado em alguns produtos
                    if (d.TryGetProperty("parent_details", out var pd) && pd.ValueKind == JsonValueKind.Object)
                    {
                        var pdName = pd.GetPropertyOrEmpty("filename");
                        var pdCmd  = pd.GetPropertyOrEmpty("cmdline");
                        if (!string.IsNullOrWhiteSpace(pdName)) extra["parent_image"]   = pdName;
                        if (!string.IsNullOrWhiteSpace(pdCmd))  extra["parent_cmdline"] = pdCmd;
                    }

                    list.Add(new FalconAlert(
                        CompositeId: d.GetPropertyOrEmpty("composite_id"),
                        Product: d.GetPropertyOrEmpty("product"),
                        Vendor: ExtractFirstFromStringArray(d, "source_vendors", fallback: "crowdstrike"),
                        Name: finalName,
                        Description: d.GetPropertyOrEmpty("description"),
                        Severity: MapSeverity(d.TryGetProperty("severity", out var sv) && sv.ValueKind == JsonValueKind.Number ? sv.GetInt32() : 0),
                        Status: d.GetPropertyOrEmpty("status"),
                        Tactic: ExtractMitre(d, "tactic"),
                        Technique: ExtractMitre(d, "technique"),
                        TacticId: ExtractMitre(d, "tactic_id"),
                        TechniqueId: ExtractMitre(d, "technique_id"),
                        Aid: d.GetPropertyOrEmpty("agent_id"),
                        Hostname: ExtractHostname(d),
                        UserName: ExtractUserName(d),
                        AssignedToName: d.GetPropertyOrEmpty("assigned_to_name"),
                        CreatedUtc: d.TryGetProperty("created_timestamp", out var ct1) && DateTimeOffset.TryParse(ct1.GetString(), out var ctDt) ? ctDt : DateTimeOffset.UtcNow,
                        UpdatedUtc: d.TryGetProperty("updated_timestamp", out var ut) && DateTimeOffset.TryParse(ut.GetString(), out var utDt)
                            ? utDt
                            : d.TryGetProperty("crawled_timestamp", out var crt) && DateTimeOffset.TryParse(crt.GetString(), out var crDt)
                                ? crDt
                                : DateTimeOffset.UtcNow,
                        Extra: extra));
                }
            }
            return list.AsReadOnly();
        }, IrisErrorCode.CsApiServerError);

    public Task<Result<IReadOnlyList<FalconIncident>>> ListIncidentsAsync(TimeSpan? lookBack = null, int limit = 200, CancellationToken ct = default)
        => Result.Try<IReadOnlyList<FalconIncident>>(async () =>
        {
            var fql = "";
            if (lookBack is { } lb)
            {
                var since = DateTimeOffset.UtcNow.Subtract(lb).ToString("yyyy-MM-ddTHH:mm:ssZ");
                fql = "&filter=" + Uri.EscapeDataString($"created:>='{since}'");
            }
            using var ids = await _http.GetAsync($"/incidents/queries/incidents/v1?limit={limit}&sort=created:desc{fql}", ct).ConfigureAwait(false);
            await EnsureSuccessAsync(ids, ct).ConfigureAwait(false);
            using var idsDoc = JsonDocument.Parse(await ids.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var idArr = idsDoc.RootElement.GetProperty("resources").EnumerateArray().Select(e => e.GetString()!).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
            if (idArr.Length == 0) return Array.Empty<FalconIncident>();

            var list = new List<FalconIncident>();
            for (int i = 0; i < idArr.Length; i += 100)
            {
                var batch = idArr.Skip(i).Take(100).ToArray();
                var payload = JsonSerializer.Serialize(new { ids = batch });
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var resp = await _http.PostAsync("/incidents/entities/incidents/GET/v1", content, ct).ConfigureAwait(false);
                await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
                foreach (var d in doc.RootElement.GetProperty("resources").EnumerateArray())
                {
                    int fineScore = d.TryGetProperty("fine_score", out var fs) && fs.ValueKind == JsonValueKind.Number ? fs.GetInt32() : 0;
                    var hostnames = new List<string>();
                    if (d.TryGetProperty("hosts", out var hs) && hs.ValueKind == JsonValueKind.Array)
                        foreach (var h in hs.EnumerateArray())
                            if (h.TryGetProperty("hostname", out var hn)) hostnames.Add(hn.GetString() ?? "");
                    var tactics = new List<string>();
                    if (d.TryGetProperty("tactics", out var ta) && ta.ValueKind == JsonValueKind.Array)
                        foreach (var t in ta.EnumerateArray()) tactics.Add(t.GetString() ?? "");
                    var techniques = new List<string>();
                    if (d.TryGetProperty("techniques", out var tq) && tq.ValueKind == JsonValueKind.Array)
                        foreach (var t in tq.EnumerateArray()) techniques.Add(t.GetString() ?? "");
                    var objectives = new List<string>();
                    if (d.TryGetProperty("objectives", out var ob) && ob.ValueKind == JsonValueKind.Array)
                        foreach (var o in ob.EnumerateArray()) objectives.Add(o.GetString() ?? "");

                    var status = (d.TryGetProperty("status", out var st) && st.ValueKind == JsonValueKind.Number ? st.GetInt32() : 20) switch
                    {
                        20 => "new", 25 => "reopened", 30 => "in_progress", 40 => "closed", _ => "new"
                    };

                    list.Add(new FalconIncident(
                        IncidentId: d.GetPropertyOrEmpty("incident_id"),
                        Name: d.GetPropertyOrEmpty("name"),
                        Description: d.GetPropertyOrEmpty("description"),
                        Severity: MapSeverity(fineScore),
                        FineScore: fineScore,
                        Status: status,
                        AssignedToName: d.GetPropertyOrEmpty("assigned_to_name"),
                        HostsCount: d.TryGetProperty("host_ids", out var hi) && hi.ValueKind == JsonValueKind.Array ? hi.GetArrayLength() : 0,
                        DetectionsCount: d.TryGetProperty("alert_ids", out var ai) && ai.ValueKind == JsonValueKind.Array ? ai.GetArrayLength() : 0,
                        Hostnames: hostnames,
                        Tactics: tactics,
                        Techniques: techniques,
                        Objectives: objectives,
                        StartUtc: d.TryGetProperty("start", out var sd) && DateTimeOffset.TryParse(sd.GetString(), out var sdt) ? sdt : DateTimeOffset.UtcNow,
                        EndUtc: d.TryGetProperty("end", out var ed) && DateTimeOffset.TryParse(ed.GetString(), out var edt) ? edt : DateTimeOffset.UtcNow,
                        CreatedUtc: d.TryGetProperty("created", out var cd) && DateTimeOffset.TryParse(cd.GetString(), out var cdt) ? cdt : DateTimeOffset.UtcNow,
                        ModifiedUtc: d.TryGetProperty("modified_timestamp", out var md) && DateTimeOffset.TryParse(md.GetString(), out var mdt) ? mdt : DateTimeOffset.UtcNow));
                }
            }
            return list.AsReadOnly();
        }, IrisErrorCode.CsApiServerError);

    public Task<Result<IReadOnlyList<FalconHost>>> SearchHostsAsync(string filter, CancellationToken ct = default)
        => Result.Try<IReadOnlyList<FalconHost>>(async () =>
        {
            using var resp = await _http.GetAsync($"/devices/queries/devices/v1?limit=100&filter={Uri.EscapeDataString(filter)}", ct).ConfigureAwait(false);
            await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var ids = doc.RootElement.GetProperty("resources").EnumerateArray().Select(e => e.GetString()!).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
            if (ids.Length == 0) return Array.Empty<FalconHost>();

            using var details = await _http.GetAsync($"/devices/entities/devices/v2?ids={string.Join("&ids=", ids)}", ct).ConfigureAwait(false);
            await EnsureSuccessAsync(details, ct).ConfigureAwait(false);
            using var dDoc = JsonDocument.Parse(await details.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var list = new List<FalconHost>();
            foreach (var h in dDoc.RootElement.GetProperty("resources").EnumerateArray())
            {
                list.Add(new FalconHost(
                    Aid: h.GetPropertyOrEmpty("device_id"),
                    Hostname: h.GetPropertyOrEmpty("hostname"),
                    Platform: ParsePlatform(h.GetPropertyOrEmpty("platform_name")),
                    OsVersion: h.GetPropertyOrEmpty("os_version"),
                    LocalIp: h.GetPropertyOrEmpty("local_ip"),
                    ExternalIp: h.GetPropertyOrEmpty("external_ip"),
                    Status: h.GetPropertyOrEmpty("status"),
                    LastSeenUtc: h.TryGetProperty("last_seen", out var ls) && DateTimeOffset.TryParse(ls.GetString(), out var dto) ? dto : DateTimeOffset.UtcNow,
                    Tags: h.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array ? t.EnumerateArray().Select(x => x.GetString() ?? "").ToArray() : Array.Empty<string>()));
            }
            return list.AsReadOnly();
        }, IrisErrorCode.CsApiServerError);

    public Task<Result<DeviceProfile>> GetDeviceProfileAsync(string aid, CancellationToken ct = default)
        => Result.Try<DeviceProfile>(async () =>
        {
            using var resp = await _http.GetAsync($"/devices/entities/devices/v2?ids={Uri.EscapeDataString(aid)}", ct).ConfigureAwait(false);
            await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var arr = doc.RootElement.GetProperty("resources").EnumerateArray();
            if (!arr.Any()) return new DeviceProfile(aid, "—", "—", "—", "—", "—", "unknown",
                DateTimeOffset.MinValue, DateTimeOffset.MinValue, "—", "—", "—", "—", "—", "—", "—",
                Array.Empty<string>());
            var h = arr.First();
            return new DeviceProfile(
                Aid:               h.GetPropertyOrEmpty("device_id"),
                Hostname:          h.GetPropertyOrEmpty("hostname"),
                Platform:          h.GetPropertyOrEmpty("platform_name"),
                OsVersion:         h.GetPropertyOrEmpty("os_version"),
                LocalIp:           h.GetPropertyOrEmpty("local_ip"),
                ExternalIp:        h.GetPropertyOrEmpty("external_ip"),
                Status:            h.GetPropertyOrEmpty("status"),
                LastSeenUtc:       h.TryGetProperty("last_seen",  out var ls) && DateTimeOffset.TryParse(ls.GetString(), out var lsDto) ? lsDto : DateTimeOffset.MinValue,
                FirstSeenUtc:      h.TryGetProperty("first_seen", out var fs) && DateTimeOffset.TryParse(fs.GetString(), out var fsDto) ? fsDto : DateTimeOffset.MinValue,
                MachineDomain:     h.GetPropertyOrEmpty("machine_domain"),
                OuPath:            h.GetPropertyOrEmpty("ou"),
                SiteName:          h.GetPropertyOrEmpty("site_name"),
                SystemManufacturer:h.GetPropertyOrEmpty("system_manufacturer"),
                SystemProductName: h.GetPropertyOrEmpty("system_product_name"),
                AgentVersion:      h.GetPropertyOrEmpty("agent_version"),
                KernelVersion:     h.GetPropertyOrEmpty("kernel_version"),
                Tags:              h.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
                                       ? t.EnumerateArray().Select(x => x.GetString() ?? "").Where(s => !string.IsNullOrWhiteSpace(s)).ToArray()
                                       : Array.Empty<string>());
        }, IrisErrorCode.CsApiServerError);

    public Task<Result<bool>> ContainHostAsync(string aid, CancellationToken ct = default)
        => DeviceActionAsync(aid, "contain", ct);
    public Task<Result<bool>> LiftContainmentAsync(string aid, CancellationToken ct = default)
        => DeviceActionAsync(aid, "lift_containment", ct);

    public Task<Result<bool>> UpdateAlertStatusAsync(string compositeId, string status, CancellationToken ct = default)
        => Result.Try<bool>(async () =>
        {
            // PATCH /alerts/entities/alerts/v2 — atualiza status do alerta via Alerts API v2.
            // Valores válidos: new | in_progress | true_positive | false_positive | ignored | closed
            var payload = JsonSerializer.Serialize(new
            {
                action_parameters = new[] { new { name = "update_status", value = status } },
                composite_ids = new[] { compositeId }
            });
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            var req = new HttpRequestMessage(HttpMethod.Patch, "/alerts/entities/alerts/v2") { Content = content };
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            await EnsureSuccessAsync(resp, ct, IrisErrorCode.CsApiServerError).ConfigureAwait(false);
            return true;
        }, IrisErrorCode.CsApiServerError);

    private Task<Result<bool>> DeviceActionAsync(string aid, string action, CancellationToken ct)
        => Result.Try<bool>(async () =>
        {
            var payload = JsonSerializer.Serialize(new { ids = new[] { aid }, action_parameters = Array.Empty<object>() });
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync($"/devices/entities/devices-actions/v2?action_name={action}", content, ct).ConfigureAwait(false);
            await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
            return true;
        }, IrisErrorCode.CsHostContainmentFailed);

    public Task<Result<RtrSessionInfo>> StartRtrSessionAsync(string aid, CancellationToken ct = default)
        => Result.Try(async () =>
        {
            var payload = JsonSerializer.Serialize(new { device_id = aid, origin = "CyberThrust.IRIS" });
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync("/real-time-response/entities/sessions/v1", content, ct).ConfigureAwait(false);
            await EnsureSuccessAsync(resp, ct, IrisErrorCode.CsRtrSessionInitFailed).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var r = doc.RootElement.GetProperty("resources").EnumerateArray().First();
            return new RtrSessionInfo(
                SessionId: r.GetPropertyOrEmpty("session_id"),
                Aid: aid,
                CreatedUtc: DateTimeOffset.UtcNow,
                ExpiresUtc: DateTimeOffset.UtcNow.AddMinutes(10));
        }, IrisErrorCode.CsRtrSessionInitFailed);

    public Task<Result<RtrCommandResult>> ExecuteRtrAsync(string sessionId, string command, string commandString, CancellationToken ct = default)
        => Result.Try(async () =>
        {
            var payload = JsonSerializer.Serialize(new { base_command = command, command_string = commandString, session_id = sessionId, persist = true });
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync("/real-time-response/entities/admin-command/v1", content, ct).ConfigureAwait(false);
            await EnsureSuccessAsync(resp, ct, IrisErrorCode.CsRtrCommandRejected).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var r = doc.RootElement.GetProperty("resources").EnumerateArray().First();
            return new RtrCommandResult(
                Aid: r.GetPropertyOrEmpty("aid"),
                SessionId: sessionId,
                Complete: r.TryGetProperty("complete", out var cp) && cp.GetBoolean(),
                Stdout: r.TryGetProperty("stdout", out var so) ? so.GetString() : null,
                Stderr: r.TryGetProperty("stderr", out var se) ? se.GetString() : null,
                ExitCode: r.TryGetProperty("exit_code", out var ec) && ec.ValueKind == JsonValueKind.Number ? ec.GetInt32() : null,
                TaskId: r.GetPropertyOrEmpty("task_id"));
        }, IrisErrorCode.CsRtrCommandRejected);

    public Task<Result<IReadOnlyList<RtrCommandResult>>> ExecuteRtrBatchAsync(IEnumerable<string> aids, string command, string commandString, TimeSpan? timeout = null, CancellationToken ct = default)
        => Result.Try<IReadOnlyList<RtrCommandResult>>(async () =>
        {
            var aidArr = aids.ToArray();
            // 1) abrir batch
            var initPayload = JsonSerializer.Serialize(new { host_ids = aidArr, origin = "CyberThrust.IRIS", timeout = (int)(timeout?.TotalSeconds ?? 60) });
            using var initContent = new StringContent(initPayload, Encoding.UTF8, "application/json");
            using var initResp = await _http.PostAsync("/real-time-response/combined/batch-init-session/v1", initContent, ct).ConfigureAwait(false);
            await EnsureSuccessAsync(initResp, ct, IrisErrorCode.CsRtrSessionInitFailed).ConfigureAwait(false);
            using var initDoc = JsonDocument.Parse(await initResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var batchId = initDoc.RootElement.GetProperty("batch_id").GetString()
                ?? throw new IrisException(IrisErrorCode.CsRtrSessionInitFailed, "batch_id ausente.");

            // 2) executar
            var execPayload = JsonSerializer.Serialize(new { base_command = command, command_string = commandString, batch_id = batchId });
            using var execContent = new StringContent(execPayload, Encoding.UTF8, "application/json");
            using var execResp = await _http.PostAsync("/real-time-response/combined/batch-admin-command/v1", execContent, ct).ConfigureAwait(false);
            await EnsureSuccessAsync(execResp, ct, IrisErrorCode.CsRtrCommandRejected).ConfigureAwait(false);
            using var execDoc = JsonDocument.Parse(await execResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));

            var list = new List<RtrCommandResult>();
            if (execDoc.RootElement.TryGetProperty("combined", out var combined) && combined.TryGetProperty("resources", out var resources))
            {
                foreach (var entry in resources.EnumerateObject())
                {
                    var aid = entry.Name;
                    var v = entry.Value;
                    list.Add(new RtrCommandResult(
                        Aid: aid,
                        SessionId: v.GetPropertyOrEmpty("session_id"),
                        Complete: v.TryGetProperty("complete", out var c) && c.GetBoolean(),
                        Stdout: v.TryGetProperty("stdout", out var so) ? so.GetString() : null,
                        Stderr: v.TryGetProperty("stderr", out var se) ? se.GetString() : null,
                        ExitCode: null,
                        TaskId: v.GetPropertyOrEmpty("task_id")));
                }
            }
            return list.AsReadOnly();
        }, IrisErrorCode.CsRtrBatchPartialFailure);

    // ─── helpers ──────────────────────────────────────────────────────────
    private static async Task EnsureSuccessAsync(HttpResponseMessage resp, CancellationToken ct, IrisErrorCode? specific = null)
    {
        if (resp.IsSuccessStatusCode) return;
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var code = resp.StatusCode switch
        {
            HttpStatusCode.Unauthorized => IrisErrorCode.CsApiUnauthorized,
            HttpStatusCode.Forbidden => IrisErrorCode.CsApiForbidden,
            HttpStatusCode.TooManyRequests => IrisErrorCode.CsApiRateLimited,
            HttpStatusCode.BadGateway => IrisErrorCode.CsApiBadGateway,
            HttpStatusCode.RequestTimeout or HttpStatusCode.GatewayTimeout => IrisErrorCode.CsApiTimeout,
            _ when (int)resp.StatusCode >= 500 => IrisErrorCode.CsApiServerError,
            _ => specific ?? IrisErrorCode.CsApiServerError
        };
        throw new IrisException(code, $"Falcon API {(int)resp.StatusCode} {resp.ReasonPhrase}: {Truncate(body, 500)}");
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    private static Severity MapSeverity(int v) => v switch
    {
        >= 90 => Severity.Critical,
        >= 70 => Severity.High,
        >= 40 => Severity.Medium,
        >= 20 => Severity.Low,
        _ => Severity.Informational
    };

    private static HostPlatform ParsePlatform(string s) => s.ToLowerInvariant() switch
    {
        "windows" => HostPlatform.Windows,
        "linux" => HostPlatform.Linux,
        "mac" or "macos" or "macosx" => HostPlatform.MacOs,
        "esxi" => HostPlatform.Esxi,
        _ => HostPlatform.Other
    };

    // ─── Alerts v2 schema helpers ───────────────────────────────────────────
    // O JSON real de /alerts/entities/alerts/v2 (verificado em us-2) NÃO usa
    // device.hostname / tactic / technique no topo. Os campos vivem em:
    //   • host_names:[ "DESKTOP-X" ]          (preferido)
    //   • source_endpoint_host_name:"…"       (fallback EPP)
    //   • mitre_attack:[ {tactic, technique, tactic_id, technique_id, …} ]
    //   • source_account_name:"…"             (IDP) / user_name não existe

    private static string ExtractHostname(JsonElement d)
    {
        if (d.TryGetProperty("host_names", out var hn) && hn.ValueKind == JsonValueKind.Array)
        {
            foreach (var h in hn.EnumerateArray())
            {
                var s = h.GetString();
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
        }
        var src = d.GetPropertyOrEmpty("source_endpoint_host_name");
        if (!string.IsNullOrWhiteSpace(src)) return src;
        // último fallback legado
        return d.GetPropertyOrEmpty("device.hostname");
    }

    private static string ExtractMitre(JsonElement d, string field)
    {
        if (d.TryGetProperty("mitre_attack", out var ma) && ma.ValueKind == JsonValueKind.Array)
        {
            foreach (var m in ma.EnumerateArray())
            {
                if (m.TryGetProperty(field, out var v) && v.ValueKind == JsonValueKind.String)
                {
                    var s = v.GetString();
                    if (!string.IsNullOrWhiteSpace(s)) return s;
                }
            }
        }
        // fallback top-level (alguns produtos antigos)
        return d.GetPropertyOrEmpty(field);
    }

    private static string ExtractUserName(JsonElement d)
    {
        var idp = d.GetPropertyOrEmpty("source_account_name");
        if (!string.IsNullOrWhiteSpace(idp)) return idp;
        return d.GetPropertyOrEmpty("user_name");
    }

    private static string ExtractFirstFromStringArray(JsonElement d, string field, string fallback = "")
    {
        if (d.TryGetProperty(field, out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in arr.EnumerateArray())
            {
                var s = e.GetString();
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
        }
        return fallback;
    }
}

file static class JsonElementExtensions
{
    public static string GetPropertyOrEmpty(this JsonElement el, string path)
    {
        var parts = path.Split('.');
        var current = el;
        foreach (var part in parts)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(part, out var next)) return string.Empty;
            current = next;
        }
        return current.ValueKind switch
        {
            JsonValueKind.String => current.GetString() ?? string.Empty,
            JsonValueKind.Number => current.ToString(),
            JsonValueKind.True or JsonValueKind.False => current.GetBoolean().ToString(),
            _ => string.Empty
        };
    }
}
