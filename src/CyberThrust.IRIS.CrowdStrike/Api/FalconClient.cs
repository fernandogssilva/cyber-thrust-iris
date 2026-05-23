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

            var payload = JsonSerializer.Serialize(new { ids = idArr });
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
                    Hostname: d.GetPropertyOrEmpty("device.hostname"),
                    Severity: MapSeverity(d.TryGetProperty("severity", out var sv) ? sv.GetInt32() : 0),
                    Tactic: d.GetPropertyOrEmpty("tactic"),
                    Technique: d.GetPropertyOrEmpty("technique"),
                    Description: d.GetPropertyOrEmpty("description"),
                    TimestampUtc: d.TryGetProperty("created_timestamp", out var ts) && DateTimeOffset.TryParse(ts.GetString(), out var dto) ? dto : DateTimeOffset.UtcNow,
                    Context: new Dictionary<string, string>()));
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

    public Task<Result<bool>> ContainHostAsync(string aid, CancellationToken ct = default)
        => DeviceActionAsync(aid, "contain", ct);
    public Task<Result<bool>> LiftContainmentAsync(string aid, CancellationToken ct = default)
        => DeviceActionAsync(aid, "lift_containment", ct);

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
