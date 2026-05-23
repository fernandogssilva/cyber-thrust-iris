using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using CyberThrust.IRIS.CrowdStrike.Rtr;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.Forensics.Uac;

/// <summary>
/// Orquestra UAC (Unix-like Artifacts Collector) via RTR em hosts Linux/macOS/ESXi.
/// Implementa o fluxo oficial: https://tclahr.github.io/uac-docs/using_uac_with_cs_falcon_rtr/
/// </summary>
public sealed class UacOrchestrator : IForensicsCollector
{
    private readonly IFalconClient _falcon;
    private readonly ILogger<UacOrchestrator> _log;
    public string Name => "UAC";
    public HostPlatform[] SupportedPlatforms => [HostPlatform.Linux, HostPlatform.MacOs, HostPlatform.Esxi];

    public UacOrchestrator(IFalconClient falcon, ILogger<UacOrchestrator> log)
    {
        _falcon = falcon;
        _log = log;
    }

    public async Task<Result<ForensicsJob>> StartCollectionAsync(string aid, ForensicsCollectionOptions options, IProgress<JobProgress>? progress = null, CancellationToken ct = default)
    {
        var jobId = Guid.NewGuid().ToString("N");
        var started = DateTimeOffset.UtcNow;
        try
        {
            progress?.Report(new JobProgress(5, "session.init", "Abrindo RTR"));
            var s = await _falcon.StartRtrSessionAsync(aid, ct).ConfigureAwait(false);
            if (s.IsFailure) return Result<ForensicsJob>.Fail(s.Error!);

            progress?.Report(new JobProgress(15, "uac.deploy", "Enviando UAC para o host"));
            var put = await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.Put, "put uac.tar.gz", ct).ConfigureAwait(false);
            if (put.IsFailure) return Result<ForensicsJob>.Fail(put.Error!);

            var profilesCsv = options.Modules.Count > 0 ? string.Join(",", options.Modules) : "ir_triage";

            progress?.Report(new JobProgress(30, "uac.run", "Executando UAC — pode levar minutos"));
            var run = await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.RunScript,
                $"runscript -Raw=```cd /tmp && tar -xzf uac.tar.gz && cd uac-* && ./uac -p {profilesCsv} /tmp/uac-out```", ct).ConfigureAwait(false);
            if (run.IsFailure) return Result<ForensicsJob>.Fail(run.Error!);

            progress?.Report(new JobProgress(80, "exfil", "Enviando para storage"));
            var exfil = await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.RunScript,
                $"runscript -Raw=```curl -X PUT -T /tmp/uac-out/uac-*.tar.gz '{options.ExfilUri}'```", ct).ConfigureAwait(false);
            if (exfil.IsFailure) return Result<ForensicsJob>.Fail(IrisError.From(IrisErrorCode.DskExfilFailed, "Falha exfil UAC.", exfil.Error!.Cause));

            progress?.Report(new JobProgress(95, "cleanup", "Limpando host"));
            await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.RunScript,
                "runscript -Raw=```rm -rf /tmp/uac-* /tmp/uac.tar.gz /tmp/uac-out```", ct).ConfigureAwait(false);

            progress?.Report(new JobProgress(100, "done", "OK"));
            return Result<ForensicsJob>.Ok(new ForensicsJob(jobId, aid, ForensicsToolKind.Uac, JobState.Succeeded, options.ExfilUri, null, started, DateTimeOffset.UtcNow, 100));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "UAC falhou para AID {Aid}", aid);
            return Result<ForensicsJob>.Fail(IrisErrorCode.DskUacExecutionFailed, ex.Message, ex);
        }
    }

    public Task<Result<ForensicsJob>> GetStatusAsync(string jobId, CancellationToken ct = default)
        => Task.FromResult(Result<ForensicsJob>.Fail(IrisErrorCode.SysUnknown, "Status persistente não implementado."));
}
