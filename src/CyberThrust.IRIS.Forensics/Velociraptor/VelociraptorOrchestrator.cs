using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using CyberThrust.IRIS.CrowdStrike.Rtr;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.Forensics.Velociraptor;

/// <summary>
/// Deploy do Velociraptor "offline collector" via RTR. O collector é um binário
/// auto-contido gerado previamente no servidor Velociraptor e armazenado como put-file.
/// </summary>
public sealed class VelociraptorOrchestrator : IForensicsCollector
{
    private readonly IFalconClient _falcon;
    private readonly ILogger<VelociraptorOrchestrator> _log;
    public string Name => "Velociraptor";
    public HostPlatform[] SupportedPlatforms => [HostPlatform.Windows, HostPlatform.Linux, HostPlatform.MacOs];

    public VelociraptorOrchestrator(IFalconClient falcon, ILogger<VelociraptorOrchestrator> log)
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
            progress?.Report(new JobProgress(5, "session.init", "Abrindo sessão RTR"));
            var s = await _falcon.StartRtrSessionAsync(aid, ct).ConfigureAwait(false);
            if (s.IsFailure) return Result<ForensicsJob>.Fail(s.Error!);

            progress?.Report(new JobProgress(15, "velo.deploy", "Enviando Velociraptor collector"));
            var put = await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.Put, "put velociraptor-collector.exe", ct).ConfigureAwait(false);
            if (put.IsFailure) return Result<ForensicsJob>.Fail(put.Error!);

            progress?.Report(new JobProgress(30, "velo.run", "Executando coleta — aguarde"));
            var run = await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.RunScript,
                "runscript -Raw=```Start-Process -FilePath 'C:\\Windows\\Temp\\velociraptor-collector.exe' -ArgumentList '--output','C:\\Windows\\Temp\\velo.zip' -Wait -NoNewWindow```", ct).ConfigureAwait(false);
            if (run.IsFailure) return Result<ForensicsJob>.Fail(run.Error!);

            progress?.Report(new JobProgress(80, "exfil", "Enviando resultado"));
            var exfil = await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.RunScript,
                $"runscript -Raw=```Invoke-WebRequest -Uri '{options.ExfilUri}' -Method PUT -InFile 'C:\\Windows\\Temp\\velo.zip'```", ct).ConfigureAwait(false);
            if (exfil.IsFailure) return Result<ForensicsJob>.Fail(IrisError.From(IrisErrorCode.DskExfilFailed, "Falha exfil Velociraptor.", exfil.Error!.Cause));

            progress?.Report(new JobProgress(95, "cleanup", "Limpando host"));
            await _falcon.ExecuteRtrAsync(s.Value!.SessionId, RtrCommands.RunScript,
                "runscript -Raw=```Remove-Item -Force C:\\Windows\\Temp\\velociraptor-collector.exe,C:\\Windows\\Temp\\velo.zip```", ct).ConfigureAwait(false);

            progress?.Report(new JobProgress(100, "done", "OK"));
            return Result<ForensicsJob>.Ok(new ForensicsJob(jobId, aid, ForensicsToolKind.Velociraptor, JobState.Succeeded, options.ExfilUri, null, started, DateTimeOffset.UtcNow, 100));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Velociraptor falhou para AID {Aid}", aid);
            return Result<ForensicsJob>.Fail(IrisErrorCode.DskVelociraptorExecutionFailed, ex.Message, ex);
        }
    }

    public Task<Result<ForensicsJob>> GetStatusAsync(string jobId, CancellationToken ct = default)
        => Task.FromResult(Result<ForensicsJob>.Fail(IrisErrorCode.SysUnknown, "Status persistente não implementado."));
}
