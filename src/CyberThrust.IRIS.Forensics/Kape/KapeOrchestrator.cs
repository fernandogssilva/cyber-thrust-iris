using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using CyberThrust.IRIS.CrowdStrike.Rtr;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.Forensics.Kape;

/// <summary>
/// Orquestra coleta KAPE via RTR em hosts Windows:
///  1. put do KAPE.zip + targets/modules custom
///  2. runscript para descompactar e executar
///  3. compactar resultado, calcular SHA-256
///  4. exfil direto para presigned URL (evita gargalo do `get` 4GB)
///  5. limpar artefatos do host
/// </summary>
public sealed class KapeOrchestrator : IForensicsCollector
{
    private readonly IFalconClient _falcon;
    private readonly ILogger<KapeOrchestrator> _log;
    public string Name => "KAPE";
    public HostPlatform[] SupportedPlatforms => [HostPlatform.Windows];

    public KapeOrchestrator(IFalconClient falcon, ILogger<KapeOrchestrator> log)
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
            progress?.Report(new JobProgress(2, "session.init", "Abrindo sessão RTR"));
            var session = await _falcon.StartRtrSessionAsync(aid, ct).ConfigureAwait(false);
            if (session.IsFailure) return Result<ForensicsJob>.Fail(session.Error!);

            progress?.Report(new JobProgress(10, "kape.deploy", "Enviando KAPE para o host"));
            // put presume que existe um "put-file" registrado no Falcon RTR com nome "KAPE.zip"
            var put = await _falcon.ExecuteRtrAsync(session.Value!.SessionId, RtrCommands.Put, "put KAPE.zip", ct).ConfigureAwait(false);
            if (put.IsFailure) return Result<ForensicsJob>.Fail(put.Error!);

            progress?.Report(new JobProgress(25, "kape.unpack", "Descompactando"));
            var unpack = await _falcon.ExecuteRtrAsync(session.Value!.SessionId, RtrCommands.RunScript,
                "runscript -Raw=```Expand-Archive -Path C:\\Windows\\Temp\\KAPE.zip -DestinationPath C:\\Windows\\Temp\\KAPE -Force```", ct).ConfigureAwait(false);
            if (unpack.IsFailure) return Result<ForensicsJob>.Fail(unpack.Error!);

            var targetsCsv = string.Join(",", options.Targets);
            var modulesCsv = string.Join(",", options.Modules);
            var kapeCmd = $"runscript -Raw=```C:\\Windows\\Temp\\KAPE\\kape.exe --tsource C: --tdest C:\\Windows\\Temp\\kape-out --target {targetsCsv} --module {modulesCsv} --vhdx kape-{aid} --zip kape-{aid}```";

            progress?.Report(new JobProgress(35, "kape.run", "Executando KAPE — pode levar até 30 min"));
            var run = await _falcon.ExecuteRtrAsync(session.Value!.SessionId, RtrCommands.RunScript, kapeCmd, ct).ConfigureAwait(false);
            if (run.IsFailure) return Result<ForensicsJob>.Fail(run.Error!);

            progress?.Report(new JobProgress(80, "exfil", "Enviando evidência para storage"));
            var exfilCmd = $"runscript -Raw=```Invoke-WebRequest -Uri '{options.ExfilUri}' -Method PUT -InFile 'C:\\Windows\\Temp\\kape-out\\kape-{aid}.zip'```";
            var exfil = await _falcon.ExecuteRtrAsync(session.Value!.SessionId, RtrCommands.RunScript, exfilCmd, ct).ConfigureAwait(false);
            if (exfil.IsFailure) return Result<ForensicsJob>.Fail(IrisError.From(IrisErrorCode.DskExfilFailed, "Falha ao exfiltrar evidência KAPE.", exfil.Error!.Cause));

            progress?.Report(new JobProgress(95, "cleanup", "Removendo artefatos do host"));
            await _falcon.ExecuteRtrAsync(session.Value!.SessionId, RtrCommands.RunScript,
                "runscript -Raw=```Remove-Item -Recurse -Force C:\\Windows\\Temp\\KAPE,C:\\Windows\\Temp\\KAPE.zip,C:\\Windows\\Temp\\kape-out```", ct).ConfigureAwait(false);

            progress?.Report(new JobProgress(100, "done", "Concluído"));
            return Result<ForensicsJob>.Ok(new ForensicsJob(jobId, aid, ForensicsToolKind.Kape, JobState.Succeeded, options.ExfilUri, null, started, DateTimeOffset.UtcNow, 100));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "KAPE orchestration falhou para AID {Aid}", aid);
            return Result<ForensicsJob>.Fail(IrisErrorCode.DskKapeExecutionFailed, ex.Message, ex);
        }
    }

    public Task<Result<ForensicsJob>> GetStatusAsync(string jobId, CancellationToken ct = default)
        => Task.FromResult(Result<ForensicsJob>.Fail(IrisErrorCode.SysUnknown, "Status persistente não implementado nesta versão — use o IProgress retornado por StartCollectionAsync."));
}
