using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using CyberThrust.IRIS.CrowdStrike.Rtr;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.Memory;

/// <summary>
/// Coleta de memória via RTR.
/// Estratégia preferida:
///  1. Falcon xmemdump nativo quando RAM ≤ 4GB (cabe no `get` direto)
///  2. Magnet DumpIt (free) para RAM > 4GB com exfil direto para presigned URL
///  3. WinPmem (Velocidx/AFF4) como fallback open-source
/// </summary>
public sealed class MemoryCollector : IMemoryCollector
{
    private readonly IFalconClient _falcon;
    private readonly ILogger<MemoryCollector> _log;
    public string Name => "FalconMemoryCollector";

    public MemoryCollector(IFalconClient falcon, ILogger<MemoryCollector> log)
    {
        _falcon = falcon;
        _log = log;
    }

    public async Task<Result<MemoryJob>> CaptureAsync(string aid, MemoryCaptureOptions options, IProgress<JobProgress>? progress = null, CancellationToken ct = default)
    {
        var jobId = Guid.NewGuid().ToString("N");
        var started = DateTimeOffset.UtcNow;
        try
        {
            progress?.Report(new JobProgress(5, "session.init", "Abrindo RTR"));
            var s = await _falcon.StartRtrSessionAsync(aid, ct).ConfigureAwait(false);
            if (s.IsFailure) return Result<MemoryJob>.Fail(s.Error!);

            return options.Tool switch
            {
                MemoryToolKind.FalconXmemdump => await CaptureXmemdumpAsync(s.Value!.SessionId, aid, options, jobId, started, progress, ct).ConfigureAwait(false),
                MemoryToolKind.MagnetDumpIt => await CaptureDumpItAsync(s.Value!.SessionId, aid, options, jobId, started, progress, ct).ConfigureAwait(false),
                MemoryToolKind.WinPmem => await CaptureWinPmemAsync(s.Value!.SessionId, aid, options, jobId, started, progress, ct).ConfigureAwait(false),
                _ => Result<MemoryJob>.Fail(IrisErrorCode.MemCollectorNotFound, $"Coletor {options.Tool} não implementado.")
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Memory capture falhou para AID {Aid}", aid);
            return Result<MemoryJob>.Fail(IrisErrorCode.SysUnknown, ex.Message, ex);
        }
    }

    private async Task<Result<MemoryJob>> CaptureXmemdumpAsync(string sessionId, string aid, MemoryCaptureOptions opt, string jobId, DateTimeOffset started, IProgress<JobProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new JobProgress(15, "xmemdump", "Executando xmemdump nativo Falcon"));
        var cmd = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.XmemDump, $"xmemdump -path \"C:\\Windows\\Temp\\xmem-{aid}.raw\"", ct).ConfigureAwait(false);
        if (cmd.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemXmemdumpFailed, cmd.Error!.Message, cmd.Error.Cause);

        progress?.Report(new JobProgress(70, "exfil", "Enviando para storage"));
        var exfil = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```Invoke-WebRequest -Uri '{opt.ExfilUri}' -Method PUT -InFile 'C:\\Windows\\Temp\\xmem-{aid}.raw'```", ct).ConfigureAwait(false);
        if (exfil.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemUploadFailed, exfil.Error!.Message);

        progress?.Report(new JobProgress(95, "cleanup", "Limpando host"));
        await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```Remove-Item -Force 'C:\\Windows\\Temp\\xmem-{aid}.raw'```", ct).ConfigureAwait(false);

        progress?.Report(new JobProgress(100, "done"));
        return Result<MemoryJob>.Ok(new MemoryJob(jobId, aid, opt.Tool, JobState.Succeeded, opt.ExfilUri, null, null, started, DateTimeOffset.UtcNow, 100));
    }

    private async Task<Result<MemoryJob>> CaptureDumpItAsync(string sessionId, string aid, MemoryCaptureOptions opt, string jobId, DateTimeOffset started, IProgress<JobProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new JobProgress(10, "dumpit.deploy", "Enviando Magnet DumpIt"));
        var put = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.Put, "put DumpIt.exe", ct).ConfigureAwait(false);
        if (put.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemDumpitFailed, put.Error!.Message);

        progress?.Report(new JobProgress(30, "dumpit.run", "Capturando RAM"));
        var run = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```Start-Process -FilePath C:\\Windows\\Temp\\DumpIt.exe -ArgumentList '/output C:\\Windows\\Temp\\dumpit-{aid}.dmp /quiet' -Wait -NoNewWindow```", ct).ConfigureAwait(false);
        if (run.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemDumpitFailed, run.Error!.Message);

        progress?.Report(new JobProgress(75, "exfil", "Enviando para storage"));
        var exfil = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```Invoke-WebRequest -Uri '{opt.ExfilUri}' -Method PUT -InFile 'C:\\Windows\\Temp\\dumpit-{aid}.dmp'```", ct).ConfigureAwait(false);
        if (exfil.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemUploadFailed, exfil.Error!.Message);

        progress?.Report(new JobProgress(95, "cleanup", "Limpando"));
        await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```Remove-Item -Force C:\\Windows\\Temp\\DumpIt.exe,C:\\Windows\\Temp\\dumpit-{aid}.dmp```", ct).ConfigureAwait(false);

        progress?.Report(new JobProgress(100, "done"));
        return Result<MemoryJob>.Ok(new MemoryJob(jobId, aid, opt.Tool, JobState.Succeeded, opt.ExfilUri, null, null, started, DateTimeOffset.UtcNow, 100));
    }

    private async Task<Result<MemoryJob>> CaptureWinPmemAsync(string sessionId, string aid, MemoryCaptureOptions opt, string jobId, DateTimeOffset started, IProgress<JobProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new JobProgress(10, "winpmem.deploy"));
        var put = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.Put, "put winpmem.exe", ct).ConfigureAwait(false);
        if (put.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemWinpmemFailed, put.Error!.Message);

        progress?.Report(new JobProgress(35, "winpmem.run"));
        var run = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```& C:\\Windows\\Temp\\winpmem.exe --format=raw --output=C:\\Windows\\Temp\\winpmem-{aid}.raw```", ct).ConfigureAwait(false);
        if (run.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemWinpmemFailed, run.Error!.Message);

        progress?.Report(new JobProgress(80, "exfil"));
        var exfil = await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```Invoke-WebRequest -Uri '{opt.ExfilUri}' -Method PUT -InFile 'C:\\Windows\\Temp\\winpmem-{aid}.raw'```", ct).ConfigureAwait(false);
        if (exfil.IsFailure) return Result<MemoryJob>.Fail(IrisErrorCode.MemUploadFailed, exfil.Error!.Message);

        await _falcon.ExecuteRtrAsync(sessionId, RtrCommands.RunScript,
            $"runscript -Raw=```Remove-Item -Force C:\\Windows\\Temp\\winpmem.exe,C:\\Windows\\Temp\\winpmem-{aid}.raw```", ct).ConfigureAwait(false);

        progress?.Report(new JobProgress(100, "done"));
        return Result<MemoryJob>.Ok(new MemoryJob(jobId, aid, opt.Tool, JobState.Succeeded, opt.ExfilUri, null, null, started, DateTimeOffset.UtcNow, 100));
    }

    public Task<Result<MemoryAnalysisReport>> AnalyzeAsync(string artifactPath, CancellationToken ct = default)
    {
        // Hook para SuperMem/Volatility/MemProcFS via Process.Start
        // Mantido propositalmente abstrato — a UI baixa o artefato e dispara o analisador localmente.
        if (!File.Exists(artifactPath))
            return Task.FromResult(Result<MemoryAnalysisReport>.Fail(IrisErrorCode.CfgPathInvalid, $"Artefato não encontrado: {artifactPath}"));

        var rpt = new MemoryAnalysisReport(
            ArtifactPath: artifactPath,
            Findings: Array.Empty<MemoryFinding>(),
            SuspiciousProcesses: Array.Empty<string>(),
            Metadata: new Dictionary<string, string> { ["status"] = "analyzer-not-attached" });
        return Task.FromResult(Result<MemoryAnalysisReport>.Ok(rpt));
    }
}
