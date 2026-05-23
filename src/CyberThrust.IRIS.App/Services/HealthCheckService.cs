using System.Diagnostics;
using System.Net.NetworkInformation;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.CrowdStrike.Api;
using CyberThrust.IRIS.EntraID;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Bateria de auto-validação que roda na tela "Health Check".
/// Cada check é independente e retorna um <see cref="HealthResult"/> com código IRIS-* claro.
/// </summary>
public sealed class HealthCheckService
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<HealthCheckService> _log;

    public HealthCheckService(IServiceProvider sp, ILogger<HealthCheckService> log)
    {
        _sp = sp;
        _log = log;
    }

    public async IAsyncEnumerable<HealthResult> RunAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        yield return await Time("Runtime .NET 8", "Sistema", () =>
        {
            var ver = Environment.Version;
            return ver.Major >= 8
                ? new HealthResult("Runtime .NET 8", "Sistema", HealthStatus.Pass, $".NET {ver}")
                : new HealthResult("Runtime .NET 8", "Sistema", HealthStatus.Fail, $".NET {ver} — requer 8.0+", new IrisError(IrisErrorCode.SysUnsupportedOs, "Runtime antigo."));
        }, ct);

        yield return await Time("Windows 10/11", "Sistema", () =>
        {
            var os = Environment.OSVersion;
            return os.Platform == PlatformID.Win32NT && os.Version.Major >= 10
                ? new HealthResult("Windows 10/11", "Sistema", HealthStatus.Pass, os.VersionString)
                : new HealthResult("Windows 10/11", "Sistema", HealthStatus.Fail, os.VersionString, new IrisError(IrisErrorCode.SysUnsupportedOs, "Windows antigo."));
        }, ct);

        yield return await Time("WebView2 Runtime", "Sistema", () =>
        {
            try
            {
                var v = Microsoft.Web.WebView2.Core.CoreWebView2Environment.GetAvailableBrowserVersionString();
                return new HealthResult("WebView2", "Sistema", HealthStatus.Pass, v);
            }
            catch (Exception ex)
            {
                return new HealthResult("WebView2", "Sistema", HealthStatus.Fail, "Runtime ausente — instale Microsoft Edge WebView2",
                    new IrisError(IrisErrorCode.UiWebView2RuntimeMissing, ex.Message, "Baixe em https://go.microsoft.com/fwlink/p/?LinkId=2124703"));
            }
        }, ct);

        yield return await Time("Conectividade internet", "Rede", () =>
        {
            try
            {
                using var ping = new Ping();
                var reply = ping.Send("8.8.8.8", 3000);
                return reply?.Status == IPStatus.Success
                    ? new HealthResult("Conectividade", "Rede", HealthStatus.Pass, $"latência {reply.RoundtripTime}ms")
                    : new HealthResult("Conectividade", "Rede", HealthStatus.Warn, "Sem resposta", new IrisError(IrisErrorCode.NetConnectivityCheckFailed, "Ping falhou."));
            }
            catch (Exception ex)
            {
                return new HealthResult("Conectividade", "Rede", HealthStatus.Fail, ex.Message, new IrisError(IrisErrorCode.NetConnectivityCheckFailed, ex.Message));
            }
        }, ct);

        // Entra ID — sem chamada real; valida config e cache
        yield return await Time("Entra ID configurado", "Identidade", () =>
        {
            var opt = (EntraOptions?)_sp.GetService(typeof(EntraOptions));
            if (opt is null || string.IsNullOrWhiteSpace(opt.ClientId) || opt.ClientId.StartsWith("00000000"))
                return new HealthResult("Entra ID", "Identidade", HealthStatus.Warn, "Configure ClientId em appsettings.local.json",
                    new IrisError(IrisErrorCode.CfgEntraSectionInvalid, "ClientId vazio/placeholder."));
            return new HealthResult("Entra ID", "Identidade", HealthStatus.Pass, $"tenant={opt.TenantId} / clientId={opt.ClientId[..8]}…");
        }, ct);

        // Falcon — capability probe (faz chamada real se possível)
        yield return await TimeAsync("Falcon — capability probe", "CrowdStrike", async () =>
        {
            try
            {
                var fopt = (FalconOptions?)_sp.GetService(typeof(FalconOptions));
                if (fopt is null || string.IsNullOrWhiteSpace(fopt.ClientId) || string.IsNullOrWhiteSpace(fopt.ClientSecret))
                    return new HealthResult("Falcon API", "CrowdStrike", HealthStatus.Warn, "Configure Falcon ClientId/Secret em appsettings.local.json",
                        new IrisError(IrisErrorCode.CfgFalconSectionInvalid, "Credenciais Falcon ausentes."));
                var falcon = (IFalconClient?)_sp.GetService(typeof(IFalconClient));
                if (falcon is null) return new HealthResult("Falcon API", "CrowdStrike", HealthStatus.Fail, "IFalconClient não registrado.",
                    new IrisError(IrisErrorCode.SysUnknown, "DI mal configurada."));
                var cap = await falcon.ProbeCapabilitiesAsync(ct).ConfigureAwait(false);
                if (cap.IsFailure) return new HealthResult("Falcon API", "CrowdStrike", HealthStatus.Fail, cap.Error!.Message, cap.Error);
                var lic = string.Join(", ", cap.Value!.Licensed);
                return new HealthResult("Falcon API", "CrowdStrike", HealthStatus.Pass, $"cloud={cap.Value.CloudRegion}; licenciados: {lic}");
            }
            catch (Exception ex)
            {
                return new HealthResult("Falcon API", "CrowdStrike", HealthStatus.Fail, ex.Message, new IrisError(IrisErrorCode.CsCapabilityProbeFailed, ex.Message, ex));
            }
        }, ct);

        // Ferramentas externas
        yield return CheckExternalTool("KAPE", "tools/external/kape/kape.exe", IrisErrorCode.DskKapeMissing);
        yield return CheckExternalTool("Velociraptor", "tools/external/velociraptor/velociraptor.exe", IrisErrorCode.DskVelociraptorMissing);
        yield return CheckExternalTool("WinPmem", "tools/external/winpmem/winpmem.exe", IrisErrorCode.MemWinpmemFailed);
        yield return CheckExternalTool("DumpIt", "tools/external/dumpit/DumpIt.exe", IrisErrorCode.MemDumpitFailed);
        yield return CheckExternalTool("UAC", "tools/external/uac/uac", IrisErrorCode.DskUacMissing);

        // Pasta de logs gravável
        yield return Time("Pasta de logs gravável", "Sistema", () =>
        {
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberThrust", "IRIS", "logs");
                Directory.CreateDirectory(dir);
                var probe = Path.Combine(dir, $".write-probe-{Guid.NewGuid():N}");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return new HealthResult("Logs writable", "Sistema", HealthStatus.Pass, dir);
            }
            catch (Exception ex)
            {
                return new HealthResult("Logs writable", "Sistema", HealthStatus.Fail, ex.Message, new IrisError(IrisErrorCode.SysFileSystemError, ex.Message, ex));
            }
        }).Result;
    }

    private HealthResult CheckExternalTool(string name, string relativePath, IrisErrorCode missingCode)
    {
        var full = Path.Combine(AppContext.BaseDirectory, relativePath.Replace('/', Path.DirectorySeparatorChar));
        if (File.Exists(full))
            return new HealthResult(name, "Ferramentas", HealthStatus.Pass, full);
        return new HealthResult(name, "Ferramentas", HealthStatus.Skipped, $"opcional — coloque em {relativePath}",
            new IrisError(missingCode, $"{name} ausente em {relativePath}", "Download e copie o binário para esta pasta para habilitar coletas locais."));
    }

    // ─── helpers cronometrados ──────────────────────────────────────────────
    private static async Task<HealthResult> Time(string name, string category, Func<HealthResult> action, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var r = await Task.Run(action, ct).ConfigureAwait(false);
        return r with { Duration = sw.Elapsed };
    }
    private static async Task<HealthResult> TimeAsync(string name, string category, Func<Task<HealthResult>> action, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var r = await action().ConfigureAwait(false);
        return r with { Duration = sw.Elapsed };
    }
}
