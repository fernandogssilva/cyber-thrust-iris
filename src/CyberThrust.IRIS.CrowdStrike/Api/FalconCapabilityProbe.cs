using System.Net;
using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;
using Microsoft.Extensions.Logging;

namespace CyberThrust.IRIS.CrowdStrike.Api;

/// <summary>
/// "Probe" que descobre quais módulos da Falcon estão licenciados na tenant atual,
/// chamando endpoints leves de cada produto e mapeando 200/403/404 para licenciamento.
///
/// Garantia central do produto: a UI NUNCA quebra por falta de licença — apenas
/// desabilita o recurso e mostra tooltip explicando o motivo.
/// </summary>
public sealed class FalconCapabilityProbe
{
    private readonly HttpClient _http;
    private readonly FalconOptions _opt;
    private readonly ILogger<FalconCapabilityProbe> _log;

    public FalconCapabilityProbe(HttpClient http, FalconOptions opt, ILogger<FalconCapabilityProbe> log)
    {
        _http = http;
        _opt = opt;
        _log = log;
    }

    public async Task<Result<FalconCapability>> ProbeAsync(CancellationToken ct = default)
    {
        try
        {
            // Cada chamada usa "limit=1" e ignora o body — só interessa o status code.
            var insight = await ProbeEndpointAsync("/detects/queries/detects/v1?limit=1", ct).ConfigureAwait(false);
            var identity = await ProbeEndpointAsync("/identity-protection/combined/policies/v1?limit=1", ct).ConfigureAwait(false);
            var spotlight = await ProbeEndpointAsync("/spotlight/queries/vulnerabilities/v1?limit=1", ct).ConfigureAwait(false);
            var discover = await ProbeEndpointAsync("/discover/queries/applications/v1?limit=1", ct).ConfigureAwait(false);
            var surface = await ProbeEndpointAsync("/fem/queries/external-assets/v1?limit=1", ct).ConfigureAwait(false);
            var logscale = await ProbeEndpointAsync("/humio-config/v1/sources", ct).ConfigureAwait(false);
            var forensics = await ProbeEndpointAsync("/falcon-forensics/queries/jobs/v1?limit=1", ct).ConfigureAwait(false);
            var fusion = await ProbeEndpointAsync("/workflows/queries/definitions/v1?limit=1", ct).ConfigureAwait(false);
            var fdr = await ProbeEndpointAsync("/files-data-replicator/v1/streams?limit=1", ct).ConfigureAwait(false);
            var rtrAdmin = await ProbeEndpointAsync("/real-time-response/queries/scripts/v1?limit=1", ct).ConfigureAwait(false);

            return Result<FalconCapability>.Ok(new FalconCapability(
                InsightXdr: insight,
                IdentityProtection: identity,
                Spotlight: spotlight,
                Discover: discover,
                Surface: surface,
                LogScale: logscale,
                Forensics: forensics,
                Fusion: fusion,
                DataReplicator: fdr,
                RtrAdmin: rtrAdmin,
                CloudRegion: _opt.Cloud));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Falha ao executar capability probe.");
            return Result<FalconCapability>.Fail(IrisErrorCode.CsCapabilityProbeFailed, ex.Message, ex);
        }
    }

    private async Task<bool> ProbeEndpointAsync(string path, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        try
        {
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            // Interpretação dos códigos HTTP (validado em tenant us-2 real):
            //  200/206              → módulo licenciado + scope da API key OK
            //  429 TooManyRequests  → licenciado, apenas rate-limited
            //  405 MethodNotAllowed → endpoint write-only existe (Hosts actions, RTR sessions) — módulo presente
            //  403 Forbidden        → módulo provavelmente licenciado mas a API key não tem o scope necessário
            //                         (ajustável no Falcon Console sem custo adicional)
            //  404 NotFound         → módulo NÃO está disponível na tenant (requer contrato adicional)
            //  401 Unauthorized     → token ruim (não conclusivo)
            return resp.StatusCode is HttpStatusCode.OK
                or HttpStatusCode.PartialContent
                or HttpStatusCode.TooManyRequests
                or HttpStatusCode.MethodNotAllowed;
        }
        catch
        {
            return false;
        }
    }
}
