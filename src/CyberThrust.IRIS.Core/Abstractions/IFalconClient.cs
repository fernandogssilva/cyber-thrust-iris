using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;

namespace CyberThrust.IRIS.Core.Abstractions;

public interface IFalconClient
{
    Task<Result<FalconCapability>> ProbeCapabilitiesAsync(CancellationToken ct = default);
    Task<Result<IReadOnlyList<FalconDetection>>> ListRecentDetectionsAsync(int limit = 100, CancellationToken ct = default);
    Task<Result<IReadOnlyList<FalconAlert>>> ListAlertsAsync(FalconAlertsFilter filter, CancellationToken ct = default);
    Task<Result<IReadOnlyList<FalconIncident>>> ListIncidentsAsync(TimeSpan? lookBack = null, int limit = 200, CancellationToken ct = default);
    Task<Result<IReadOnlyList<FalconHost>>> SearchHostsAsync(string filter, CancellationToken ct = default);
    /// <summary>Perfil completo do device via /devices/entities/devices/v2?ids={aid}. Retorna OS, IPs, agente, manufacturer, last_seen, containment status, OU, tags etc.</summary>
    Task<Result<DeviceProfile>> GetDeviceProfileAsync(string aid, CancellationToken ct = default);
    Task<Result<bool>> ContainHostAsync(string aid, CancellationToken ct = default);
    Task<Result<bool>> LiftContainmentAsync(string aid, CancellationToken ct = default);
    /// <summary>Atualiza o status de um alerta (new | in_progress | true_positive | false_positive | ignored | closed).</summary>
    Task<Result<bool>> UpdateAlertStatusAsync(string compositeId, string status, CancellationToken ct = default);
    Task<Result<RtrSessionInfo>> StartRtrSessionAsync(string aid, CancellationToken ct = default);
    Task<Result<RtrCommandResult>> ExecuteRtrAsync(string sessionId, string command, string commandString, CancellationToken ct = default);
    Task<Result<IReadOnlyList<RtrCommandResult>>> ExecuteRtrBatchAsync(IEnumerable<string> aids, string command, string commandString, TimeSpan? timeout = null, CancellationToken ct = default);
}
