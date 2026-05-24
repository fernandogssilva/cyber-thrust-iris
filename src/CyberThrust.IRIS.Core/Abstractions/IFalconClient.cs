using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;

namespace CyberThrust.IRIS.Core.Abstractions;

public interface IFalconClient
{
    Task<Result<FalconCapability>> ProbeCapabilitiesAsync(CancellationToken ct = default);
    Task<Result<IReadOnlyList<FalconDetection>>> ListRecentDetectionsAsync(int limit = 100, CancellationToken ct = default);
    Task<Result<IReadOnlyList<FalconAlert>>> ListAlertsAsync(FalconAlertsFilter filter, CancellationToken ct = default);
    Task<Result<IReadOnlyList<FalconHost>>> SearchHostsAsync(string filter, CancellationToken ct = default);
    Task<Result<bool>> ContainHostAsync(string aid, CancellationToken ct = default);
    Task<Result<bool>> LiftContainmentAsync(string aid, CancellationToken ct = default);
    Task<Result<RtrSessionInfo>> StartRtrSessionAsync(string aid, CancellationToken ct = default);
    Task<Result<RtrCommandResult>> ExecuteRtrAsync(string sessionId, string command, string commandString, CancellationToken ct = default);
    Task<Result<IReadOnlyList<RtrCommandResult>>> ExecuteRtrBatchAsync(IEnumerable<string> aids, string command, string commandString, TimeSpan? timeout = null, CancellationToken ct = default);
}
