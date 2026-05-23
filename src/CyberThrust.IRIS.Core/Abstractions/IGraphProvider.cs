using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;

namespace CyberThrust.IRIS.Core.Abstractions;

public interface IGraphProvider
{
    Task<Result<AttackGraph>> BuildAttackGraphAsync(string incidentId, CancellationToken ct = default);
    Task<Result<AttackGraph>> BuildLateralMovementGraphAsync(string aid, TimeSpan lookback, CancellationToken ct = default);
}
