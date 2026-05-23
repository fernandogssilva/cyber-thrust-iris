using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;

namespace CyberThrust.IRIS.Core.Abstractions;

public interface IForensicsCollector
{
    string Name { get; }
    HostPlatform[] SupportedPlatforms { get; }
    Task<Result<ForensicsJob>> StartCollectionAsync(string aid, ForensicsCollectionOptions options, IProgress<JobProgress>? progress = null, CancellationToken ct = default);
    Task<Result<ForensicsJob>> GetStatusAsync(string jobId, CancellationToken ct = default);
}
