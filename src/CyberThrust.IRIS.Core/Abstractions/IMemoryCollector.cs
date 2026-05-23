using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;

namespace CyberThrust.IRIS.Core.Abstractions;

public interface IMemoryCollector
{
    string Name { get; }
    Task<Result<MemoryJob>> CaptureAsync(string aid, MemoryCaptureOptions options, IProgress<JobProgress>? progress = null, CancellationToken ct = default);
    Task<Result<MemoryAnalysisReport>> AnalyzeAsync(string artifactPath, CancellationToken ct = default);
}
