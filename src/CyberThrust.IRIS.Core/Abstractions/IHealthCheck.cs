using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.Core.Abstractions;

/// <summary>Cada módulo implementa um health check que aparece na tela "Validação do Sistema".</summary>
public interface IHealthCheck
{
    string Name { get; }
    string Category { get; }
    Task<HealthResult> CheckAsync(CancellationToken ct = default);
}
