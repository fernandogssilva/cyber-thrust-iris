using CyberThrust.IRIS.Core.Models;
using CyberThrust.IRIS.Core.Results;

namespace CyberThrust.IRIS.Core.Abstractions;

/// <summary>Contrato para qualquer provedor de autenticação (Entra ID hoje, outros amanhã).</summary>
public interface IAuthenticator
{
    Task<Result<IrisIdentity>> SignInInteractiveAsync(CancellationToken ct = default);
    Task<Result<IrisIdentity>> SignInSilentAsync(CancellationToken ct = default);
    Task<Result<bool>> SignOutAsync(CancellationToken ct = default);
    Task<Result<string>> GetAccessTokenAsync(IEnumerable<string> scopes, CancellationToken ct = default);
    bool IsAuthenticated { get; }
}
