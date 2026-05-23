namespace CyberThrust.IRIS.Core.Errors;

/// <summary>
/// Erro estruturado retornado por todos os módulos. Sempre carrega um <see cref="IrisErrorCode"/>,
/// uma mensagem amigável (i18n-ready) e opcionalmente dados de contexto e a exceção original.
/// </summary>
public sealed record IrisError(
    IrisErrorCode Code,
    string Message,
    string? Hint = null,
    Exception? Cause = null,
    IReadOnlyDictionary<string, string>? Context = null)
{
    public string CodeString => Code.ToCodeString();

    public override string ToString()
    {
        var ctx = Context is { Count: > 0 } ? " | " + string.Join(", ", Context.Select(kv => $"{kv.Key}={kv.Value}")) : string.Empty;
        return $"[{CodeString}] {Message}{ctx}";
    }

    public static IrisError From(IrisErrorCode code, string message, Exception? cause = null, string? hint = null)
        => new(code, message, hint, cause);
}
