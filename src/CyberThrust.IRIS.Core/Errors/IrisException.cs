namespace CyberThrust.IRIS.Core.Errors;

/// <summary>Exceção que encapsula um <see cref="IrisError"/> — usada quando o fluxo precisa propagar via throw.</summary>
public sealed class IrisException : Exception
{
    public IrisError Error { get; }

    public IrisException(IrisError error) : base(error.Message, error.Cause) => Error = error;

    public IrisException(IrisErrorCode code, string message, Exception? cause = null, string? hint = null)
        : this(new IrisError(code, message, hint, cause))
    { }
}
