using CyberThrust.IRIS.Core.Errors;

namespace CyberThrust.IRIS.Core.Results;

/// <summary>
/// Result pattern minimalista. Evita exceptions em fluxos esperados de falha e força tratamento explícito.
/// </summary>
public readonly struct Result<T>
{
    public bool IsSuccess { get; }
    public T? Value { get; }
    public IrisError? Error { get; }
    public bool IsFailure => !IsSuccess;

    private Result(T value)
    {
        IsSuccess = true;
        Value = value;
        Error = null;
    }

    private Result(IrisError error)
    {
        IsSuccess = false;
        Value = default;
        Error = error;
    }

    public static Result<T> Ok(T value) => new(value);
    public static Result<T> Fail(IrisError error) => new(error);
    public static Result<T> Fail(IrisErrorCode code, string message, Exception? cause = null, string? hint = null)
        => new(new IrisError(code, message, hint, cause));

    public TOut Match<TOut>(Func<T, TOut> onSuccess, Func<IrisError, TOut> onFailure)
        => IsSuccess ? onSuccess(Value!) : onFailure(Error!);

    public Result<TOut> Map<TOut>(Func<T, TOut> map)
        => IsSuccess ? Result<TOut>.Ok(map(Value!)) : Result<TOut>.Fail(Error!);

    public async Task<Result<TOut>> MapAsync<TOut>(Func<T, Task<TOut>> map)
        => IsSuccess ? Result<TOut>.Ok(await map(Value!).ConfigureAwait(false)) : Result<TOut>.Fail(Error!);

    public Result<TOut> Bind<TOut>(Func<T, Result<TOut>> bind)
        => IsSuccess ? bind(Value!) : Result<TOut>.Fail(Error!);

    public async Task<Result<TOut>> BindAsync<TOut>(Func<T, Task<Result<TOut>>> bind)
        => IsSuccess ? await bind(Value!).ConfigureAwait(false) : Result<TOut>.Fail(Error!);
}

public static class Result
{
    public static Result<T> Ok<T>(T value) => Result<T>.Ok(value);
    public static Result<T> Fail<T>(IrisError error) => Result<T>.Fail(error);
    public static Result<T> Fail<T>(IrisErrorCode code, string message, Exception? cause = null, string? hint = null)
        => Result<T>.Fail(code, message, cause, hint);

    public static async Task<Result<T>> Try<T>(Func<Task<T>> action, IrisErrorCode fallback = IrisErrorCode.SysUnknown)
    {
        try
        {
            return Result<T>.Ok(await action().ConfigureAwait(false));
        }
        catch (IrisException ex)
        {
            return Result<T>.Fail(ex.Error);
        }
        catch (OperationCanceledException ex)
        {
            return Result<T>.Fail(IrisErrorCode.SysOperationCanceled, "Operação cancelada pelo usuário ou pelo sistema.", ex);
        }
        catch (Exception ex)
        {
            return Result<T>.Fail(fallback, ex.Message, ex);
        }
    }
}
