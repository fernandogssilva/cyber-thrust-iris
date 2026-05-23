using CyberThrust.IRIS.Core.Errors;
using CyberThrust.IRIS.Core.Results;
using FluentAssertions;
using Xunit;

namespace CyberThrust.IRIS.Tests;

public class ResultTests
{
    [Fact]
    public void Ok_holds_value()
    {
        var r = Result<int>.Ok(42);
        r.IsSuccess.Should().BeTrue();
        r.Value.Should().Be(42);
        r.Error.Should().BeNull();
    }

    [Fact]
    public void Fail_holds_error()
    {
        var r = Result<int>.Fail(IrisErrorCode.SysUnknown, "boom");
        r.IsFailure.Should().BeTrue();
        r.Error!.CodeString.Should().Be("IRIS-SYS-9000");
    }

    [Fact]
    public async Task Try_wraps_exception_into_failure()
    {
        var r = await Result.Try<int>(() => throw new InvalidOperationException("nope"));
        r.IsFailure.Should().BeTrue();
        r.Error!.Code.Should().Be(IrisErrorCode.SysUnknown);
    }
}
