using CyberThrust.IRIS.Core.Errors;
using FluentAssertions;
using Xunit;

namespace CyberThrust.IRIS.Tests;

public class ErrorCodeTests
{
    [Theory]
    [InlineData(IrisErrorCode.AuthEntraInteractiveFailed, "AUTH", "IRIS-AUTH-1001")]
    [InlineData(IrisErrorCode.CsApiRateLimited, "CS", "IRIS-CS-2012")]
    [InlineData(IrisErrorCode.MemXmemdumpFailed, "MEM", "IRIS-MEM-3002")]
    [InlineData(IrisErrorCode.DskKapeExecutionFailed, "DSK", "IRIS-DSK-4002")]
    [InlineData(IrisErrorCode.SysUnknown, "SYS", "IRIS-SYS-9000")]
    public void Categories_and_string_format_match(IrisErrorCode code, string cat, string str)
    {
        code.Category().Should().Be(cat);
        code.ToCodeString().Should().Be(str);
    }

    [Theory]
    [InlineData(IrisErrorCode.CsApiRateLimited, true)]
    [InlineData(IrisErrorCode.CsApiServerError, true)]
    [InlineData(IrisErrorCode.CsRtrCommandTimeout, true)]
    [InlineData(IrisErrorCode.AuthEntraInteractiveFailed, false)]
    [InlineData(IrisErrorCode.DskKapeMissing, false)]
    public void Transient_flag_works(IrisErrorCode code, bool expected)
        => code.IsTransient().Should().Be(expected);
}
