using Serilog;
using Serilog.Events;

namespace CyberThrust.IRIS.Core.Logging;

/// <summary>Configura Serilog com sinks de Console (debug), Debug e File (rolling diário).</summary>
public static class SerilogBuilder
{
    public static ILogger Build(string appName, string logsFolder, LogEventLevel minLevel = LogEventLevel.Information)
    {
        Directory.CreateDirectory(logsFolder);
        var logPath = Path.Combine(logsFolder, $"{appName}-.log");

        return new LoggerConfiguration()
            .MinimumLevel.Is(minLevel)
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("System.Net.Http", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithMachineName()
            .Enrich.WithThreadId()
            .Enrich.WithProperty("App", appName)
            .WriteTo.Debug()
            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
            .WriteTo.File(
                path: logPath,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                fileSizeLimitBytes: 50_000_000,
                rollOnFileSizeLimit: true,
                shared: true,
                flushToDiskInterval: TimeSpan.FromMilliseconds(500),
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{ThreadId}] {Message:lj} {Properties:j}{NewLine}{Exception}")
            .CreateLogger();
    }
}
