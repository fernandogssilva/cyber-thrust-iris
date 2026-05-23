using System.IO;
using System.Windows;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.App.ViewModels;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Logging;
using CyberThrust.IRIS.CrowdStrike.Api;
using CyberThrust.IRIS.EntraID;
using CyberThrust.IRIS.Forensics.Kape;
using CyberThrust.IRIS.Forensics.Uac;
using CyberThrust.IRIS.Forensics.Velociraptor;
using CyberThrust.IRIS.Graph;
using CyberThrust.IRIS.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Extensions.Logging;

namespace CyberThrust.IRIS.App;

public partial class App : Application
{
    public static IHost? Host { get; private set; }
    public static IServiceProvider Services => Host!.Services;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var logFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberThrust", "IRIS", "logs");
        Log.Logger = SerilogBuilder.Build("iris", logFolder, LogEventLevel.Information);

        try
        {
            Host = Microsoft.Extensions.Hosting.Host.CreateDefaultBuilder()
                .ConfigureAppConfiguration((_, cfg) =>
                {
                    cfg.SetBasePath(AppContext.BaseDirectory);
                    cfg.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                    cfg.AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: true);
                })
                .ConfigureServices((ctx, services) =>
                {
                    services.Configure<EntraOptions>(ctx.Configuration.GetSection(EntraOptions.SectionName));
                    services.Configure<FalconOptions>(ctx.Configuration.GetSection(FalconOptions.SectionName));

                    services.AddSingleton(sp => sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<EntraOptions>>().Value);
                    services.AddSingleton(sp => sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<FalconOptions>>().Value);

                    services.AddSingleton<IAuthenticator, EntraAuthenticator>();

                    services.AddSingleton<FalconAuthHandler>(sp => new FalconAuthHandler(sp.GetRequiredService<FalconOptions>()));
                    services.AddHttpClient<FalconCapabilityProbe>((sp, c) =>
                    {
                        var opt = sp.GetRequiredService<FalconOptions>();
                        c.BaseAddress = new Uri(opt.BaseUrl);
                        c.Timeout = TimeSpan.FromSeconds(opt.HttpTimeoutSeconds);
                    }).AddHttpMessageHandler<FalconAuthHandler>();

                    services.AddHttpClient<FalconClient>((sp, c) =>
                    {
                        var opt = sp.GetRequiredService<FalconOptions>();
                        c.BaseAddress = new Uri(opt.BaseUrl);
                        c.Timeout = TimeSpan.FromSeconds(opt.HttpTimeoutSeconds);
                    }).AddHttpMessageHandler<FalconAuthHandler>();

                    services.AddSingleton<IFalconClient>(sp => sp.GetRequiredService<FalconClient>());

                    services.AddSingleton<KapeOrchestrator>();
                    services.AddSingleton<VelociraptorOrchestrator>();
                    services.AddSingleton<UacOrchestrator>();
                    services.AddSingleton<MemoryCollector>();
                    services.AddSingleton<AttackGraphBuilder>();
                    services.AddSingleton<IGraphProvider>(sp => sp.GetRequiredService<AttackGraphBuilder>());

                    services.AddSingleton<INavigationService, NavigationService>();
                    services.AddSingleton<HealthCheckService>();

                    services.AddTransient<MainViewModel>();
                    services.AddTransient<LoginViewModel>();
                    services.AddTransient<DashboardViewModel>();
                    services.AddTransient<HealthCheckViewModel>();
                    services.AddTransient<AttackTreeViewModel>();
                    services.AddTransient<IncidentsViewModel>();
                    services.AddTransient<RtrConsoleViewModel>();
                    services.AddTransient<ForensicsViewModel>();
                    services.AddTransient<MemoryViewModel>();
                    services.AddTransient<SettingsViewModel>();

                    services.AddLogging(b => b.ClearProviders().AddProvider(new SerilogLoggerProvider(Log.Logger)));
                })
                .Build();

            await Host.StartAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Falha fatal no bootstrap.");
            MessageBox.Show($"Falha ao inicializar.\n\n{ex.Message}", "CyberThrust.IRIS — Erro fatal", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        try
        {
            if (Host is not null)
            {
                await Host.StopAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
                Host.Dispose();
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Falha ao parar host.");
        }
        finally
        {
            await Log.CloseAndFlushAsync().ConfigureAwait(true);
            base.OnExit(e);
        }
    }
}
