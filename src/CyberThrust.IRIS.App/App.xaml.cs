using System.IO;
using System.Windows;
using System.Windows.Threading;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.App.ViewModels;
using CyberThrust.IRIS.App.Views;
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

    private static readonly string CrashLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CyberThrust", "IRIS", "logs", "crash.log");

    /// <summary>Escreve qualquer falha catastrófica num arquivo simples, antes do Serilog estar pronto.</summary>
    private static void RawCrash(string stage, Exception? ex)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CrashLogPath)!);
            var msg = $"[{DateTimeOffset.UtcNow:O}] STAGE={stage}\n{ex}\n---\n";
            File.AppendAllText(CrashLogPath, msg);
        }
        catch { /* nada a fazer — não pode falhar dentro do handler de falha */ }
    }

    public App()
    {
        // Handlers globais — capturam exceções que escapam do try/catch do OnStartup.
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            RawCrash("AppDomain.UnhandledException", e.ExceptionObject as Exception);
            TryShowFatalMessage((e.ExceptionObject as Exception)?.Message ?? "Erro desconhecido (AppDomain)");
        };
        DispatcherUnhandledException += (s, e) =>
        {
            RawCrash("Dispatcher.UnhandledException", e.Exception);
            TryShowFatalMessage(e.Exception.Message);
            e.Handled = true;
        };
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
        {
            RawCrash("TaskScheduler.UnobservedTaskException", e.Exception);
            e.SetObserved();
        };
    }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        SplashWindow? splash = null;
        try
        {
            splash = new SplashWindow();
            splash.Show();
            splash.Report("Preparando logs…");
        }
        catch (Exception ex)
        {
            RawCrash("SplashWindow ctor/Show", ex);
            TryShowFatalMessage("Falha na splash screen: " + ex.Message);
            Shutdown(1);
            return;
        }

        try
        {
            var logFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberThrust", "IRIS", "logs");
            Log.Logger = SerilogBuilder.Build("iris", logFolder, LogEventLevel.Information);
            Log.Information("IRIS booting — BaseDirectory={BaseDir}", AppContext.BaseDirectory);
        }
        catch (Exception ex)
        {
            RawCrash("SerilogBuilder.Build", ex);
            splash?.Close();
            TryShowFatalMessage("Falha ao inicializar logs: " + ex.Message);
            Shutdown(1);
            return;
        }

        try
        {
            splash.Report("Carregando configuração…");
            Host = Microsoft.Extensions.Hosting.Host.CreateDefaultBuilder()
                .ConfigureAppConfiguration((_, cfg) =>
                {
                    cfg.SetBasePath(AppContext.BaseDirectory);
                    cfg.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
                    cfg.AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: false);
                })
                .ConfigureServices((ctx, services) =>
                {
                    services.Configure<EntraOptions>(ctx.Configuration.GetSection(EntraOptions.SectionName));
                    services.Configure<FalconOptions>(ctx.Configuration.GetSection(FalconOptions.SectionName));

                    services.AddSingleton(sp => sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<EntraOptions>>().Value);
                    services.AddSingleton(sp => sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<FalconOptions>>().Value);

                    // Lazy-resolvable: evita crash de bootstrap quando placeholder ClientId está no appsettings.json
                    services.AddSingleton<IAuthenticator>(sp =>
                    {
                        try
                        {
                            return new EntraAuthenticator(
                                sp.GetRequiredService<EntraOptions>(),
                                sp.GetRequiredService<ILogger<EntraAuthenticator>>());
                        }
                        catch (CyberThrust.IRIS.Core.Errors.IrisException ex)
                        {
                            // Erro esperado de configuração — NÃO é crash. Vai pro Serilog warning.
                            Log.Warning("EntraAuthenticator não inicializado ({Code}): {Message}", ex.Error.CodeString, ex.Error.Message);
                            return new NullAuthenticator(ex.Error.Message);
                        }
                        catch (Exception ex)
                        {
                            // Erro INESPERADO — vai pro crash.log para análise.
                            RawCrash("EntraAuthenticator ctor (unexpected)", ex);
                            return new NullAuthenticator(ex.Message);
                        }
                    });

                    // HttpClientFactory exige TRANSIENT para DelegatingHandlers (cada client recebe instância nova).
                    // Cache de token OAuth2 fica isolado por client; trade-off aceitável até refator do v0.3 com FalconTokenProvider singleton.
                    services.AddTransient<FalconAuthHandler>(sp => new FalconAuthHandler(sp.GetRequiredService<FalconOptions>()));
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

            splash.Report("Iniciando host e DI…");
            await Host.StartAsync().ConfigureAwait(true);
            Log.Information("Host iniciado.");

            splash.Report("Abrindo janela principal…");
            try
            {
                var main = new MainWindow();
                MainWindow = main;
                main.Show();
                Log.Information("MainWindow exibida.");
                Log.Logger.Verbose("Flush forçado para garantir presença no log.");
            }
            catch (Exception ex)
            {
                RawCrash("MainWindow create/show", ex);
                Log.Fatal(ex, "Falha ao criar MainWindow.");
                TryShowFatalMessage($"Falha ao abrir janela principal.\n\n[IRIS-UI-6004] {ex.GetType().Name}: {ex.Message}");
                Shutdown(1);
                return;
            }

            splash.Close();
        }
        catch (Exception ex)
        {
            RawCrash("Host build/start", ex);
            try { Log.Fatal(ex, "Falha fatal no bootstrap."); } catch { }
            try { splash?.Close(); } catch { }
            TryShowFatalMessage($"Falha ao inicializar.\n\n[IRIS-SYS-9000] {ex.GetType().Name}: {ex.Message}");
            Shutdown(1);
        }
    }

    private static void TryShowFatalMessage(string message)
    {
        try
        {
            MessageBox.Show(
                message + "\n\nDetalhes salvos em:\n" + CrashLogPath,
                "CyberThrust.IRIS — Erro fatal",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch { /* sem UI possível */ }
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
            try { Log.Warning(ex, "Falha ao parar host."); } catch { }
        }
        finally
        {
            try { await Log.CloseAndFlushAsync().ConfigureAwait(true); } catch { }
            base.OnExit(e);
        }
    }
}

/// <summary>Fallback authenticator quando a configuração Entra falha — não trava o app, mas reporta erro claro.</summary>
internal sealed class NullAuthenticator : IAuthenticator
{
    private readonly string _reason;
    public NullAuthenticator(string reason) => _reason = reason;
    public bool IsAuthenticated => false;
    public Task<Core.Results.Result<Core.Models.IrisIdentity>> SignInInteractiveAsync(CancellationToken ct = default)
        => Task.FromResult(Core.Results.Result<Core.Models.IrisIdentity>.Fail(Core.Errors.IrisErrorCode.CfgEntraSectionInvalid, _reason));
    public Task<Core.Results.Result<Core.Models.IrisIdentity>> SignInSilentAsync(CancellationToken ct = default)
        => Task.FromResult(Core.Results.Result<Core.Models.IrisIdentity>.Fail(Core.Errors.IrisErrorCode.CfgEntraSectionInvalid, _reason));
    public Task<Core.Results.Result<bool>> SignOutAsync(CancellationToken ct = default)
        => Task.FromResult(Core.Results.Result<bool>.Ok(true));
    public Task<Core.Results.Result<string>> GetAccessTokenAsync(IEnumerable<string> scopes, CancellationToken ct = default)
        => Task.FromResult(Core.Results.Result<string>.Fail(Core.Errors.IrisErrorCode.CfgEntraSectionInvalid, _reason));
}
