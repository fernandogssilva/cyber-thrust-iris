using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

// ─── Terminal line model ──────────────────────────────────────────────────────
public enum RtrLineKind { Info, Prompt, Output, Error, Success }

public sealed class RtrTerminalLine
{
    public RtrLineKind Kind   { get; init; }
    public string      Text   { get; init; } = string.Empty;
    public Brush       Fore   { get; init; } = Brushes.White;

    // Static factories keep construction uniform
    public static RtrTerminalLine Info(string t)    => new() { Kind = RtrLineKind.Info,    Text = t, Fore = new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9)) };
    public static RtrTerminalLine Prompt(string t)  => new() { Kind = RtrLineKind.Prompt,  Text = t, Fore = new SolidColorBrush(Color.FromRgb(0x40, 0xE0, 0xFF)) };
    public static RtrTerminalLine Output(string t)  => new() { Kind = RtrLineKind.Output,  Text = t, Fore = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xFF)) };
    public static RtrTerminalLine Error(string t)   => new() { Kind = RtrLineKind.Error,   Text = t, Fore = new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)) };
    public static RtrTerminalLine Success(string t) => new() { Kind = RtrLineKind.Success, Text = t, Fore = new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76)) };
    public static RtrTerminalLine Blank()           => new() { Kind = RtrLineKind.Info,    Text = string.Empty, Fore = Brushes.Transparent };
}

// ─── ViewModel ───────────────────────────────────────────────────────────────
/// <summary>
/// Console RTR (Real-Time Response) — shell interativo contra 1 endpoint via Falcon.
/// Zero-Storage: nenhum dado é persistido em disco, toda interação é efêmera em memória.
/// </summary>
public partial class RtrConsoleViewModel : ViewModelBase
{
    private readonly IFalconClient          _falcon;
    private readonly INavigationService     _nav;
    private readonly AlertInvestigationContext _ctx;

    private RtrSessionInfo? _session;

    // ─── Observable state ────────────────────────────────────────────────────
    [ObservableProperty] private string  _aidInput       = string.Empty;
    [ObservableProperty] private string  _hostnameDisplay = string.Empty;
    [ObservableProperty] private bool    _isConnected;
    [ObservableProperty] private bool    _isNotConnected  = true;
    [ObservableProperty] private bool    _canConnect;
    [ObservableProperty] private string  _commandInput   = string.Empty;
    [ObservableProperty] private string  _statusLine     = "Desconectado — informe o AID e clique Conectar.";

    public ObservableCollection<RtrTerminalLine> Terminal { get; } = new();

    // ─── Constructor ─────────────────────────────────────────────────────────
    public RtrConsoleViewModel(IFalconClient falcon, INavigationService nav, AlertInvestigationContext ctx)
    {
        _falcon = falcon;
        _nav    = nav;
        _ctx    = ctx;

        PrintBanner();

        // Pre-fill from investigation context (navigated from Detecções panel)
        if (ctx.HasContext)
        {
            AidInput        = ctx.Aid       ?? string.Empty;
            HostnameDisplay = ctx.Hostname  ?? string.Empty;
            CanConnect      = true;

            if (!string.IsNullOrWhiteSpace(AidInput))
            {
                Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Contexto de investigação carregado."));
                Terminal.Add(RtrTerminalLine.Info($"       Hostname : {HostnameDisplay}"));
                Terminal.Add(RtrTerminalLine.Info($"       AID      : {AidInput}"));
                Terminal.Add(RtrTerminalLine.Blank());

                // Auto-connect when arriving from an alert
                _ = ConnectCommand.ExecuteAsync(null);
            }
        }
        else
        {
            Terminal.Add(RtrTerminalLine.Info("Informe o AID do endpoint-alvo e clique Conectar."));
            Terminal.Add(RtrTerminalLine.Blank());
        }
    }

    // ─── Property change handlers ─────────────────────────────────────────────
    partial void OnAidInputChanged(string value)
    {
        CanConnect = !string.IsNullOrWhiteSpace(value) && !IsConnected;
    }

    partial void OnIsConnectedChanged(bool value)
    {
        IsNotConnected = !value;
        CanConnect     = !value && !string.IsNullOrWhiteSpace(AidInput);
    }

    // ─── Connect / Disconnect ─────────────────────────────────────────────────
    [RelayCommand]
    private async Task Connect()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid)) return;

        IsBusy     = true;
        CanConnect = false;
        StatusLine = $"Iniciando sessão RTR em {Abbreviate(aid)}…";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Conectando ao endpoint AID={Abbreviate(aid)}…"));

        try
        {
            var r = await _falcon.StartRtrSessionAsync(aid).ConfigureAwait(true);

            if (r.IsFailure)
            {
                Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ERRO ao iniciar sessão: {r.Error}"));
                StatusLine = "Falha ao conectar.";
                Log.Warning("RTR Connect failed: {Error}", r.Error);
                return;
            }

            _session        = r.Value!;
            IsConnected     = true;
            var host        = DisplayHost;
            StatusLine      = $"Sessão ativa — {host}  (expira {_session.ExpiresUtc.ToLocalTime():HH:mm:ss})";

            Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Sessão RTR estabelecida."));
            Terminal.Add(RtrTerminalLine.Info($"       SessionID : {Abbreviate(_session.SessionId, 16)}…"));
            Terminal.Add(RtrTerminalLine.Info($"       Host      : {host}"));
            Terminal.Add(RtrTerminalLine.Info($"       Expira em : {_session.ExpiresUtc.ToLocalTime():HH:mm:ss}"));
            Terminal.Add(RtrTerminalLine.Blank());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "RTR Connect exception");
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] Exceção: {ex.Message}"));
            StatusLine = "Erro inesperado.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void Disconnect()
    {
        _session    = null;
        IsConnected = false;
        StatusLine  = "Sessão encerrada.";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Sessão RTR encerrada pelo analista."));
        Terminal.Add(RtrTerminalLine.Blank());
    }

    // ─── Command execution ────────────────────────────────────────────────────
    [RelayCommand]
    private async Task Send()
    {
        var cmd = CommandInput.Trim();
        if (string.IsNullOrWhiteSpace(cmd) || _session is null) return;

        CommandInput = string.Empty;

        Terminal.Add(RtrTerminalLine.Prompt($"PS {DisplayHost}> {cmd}"));

        // Parse base command (first whitespace-separated token)
        var baseCmd = cmd.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[0].ToLowerInvariant();

        IsBusy     = true;
        StatusLine = $"Executando: {cmd}";

        try
        {
            var r = await _falcon.ExecuteRtrAsync(_session.SessionId, baseCmd, cmd).ConfigureAwait(true);

            if (r.IsFailure)
            {
                Terminal.Add(RtrTerminalLine.Error($"Erro de API: {r.Error}"));
                Log.Warning("RTR SendCommand failed: {Error}", r.Error);
            }
            else
            {
                var result = r.Value!;

                if (!string.IsNullOrWhiteSpace(result.Stdout))
                    foreach (var line in result.Stdout.Split('\n'))
                        Terminal.Add(RtrTerminalLine.Output(line.TrimEnd('\r')));

                if (!string.IsNullOrWhiteSpace(result.Stderr))
                    foreach (var line in result.Stderr.Split('\n'))
                        Terminal.Add(RtrTerminalLine.Error(line.TrimEnd('\r')));

                if (!result.Complete)
                    Terminal.Add(RtrTerminalLine.Info("(Tarefa assíncrona — aguardando conclusão em background)"));

                if (result.ExitCode.HasValue && result.ExitCode != 0)
                    Terminal.Add(RtrTerminalLine.Info($"Exit code: {result.ExitCode}"));
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "RTR Send exception");
            Terminal.Add(RtrTerminalLine.Error($"Exceção local: {ex.Message}"));
        }
        finally
        {
            IsBusy     = false;
            StatusLine = IsConnected ? $"Pronto — {DisplayHost}" : "Desconectado.";
        }

        Terminal.Add(RtrTerminalLine.Blank());
    }

    // ─── Quick commands ───────────────────────────────────────────────────────
    [RelayCommand]
    private void QuickCommand(string cmd)
    {
        CommandInput = cmd;
        if (IsConnected)
            _ = SendCommand.ExecuteAsync(null);
    }

    // ─── Host containment ─────────────────────────────────────────────────────
    [RelayCommand]
    private async Task ContainHost()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid))
        {
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] AID não preenchido. Informe o AID antes de conter."));
            return;
        }

        IsBusy     = true;
        StatusLine = "Isolando host via Network Containment…";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Iniciando Network Containment em {Abbreviate(aid)}…"));

        var r = await _falcon.ContainHostAsync(aid).ConfigureAwait(true);
        IsBusy = false;

        if (r.IsSuccess)
        {
            Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Host '{DisplayHost}' isolado com sucesso."));
            Terminal.Add(RtrTerminalLine.Info("       Todo tráfego de rede externo foi bloqueado."));
            StatusLine = "Host isolado.";
        }
        else
        {
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Falha ao isolar: {r.Error}"));
            StatusLine = "Falha ao isolar host.";
        }
        Terminal.Add(RtrTerminalLine.Blank());
    }

    [RelayCommand]
    private async Task LiftContainment()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid))
        {
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] AID não preenchido."));
            return;
        }

        IsBusy     = true;
        StatusLine = "Levantando contenção…";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Levantando Network Containment de {Abbreviate(aid)}…"));

        var r = await _falcon.LiftContainmentAsync(aid).ConfigureAwait(true);
        IsBusy = false;

        if (r.IsSuccess)
        {
            Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Contenção levantada — '{DisplayHost}' reintegrado à rede."));
            StatusLine = "Contenção levantada.";
        }
        else
        {
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Falha: {r.Error}"));
            StatusLine = "Falha ao levantar contenção.";
        }
        Terminal.Add(RtrTerminalLine.Blank());
    }

    // ─── Terminal management ──────────────────────────────────────────────────
    [RelayCommand]
    private void ClearTerminal()
    {
        Terminal.Clear();
        PrintBanner();
    }

    [RelayCommand]
    private void BackToAlerts() => _nav.NavigateTo("alerts");

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private void PrintBanner()
    {
        Terminal.Add(RtrTerminalLine.Info("╔══════════════════════════════════════════════════════════════╗"));
        Terminal.Add(RtrTerminalLine.Info("║  CyberThrust.IRIS — Falcon Real-Time Response (RTR)          ║"));
        Terminal.Add(RtrTerminalLine.Info("║  Zero-Storage: sessão efêmera, nada gravado em disco         ║"));
        Terminal.Add(RtrTerminalLine.Info("╚══════════════════════════════════════════════════════════════╝"));
        Terminal.Add(RtrTerminalLine.Blank());
    }

    private string DisplayHost =>
        string.IsNullOrWhiteSpace(HostnameDisplay) ? Abbreviate(AidInput) : HostnameDisplay;

    private static string Abbreviate(string s, int max = 12) =>
        string.IsNullOrEmpty(s) ? "?" : (s.Length > max ? s[..max] + "…" : s);

    private static string Ts => DateTime.Now.ToString("HH:mm:ss");
}
