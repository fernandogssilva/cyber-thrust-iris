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

    public static RtrTerminalLine Info(string t)    => new() { Kind = RtrLineKind.Info,    Text = t, Fore = new SolidColorBrush(Color.FromRgb(0x8C, 0x9B, 0xC9)) };
    public static RtrTerminalLine Prompt(string t)  => new() { Kind = RtrLineKind.Prompt,  Text = t, Fore = new SolidColorBrush(Color.FromRgb(0x40, 0xE0, 0xFF)) };
    public static RtrTerminalLine Output(string t)  => new() { Kind = RtrLineKind.Output,  Text = t, Fore = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xFF)) };
    public static RtrTerminalLine Error(string t)   => new() { Kind = RtrLineKind.Error,   Text = t, Fore = new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52)) };
    public static RtrTerminalLine Success(string t) => new() { Kind = RtrLineKind.Success, Text = t, Fore = new SolidColorBrush(Color.FromRgb(0x00, 0xE6, 0x76)) };
    public static RtrTerminalLine Warn(string t)    => new() { Kind = RtrLineKind.Info,    Text = t, Fore = new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x40)) };
    public static RtrTerminalLine Blank()           => new() { Kind = RtrLineKind.Info,    Text = string.Empty, Fore = Brushes.Transparent };
}

// ─── ViewModel ───────────────────────────────────────────────────────────────
/// <summary>
/// Console RTR — terminal interativo + catálogo de 20 scripts CrowdStrike +
/// filtros de investigação (host / IP / domínio / hash / usuário / processo).
/// Zero-Storage: sessão efêmera em memória, nada gravado em disco.
/// </summary>
public partial class RtrConsoleViewModel : ViewModelBase
{
    private readonly IFalconClient             _falcon;
    private readonly INavigationService        _nav;
    private readonly AlertInvestigationContext _ctx;

    private RtrSessionInfo? _session;

    // ─── Terminal output ──────────────────────────────────────────────────────
    public ObservableCollection<RtrTerminalLine> Terminal { get; } = new();

    // ─── Session state ────────────────────────────────────────────────────────
    [ObservableProperty] private string  _aidInput        = string.Empty;
    [ObservableProperty] private string  _hostnameDisplay = string.Empty;
    [ObservableProperty] private bool    _isConnected;
    [ObservableProperty] private bool    _isNotConnected  = true;
    [ObservableProperty] private bool    _canConnect;
    [ObservableProperty] private string  _commandInput    = string.Empty;
    [ObservableProperty] private string  _statusLine      = "Desconectado.";

    // ─── Investigation filters ────────────────────────────────────────────────
    [ObservableProperty] private string _hostFilter    = string.Empty;
    [ObservableProperty] private string _ipFilter      = string.Empty;
    [ObservableProperty] private string _domainFilter  = string.Empty;
    [ObservableProperty] private string _hashFilter    = string.Empty;
    [ObservableProperty] private string _userFilter    = string.Empty;
    [ObservableProperty] private string _processFilter = string.Empty;
    [ObservableProperty] private bool   _isSearchingHost;
    [ObservableProperty] private string _hostSearchResult = string.Empty;

    // ─── Device profile card (preenchido ao conectar) ─────────────────────────
    [ObservableProperty] private DeviceProfile? _deviceProfile;
    [ObservableProperty] private bool _hasDeviceProfile;

    // ─── Script catalog exposed to XAML ─────────────────────────────────────
    public IReadOnlyList<RtrScript> ScriptsRecon       { get; } = RtrScriptCatalog.Reconhecimento;
    public IReadOnlyList<RtrScript> ScriptsPersistencia { get; } = RtrScriptCatalog.Persistencia;
    public IReadOnlyList<RtrScript> ScriptsUsuarios     { get; } = RtrScriptCatalog.Usuarios;
    public IReadOnlyList<RtrScript> ScriptsForense      { get; } = RtrScriptCatalog.Forense;
    public IReadOnlyList<RtrScript> ScriptsColeta       { get; } = RtrScriptCatalog.Coleta;

    // ─── Constructor ─────────────────────────────────────────────────────────
    public RtrConsoleViewModel(IFalconClient falcon, INavigationService nav, AlertInvestigationContext ctx)
    {
        _falcon = falcon;
        _nav    = nav;
        _ctx    = ctx;

        PrintBanner();

        if (ctx.HasContext)
        {
            AidInput        = ctx.Aid      ?? string.Empty;
            HostnameDisplay = ctx.Hostname ?? string.Empty;
            HostFilter      = ctx.Hostname ?? string.Empty;
            IpFilter        = ctx.IpAddress  ?? string.Empty;
            HashFilter      = ctx.Sha256     ?? ctx.Md5 ?? string.Empty;
            UserFilter      = ctx.UserName   ?? string.Empty;
            ProcessFilter   = ctx.ProcessName ?? string.Empty;
            DomainFilter    = ctx.Domain     ?? string.Empty;
            CanConnect      = !string.IsNullOrWhiteSpace(AidInput);

            if (CanConnect)
            {
                Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Contexto de investigação carregado."));
                Terminal.Add(RtrTerminalLine.Info($"       Host : {HostnameDisplay}"));
                Terminal.Add(RtrTerminalLine.Info($"       AID  : {AidInput}"));
                if (!string.IsNullOrWhiteSpace(ProcessFilter))
                    Terminal.Add(RtrTerminalLine.Info($"       Proc : {ProcessFilter}"));
                if (!string.IsNullOrWhiteSpace(HashFilter))
                    Terminal.Add(RtrTerminalLine.Info($"       Hash : {Abbr(HashFilter, 24)}"));
                if (!string.IsNullOrWhiteSpace(UserFilter))
                    Terminal.Add(RtrTerminalLine.Info($"       User : {UserFilter}"));
                if (!string.IsNullOrWhiteSpace(IpFilter))
                    Terminal.Add(RtrTerminalLine.Info($"       IP   : {IpFilter}"));
                Terminal.Add(RtrTerminalLine.Blank());
                _ = ConnectCommand.ExecuteAsync(null);
            }
        }
        else
        {
            Terminal.Add(RtrTerminalLine.Info("Preencha o AID ou busque pelo hostname no painel de filtros e clique Conectar."));
            Terminal.Add(RtrTerminalLine.Blank());
        }
    }

    // ─── Property change handlers ─────────────────────────────────────────────
    partial void OnAidInputChanged(string value)    => CanConnect = !string.IsNullOrWhiteSpace(value) && !IsConnected;
    partial void OnIsConnectedChanged(bool value)   { IsNotConnected = !value; CanConnect = !value && !string.IsNullOrWhiteSpace(AidInput); }

    // ─── Session: Connect / Disconnect ───────────────────────────────────────
    [RelayCommand]
    private async Task Connect()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid)) return;

        IsBusy = true; CanConnect = false;
        StatusLine = $"Iniciando sessão RTR em {Abbr(aid)}…";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Conectando → AID={Abbr(aid)}…"));

        try
        {
            var r = await _falcon.StartRtrSessionAsync(aid).ConfigureAwait(true);
            if (r.IsFailure)
            {
                Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ERRO: {r.Error}"));
                StatusLine = "Falha ao conectar."; return;
            }
            _session    = r.Value!;
            IsConnected = true;
            var host    = DisplayHost;
            StatusLine  = $"Sessão ativa — {host}  (expira {_session.ExpiresUtc.ToLocalTime():HH:mm:ss})";
            Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Sessão RTR estabelecida."));
            Terminal.Add(RtrTerminalLine.Info($"       Host      : {host}"));
            Terminal.Add(RtrTerminalLine.Info($"       SessionID : {Abbr(_session.SessionId, 16)}…"));
            Terminal.Add(RtrTerminalLine.Info($"       Expira em : {_session.ExpiresUtc.ToLocalTime():HH:mm:ss}"));
            Terminal.Add(RtrTerminalLine.Blank());

            // Fetch device profile em background — alimenta o sidebar card
            _ = FetchDeviceProfileAsync(aid);

            // Auto-executa script preferido (ex: process-tree quando vindo de "Investigar processo")
            if (!string.IsNullOrWhiteSpace(_ctx.PreferredRtrScriptId))
            {
                var preferred = RtrScriptCatalog.FindById(_ctx.PreferredRtrScriptId);
                _ctx.PreferredRtrScriptId = null; // one-shot
                if (preferred is not null)
                {
                    Terminal.Add(RtrTerminalLine.Info($"[{Ts}] 🎯 Auto-executando script da investigação: {preferred.Name}"));
                    Terminal.Add(RtrTerminalLine.Blank());
                    _ = RunScriptCommand.ExecuteAsync(preferred);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "RTR Connect exception");
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] Exceção: {ex.Message}"));
            StatusLine = "Erro inesperado.";
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private void Disconnect()
    {
        _session = null; IsConnected = false;
        DeviceProfile = null; HasDeviceProfile = false;
        StatusLine = "Sessão encerrada.";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Sessão RTR encerrada."));
        Terminal.Add(RtrTerminalLine.Blank());
    }

    private async Task FetchDeviceProfileAsync(string aid)
    {
        try
        {
            var r = await _falcon.GetDeviceProfileAsync(aid).ConfigureAwait(true);
            if (r.IsSuccess)
            {
                DeviceProfile    = r.Value;
                HasDeviceProfile = DeviceProfile is not null;
                if (HasDeviceProfile)
                    Terminal.Add(RtrTerminalLine.Info($"[{Ts}] ℹ  Device: {DeviceProfile!.Platform} {DeviceProfile.OsVersion} · {DeviceProfile.LocalIp} · agent {DeviceProfile.AgentVersion} · last_seen {DeviceProfile.LastSeenUtc.ToLocalTime():HH:mm:ss}"));
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "FetchDeviceProfile falhou para {Aid}", aid);
        }
    }

    // ─── Command execution ────────────────────────────────────────────────────
    [RelayCommand]
    private async Task Send()
    {
        var cmd = CommandInput.Trim();
        if (string.IsNullOrWhiteSpace(cmd) || _session is null) return;
        CommandInput = string.Empty;
        await ExecuteRawAsync(cmd).ConfigureAwait(true);
    }

    // ─── Script catalog execution ─────────────────────────────────────────────
    [RelayCommand]
    private async Task RunScript(RtrScript script)
    {
        if (_session is null)
        {
            Terminal.Add(RtrTerminalLine.Warn($"[{Ts}] Conecte primeiro ao endpoint antes de executar scripts."));
            Terminal.Add(RtrTerminalLine.Blank());
            return;
        }

        var cmd = BuildParameterizedCommand(script.CommandString);
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] ▶ Script: {script.Icon} {script.Name}"));
        if (script.Risk == RtrScriptRisk.High)
            Terminal.Add(RtrTerminalLine.Warn($"       ⚠  Risco ALTO — alterações no sistema são possíveis."));
        Terminal.Add(RtrTerminalLine.Blank());
        await ExecuteRawAsync(cmd, script.BaseCommand).ConfigureAwait(true);
    }

    // ─── Quick shortcut (legacy toolbar) ─────────────────────────────────────
    [RelayCommand]
    private void QuickCommand(string cmd)
    {
        CommandInput = cmd;
        if (IsConnected) _ = SendCommand.ExecuteAsync(null);
    }

    // ─── Investigation filters: Host lookup ───────────────────────────────────
    [RelayCommand]
    private async Task SearchHost()
    {
        var q = HostFilter.Trim();
        if (string.IsNullOrWhiteSpace(q)) return;

        IsSearchingHost   = true;
        HostSearchResult  = string.Empty;
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] 🔍 Buscando host: '{q}'…"));

        var r = await _falcon.SearchHostsAsync($"hostname:'{q}'").ConfigureAwait(true);
        IsSearchingHost = false;

        if (r.IsFailure)
        {
            HostSearchResult = $"Erro: {r.Error}";
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] Falha na busca: {r.Error}"));
            return;
        }

        var hosts = r.Value!;
        if (hosts.Count == 0)
        {
            HostSearchResult = "Nenhum host encontrado.";
            Terminal.Add(RtrTerminalLine.Warn($"[{Ts}] Nenhum host encontrado para '{q}'."));
            return;
        }

        var h = hosts[0];
        AidInput        = h.Aid ?? string.Empty;
        HostnameDisplay = h.Hostname ?? string.Empty;
        HostSearchResult = $"✅ {h.Hostname} → {Abbr(h.Aid ?? "", 16)}";
        Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Host encontrado: {h.Hostname}  |  AID={Abbr(h.Aid ?? "", 16)}"));
        if (hosts.Count > 1)
            Terminal.Add(RtrTerminalLine.Info($"       (+{hosts.Count - 1} outros hosts com nome similar)"));
        Terminal.Add(RtrTerminalLine.Blank());
    }

    // ─── Host containment ─────────────────────────────────────────────────────
    [RelayCommand]
    private async Task ContainHost()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid)) { Terminal.Add(RtrTerminalLine.Error($"[{Ts}] AID não preenchido.")); return; }
        IsBusy = true; StatusLine = "Isolando host…";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Iniciando Network Containment em {Abbr(aid)}…"));
        var r = await _falcon.ContainHostAsync(aid).ConfigureAwait(true);
        IsBusy = false;
        if (r.IsSuccess) { Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Host '{DisplayHost}' isolado. Tráfego externo bloqueado.")); StatusLine = "Host isolado."; }
        else             { Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Falha: {r.Error}")); StatusLine = "Falha ao isolar."; }
        Terminal.Add(RtrTerminalLine.Blank());
    }

    [RelayCommand]
    private async Task LiftContainment()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid)) { Terminal.Add(RtrTerminalLine.Error($"[{Ts}] AID não preenchido.")); return; }
        IsBusy = true; StatusLine = "Levantando contenção…";
        Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Levantando Network Containment de {Abbr(aid)}…"));
        var r = await _falcon.LiftContainmentAsync(aid).ConfigureAwait(true);
        IsBusy = false;
        if (r.IsSuccess) { Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Contenção levantada — '{DisplayHost}' reintegrado à rede.")); StatusLine = "Contenção levantada."; }
        else             { Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Falha: {r.Error}")); StatusLine = "Falha ao levantar."; }
        Terminal.Add(RtrTerminalLine.Blank());
    }

    // ─── Terminal management ──────────────────────────────────────────────────
    [RelayCommand] private void ClearTerminal() { Terminal.Clear(); PrintBanner(); }
    [RelayCommand] private void BackToAlerts()  => _nav.NavigateTo("alerts");

    // ─── Internal: execute any raw command ───────────────────────────────────
    private async Task ExecuteRawAsync(string cmd, string? baseOverride = null)
    {
        if (_session is null) return;
        var host    = DisplayHost;
        var baseCm  = baseOverride ?? cmd.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[0].ToLowerInvariant();
        Terminal.Add(RtrTerminalLine.Prompt($"PS {host}> {(cmd.Length > 120 ? cmd[..120] + "…" : cmd)}"));
        IsBusy = true; StatusLine = $"Executando: {baseCm}…";
        try
        {
            var r = await _falcon.ExecuteRtrAsync(_session.SessionId, baseCm, cmd).ConfigureAwait(true);
            if (r.IsFailure)
            {
                Terminal.Add(RtrTerminalLine.Error($"Erro de API: {r.Error}"));
            }
            else
            {
                var res = r.Value!;
                if (!string.IsNullOrWhiteSpace(res.Stdout))
                    foreach (var ln in res.Stdout.Split('\n'))
                        Terminal.Add(RtrTerminalLine.Output(ln.TrimEnd('\r')));
                if (!string.IsNullOrWhiteSpace(res.Stderr))
                    foreach (var ln in res.Stderr.Split('\n'))
                        Terminal.Add(RtrTerminalLine.Error(ln.TrimEnd('\r')));
                if (!res.Complete)
                    Terminal.Add(RtrTerminalLine.Warn("(Tarefa assíncrona — conclusão em background)"));
                if (res.ExitCode.HasValue && res.ExitCode != 0)
                    Terminal.Add(RtrTerminalLine.Info($"Exit code: {res.ExitCode}"));
            }
        }
        catch (Exception ex) { Log.Error(ex, "RTR Send exception"); Terminal.Add(RtrTerminalLine.Error($"Exceção: {ex.Message}")); }
        finally { IsBusy = false; StatusLine = IsConnected ? $"Pronto — {host}" : "Desconectado."; }
        Terminal.Add(RtrTerminalLine.Blank());
    }

    // ─── Parameter substitution (filtros → comandos) ─────────────────────────
    private string BuildParameterizedCommand(string template)
    {
        return template
            .Replace("{HOST}",    HostFilter.Trim())
            .Replace("{IP}",      IpFilter.Trim())
            .Replace("{DOMAIN}",  DomainFilter.Trim())
            .Replace("{HASH}",    HashFilter.Trim())
            .Replace("{USER}",    UserFilter.Trim())
            .Replace("{PROCESS}", ProcessFilter.Trim());
    }

    // ─── Banner ───────────────────────────────────────────────────────────────
    private void PrintBanner()
    {
        Terminal.Add(RtrTerminalLine.Info("╔══════════════════════════════════════════════════════════════╗"));
        Terminal.Add(RtrTerminalLine.Info("║  CyberThrust.IRIS — Falcon Real-Time Response (RTR)          ║"));
        Terminal.Add(RtrTerminalLine.Info("║  20 scripts CrowdStrike · Filtros de investigação            ║"));
        Terminal.Add(RtrTerminalLine.Info("║  Zero-Storage: sessão efêmera, nada gravado em disco         ║"));
        Terminal.Add(RtrTerminalLine.Info("╚══════════════════════════════════════════════════════════════╝"));
        Terminal.Add(RtrTerminalLine.Blank());
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private string DisplayHost =>
        string.IsNullOrWhiteSpace(HostnameDisplay) ? Abbr(AidInput) : HostnameDisplay;

    private static string Abbr(string s, int max = 12) =>
        string.IsNullOrEmpty(s) ? "?" : (s.Length > max ? s[..max] + "…" : s);

    private static string Ts => DateTime.Now.ToString("HH:mm:ss");
}
