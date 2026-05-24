using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

// ─── ViewModel ───────────────────────────────────────────────────────────────
/// <summary>
/// Coleta forense de disco via Falcon RTR.
/// Ferramentas: KAPE (Kroll), Velociraptor (Velocidex), UAC (IR Ninja).
/// Zero-Storage: artefatos coletados no endpoint, não localmente.
/// </summary>
public partial class ForensicsViewModel : ViewModelBase
{
    private readonly IFalconClient             _falcon;
    private readonly INavigationService        _nav;
    private readonly AlertInvestigationContext _ctx;

    private RtrSessionInfo? _session;

    // ─── Terminal ─────────────────────────────────────────────────────────────
    public ObservableCollection<RtrTerminalLine> Terminal { get; } = new();

    // ─── State ───────────────────────────────────────────────────────────────
    [ObservableProperty] private string           _aidInput        = string.Empty;
    [ObservableProperty] private string           _hostnameDisplay = string.Empty;
    [ObservableProperty] private bool             _isConnected;
    [ObservableProperty] private bool             _isNotConnected  = true;
    [ObservableProperty] private bool             _canRun;
    [ObservableProperty] private string           _statusLine      = "Aguardando configuração.";
    [ObservableProperty] private ForensicsToolKind _selectedTool   = ForensicsToolKind.Kape;
    [ObservableProperty] private bool             _collectEvents   = true;
    [ObservableProperty] private bool             _collectRegistry = true;
    [ObservableProperty] private bool             _collectPrefetch = true;
    [ObservableProperty] private bool             _collectBrowser  = true;
    [ObservableProperty] private bool             _collectSystem   = true;
    [ObservableProperty] private bool             _collectNetwork  = false;
    [ObservableProperty] private bool             _collectFull     = false;
    [ObservableProperty] private bool             _collectComplete;
    [ObservableProperty] private string           _outputPath      = string.Empty;

    // Tool descriptions
    public string KapeDesc  => "KAPE — Kroll Artifact Parser and Extractor.\nColeta rápida de artefatos (triage) com alvos configuráveis.\nRequerido: put kape.exe no endpoint via Console RTR.\nSrc: kroll.com/kape";
    public string VeloDesc  => "Velociraptor — plataforma open source de DFIR.\nHunts de alta performance com VQL.\nRequerido: put velociraptor.exe no endpoint.\nSrc: github.com/Velocidex/velociraptor";
    public string UacDesc   => "UAC (Unix-Artifact-Collector) — ferramenta IR portátil.\nColeta artifacts em endpoints Windows/Linux.\nRequerido: put uac no endpoint.\nSrc: github.com/tclahr/uac";

    // ─── Constructor ─────────────────────────────────────────────────────────
    public ForensicsViewModel(IFalconClient falcon, INavigationService nav, AlertInvestigationContext ctx)
    {
        _falcon = falcon;
        _nav    = nav;
        _ctx    = ctx;

        PrintBanner();

        if (ctx.HasContext)
        {
            AidInput        = ctx.Aid      ?? string.Empty;
            HostnameDisplay = ctx.Hostname ?? string.Empty;
            CanRun          = !string.IsNullOrWhiteSpace(AidInput);

            // Honor the preferred tool set by AlertsViewModel (e.g., from "Velociraptor" button)
            if (ctx.PreferredForensicsTool.HasValue)
                SelectedTool = ctx.PreferredForensicsTool.Value;

            Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Contexto de investigação: {HostnameDisplay}  |  AID={Abbr(AidInput)}"));
            Terminal.Add(RtrTerminalLine.Info($"       Ferramenta pré-selecionada: {ToolLabel}"));
            Terminal.Add(RtrTerminalLine.Blank());
        }
        else
        {
            Terminal.Add(RtrTerminalLine.Info("Informe o AID do endpoint, configure os artefatos e clique Iniciar Coleta."));
            Terminal.Add(RtrTerminalLine.Blank());
        }
    }

    partial void OnAidInputChanged(string value)  => CanRun = !string.IsNullOrWhiteSpace(value) && !IsBusy;
    partial void OnIsConnectedChanged(bool value)  { IsNotConnected = !value; CanRun = !IsBusy && !string.IsNullOrWhiteSpace(AidInput); }

    // ─── Tool-selection helpers (RadioButton ↔ enum binding) ─────────────────
    partial void OnSelectedToolChanged(ForensicsToolKind _)
    {
        OnPropertyChanged(nameof(IsKape));
        OnPropertyChanged(nameof(IsVelociraptor));
        OnPropertyChanged(nameof(IsUac));
    }

    public bool IsKape
    {
        get => SelectedTool == ForensicsToolKind.Kape;
        set { if (value) SelectedTool = ForensicsToolKind.Kape; }
    }
    public bool IsVelociraptor
    {
        get => SelectedTool == ForensicsToolKind.Velociraptor;
        set { if (value) SelectedTool = ForensicsToolKind.Velociraptor; }
    }
    public bool IsUac
    {
        get => SelectedTool == ForensicsToolKind.Uac;
        set { if (value) SelectedTool = ForensicsToolKind.Uac; }
    }

    // ─── Commands ────────────────────────────────────────────────────────────
    [RelayCommand]
    private async Task StartCollection()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid)) return;

        IsBusy          = true;
        CanRun          = false;
        CollectComplete = false;
        OutputPath      = string.Empty;
        StatusLine      = "Iniciando coleta forense…";

        var ts       = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var outPath  = $@"C:\Windows\Temp\iris_triage_{DisplayHost.Replace(" ","_")}_{ts}";

        Terminal.Add(RtrTerminalLine.Warn($"[{Ts}] ⚠  Iniciando coleta forense — operação de alto risco."));
        Terminal.Add(RtrTerminalLine.Info($"       Host       : {DisplayHost}"));
        Terminal.Add(RtrTerminalLine.Info($"       Ferramenta : {ToolLabel}"));
        Terminal.Add(RtrTerminalLine.Info($"       Escopo     : {BuildScopeString()}"));
        Terminal.Add(RtrTerminalLine.Blank());

        try
        {
            // Open RTR session if needed
            if (_session is null)
            {
                Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Abrindo sessão RTR em {Abbr(aid)}…"));
                var sr = await _falcon.StartRtrSessionAsync(aid).ConfigureAwait(true);
                if (sr.IsFailure)
                {
                    Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Falha: {sr.Error}"));
                    StatusLine = "Falha na sessão RTR."; return;
                }
                _session    = sr.Value!;
                IsConnected = true;
                Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Sessão RTR aberta. Expira {_session.ExpiresUtc.ToLocalTime():HH:mm:ss}"));
                Terminal.Add(RtrTerminalLine.Blank());
            }

            // Build and execute the collection command
            var (baseCmd, fullCmd) = BuildCollectionCommand(outPath);
            Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Executando coleta com {ToolLabel}…"));
            Terminal.Add(RtrTerminalLine.Info($"       Destino: {outPath}"));
            Terminal.Add(RtrTerminalLine.Blank());

            var cr = await _falcon.ExecuteRtrAsync(_session.SessionId, baseCmd, fullCmd).ConfigureAwait(true);
            if (cr.IsFailure)
            {
                Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Erro RTR: {cr.Error}"));
                StatusLine = "Falha na coleta."; return;
            }

            var res = cr.Value!;
            if (!string.IsNullOrWhiteSpace(res.Stdout))
                foreach (var ln in res.Stdout.Split('\n'))
                    Terminal.Add(RtrTerminalLine.Output(ln.TrimEnd('\r')));
            if (!string.IsNullOrWhiteSpace(res.Stderr))
                foreach (var ln in res.Stderr.Split('\n'))
                    Terminal.Add(RtrTerminalLine.Error(ln.TrimEnd('\r')));
            Terminal.Add(RtrTerminalLine.Blank());

            if (!res.Complete)
                Terminal.Add(RtrTerminalLine.Warn($"[{Ts}] Coleta assíncrona em andamento no endpoint."));

            OutputPath      = outPath;
            CollectComplete = true;
            StatusLine      = "Coleta iniciada com sucesso.";
            Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Coleta forense iniciada com sucesso!"));
            Terminal.Add(RtrTerminalLine.Info($"       Artefatos no endpoint: {outPath}"));
            Terminal.Add(RtrTerminalLine.Info($"       Para recuperar: use 'get {outPath}.zip' no Console RTR."));
            Terminal.Add(RtrTerminalLine.Blank());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Forensics collection exception");
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] Exceção: {ex.Message}"));
            StatusLine = "Erro inesperado.";
        }
        finally { IsBusy = false; CanRun = !string.IsNullOrWhiteSpace(AidInput); }
    }

    [RelayCommand] private void SelectAll()  { CollectEvents = CollectRegistry = CollectPrefetch = CollectBrowser = CollectSystem = CollectNetwork = true; }
    [RelayCommand] private void SelectNone() { CollectEvents = CollectRegistry = CollectPrefetch = CollectBrowser = CollectSystem = CollectNetwork = CollectFull = false; }
    [RelayCommand] private void ClearTerminal() { Terminal.Clear(); PrintBanner(); }
    [RelayCommand] private void BackToAlerts()  => _nav.NavigateTo("alerts");

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private (string baseCmd, string fullCmd) BuildCollectionCommand(string outPath)
    {
        switch (SelectedTool)
        {
            case ForensicsToolKind.Kape:
            {
                var targets = BuildKapeTargets();
                return ("runscript",
                    @$"runscript -Raw=if(Test-Path 'C:\Windows\Temp\kape.exe'){{& 'C:\Windows\Temp\kape.exe' --tsource C: --tdest '{outPath}' --target {targets} --zip {DisplayHost} 2>&1}}else{{'KAPE não encontrado. Faça o put do kape.exe via Console RTR antes de iniciar a coleta.'}}");
            }
            case ForensicsToolKind.Velociraptor:
            {
                return ("runscript",
                    @$"runscript -Raw=if(Test-Path 'C:\Windows\Temp\velociraptor.exe'){{& 'C:\Windows\Temp\velociraptor.exe' artifacts collect Windows.KapeFiles.Targets --args OperatingSystem=Windows BasicCollection=Y --output '{outPath}.zip' 2>&1}}else{{'Velociraptor não encontrado. Faça o put do binário via Console RTR.'}}");
            }
            case ForensicsToolKind.Uac:
            {
                return ("runscript",
                    @$"runscript -Raw=if(Test-Path 'C:\Windows\Temp\uac.exe'){{& 'C:\Windows\Temp\uac.exe' -p windows -o '{outPath}' 2>&1}}else{{'UAC não encontrado. Faça o put do uac.exe via Console RTR.'}}");
            }
            default:
                return ("runscript", @$"runscript -Raw=echo 'Ferramenta não configurada'");
        }
    }

    private string BuildKapeTargets()
    {
        if (CollectFull) return "!FullTriage";
        var t = new List<string>();
        if (CollectEvents)   t.Add("EventLogs");
        if (CollectRegistry) t.Add("RegistryHives");
        if (CollectPrefetch) t.Add("Prefetch");
        if (CollectBrowser)  t.Add("WebBrowsers");
        if (CollectSystem)   t.Add("RecycleBin,LNKFilesAndJumpLists,FileSystem");
        if (CollectNetwork)  t.Add("NetworkCards");
        return t.Count > 0 ? string.Join(",", t) : "!BasicCollection";
    }

    private string BuildScopeString()
    {
        if (CollectFull) return "Triage Completo";
        var parts = new List<string>();
        if (CollectEvents)   parts.Add("EventLogs");
        if (CollectRegistry) parts.Add("Registro");
        if (CollectPrefetch) parts.Add("Prefetch");
        if (CollectBrowser)  parts.Add("Browser");
        if (CollectSystem)   parts.Add("Sistema/LNK");
        if (CollectNetwork)  parts.Add("Rede");
        return parts.Count > 0 ? string.Join(", ", parts) : "Básico";
    }

    private string ToolLabel => SelectedTool switch
    {
        ForensicsToolKind.Kape        => "KAPE (Kroll Artifact Parser)",
        ForensicsToolKind.Velociraptor => "Velociraptor (Velocidex)",
        ForensicsToolKind.Uac         => "UAC (IR Ninja)",
        _                             => "Desconhecido"
    };

    private void PrintBanner()
    {
        Terminal.Add(RtrTerminalLine.Info("╔═══════════════════════════════════════════════════════════════╗"));
        Terminal.Add(RtrTerminalLine.Info("║  CyberThrust.IRIS — Forense de Disco (Live Forensics)         ║"));
        Terminal.Add(RtrTerminalLine.Info("║  KAPE · Velociraptor · UAC   via Falcon RTR                   ║"));
        Terminal.Add(RtrTerminalLine.Info("║  Zero-Storage: artefatos coletados no endpoint remoto.        ║"));
        Terminal.Add(RtrTerminalLine.Info("╚═══════════════════════════════════════════════════════════════╝"));
        Terminal.Add(RtrTerminalLine.Blank());
    }

    private string DisplayHost  => string.IsNullOrWhiteSpace(HostnameDisplay) ? Abbr(AidInput) : HostnameDisplay;
    private static string Abbr(string s, int max = 14) => string.IsNullOrEmpty(s) ? "?" : (s.Length > max ? s[..max] + "…" : s);
    private static string Ts => DateTime.Now.ToString("HH:mm:ss");
}
