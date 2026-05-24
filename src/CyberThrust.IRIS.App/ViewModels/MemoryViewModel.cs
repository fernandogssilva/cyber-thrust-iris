using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Abstractions;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.ViewModels;

// ─── Memory tool option ───────────────────────────────────────────────────────
public enum MemoryTool
{
    XMemdump,   // Falcon nativo: xmemdump — sem transferência de binário
    WinPmem,    // Velocidex WinPmem — put-and-run via RTR
    DumpIt      // Comae DumpIt — put-and-run via RTR
}

// ─── ViewModel ───────────────────────────────────────────────────────────────
/// <summary>
/// Captura de memória RAM em endpoints remotos via Falcon RTR.
/// Ferramentas: xmemdump (nativo), WinPmem, DumpIt.
/// Zero-Storage: nenhum dado é gravado localmente — tudo via API.
/// </summary>
public partial class MemoryViewModel : ViewModelBase
{
    private readonly IFalconClient             _falcon;
    private readonly INavigationService        _nav;
    private readonly AlertInvestigationContext _ctx;

    private RtrSessionInfo? _session;

    // ─── Terminal ─────────────────────────────────────────────────────────────
    public ObservableCollection<RtrTerminalLine> Terminal { get; } = new();

    // ─── State ───────────────────────────────────────────────────────────────
    [ObservableProperty] private string     _aidInput        = string.Empty;
    [ObservableProperty] private string     _hostnameDisplay = string.Empty;
    [ObservableProperty] private bool       _isConnected;
    [ObservableProperty] private bool       _isNotConnected  = true;
    [ObservableProperty] private bool       _canRun;
    [ObservableProperty] private string     _statusLine      = "Desconectado.";
    [ObservableProperty] private MemoryTool _selectedTool    = MemoryTool.XMemdump;
    [ObservableProperty] private bool       _captureComplete;
    [ObservableProperty] private string     _outputFilePath  = string.Empty;

    // Tool descriptions shown in UI
    public string XMemdumpDesc => "Comando nativo Falcon RTR Active Responder.\nSem upload de binário — disponível em qualquer endpoint.\nRecomendado para capturas rápidas.";
    public string WinPmemDesc  => "Velocidex WinPmem — ferramenta open source leve (< 2 MB).\nRequerido: fazer put do binário antes via RTR.\nSuporta RAM física + kernel objects.\nSrc: github.com/Velocidex/WinPmem";
    public string DumpItDesc   => "Comae DumpIt — solução forense profissional.\nRequerido: fazer put do binário + licença antes.\nSrc: www.comae.com";

    // ─── Constructor ─────────────────────────────────────────────────────────
    public MemoryViewModel(IFalconClient falcon, INavigationService nav, AlertInvestigationContext ctx)
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
            Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Contexto de investigação: {HostnameDisplay}  |  AID={Abbr(AidInput)}"));
            Terminal.Add(RtrTerminalLine.Blank());
        }
        else
        {
            Terminal.Add(RtrTerminalLine.Info("Informe o AID do endpoint-alvo e selecione a ferramenta de captura."));
            Terminal.Add(RtrTerminalLine.Blank());
        }
    }

    // ─── Property change handlers ─────────────────────────────────────────────
    partial void OnAidInputChanged(string value)  => CanRun = !string.IsNullOrWhiteSpace(value) && !IsBusy;
    partial void OnIsConnectedChanged(bool value)  { IsNotConnected = !value; CanRun = !IsBusy && !string.IsNullOrWhiteSpace(AidInput); }

    // ─── Tool-selection helpers (RadioButton ↔ enum binding) ─────────────────
    partial void OnSelectedToolChanged(MemoryTool _)
    {
        OnPropertyChanged(nameof(IsXMemdump));
        OnPropertyChanged(nameof(IsWinPmem));
        OnPropertyChanged(nameof(IsDumpIt));
    }

    public bool IsXMemdump
    {
        get => SelectedTool == MemoryTool.XMemdump;
        set { if (value) SelectedTool = MemoryTool.XMemdump; }
    }
    public bool IsWinPmem
    {
        get => SelectedTool == MemoryTool.WinPmem;
        set { if (value) SelectedTool = MemoryTool.WinPmem; }
    }
    public bool IsDumpIt
    {
        get => SelectedTool == MemoryTool.DumpIt;
        set { if (value) SelectedTool = MemoryTool.DumpIt; }
    }

    // ─── Commands ────────────────────────────────────────────────────────────
    [RelayCommand]
    private async Task StartCapture()
    {
        var aid = AidInput.Trim();
        if (string.IsNullOrWhiteSpace(aid)) return;

        IsBusy          = true;
        CanRun          = false;
        CaptureComplete = false;
        OutputFilePath  = string.Empty;
        StatusLine      = "Iniciando captura de memória…";

        Terminal.Add(RtrTerminalLine.Warn($"[{Ts}] ⚠  Iniciando dump de memória — operação de alto risco."));
        Terminal.Add(RtrTerminalLine.Info($"       Host       : {DisplayHost}"));
        Terminal.Add(RtrTerminalLine.Info($"       Ferramenta : {ToolLabel}"));
        Terminal.Add(RtrTerminalLine.Blank());

        try
        {
            // Step 1: Start RTR session
            if (_session is null)
            {
                Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Abrindo sessão RTR em {Abbr(aid)}…"));
                var sr = await _falcon.StartRtrSessionAsync(aid).ConfigureAwait(true);
                if (sr.IsFailure)
                {
                    Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Falha ao abrir sessão: {sr.Error}"));
                    StatusLine = "Falha na sessão RTR."; return;
                }
                _session    = sr.Value!;
                IsConnected = true;
                Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Sessão RTR aberta. Expira {_session.ExpiresUtc.ToLocalTime():HH:mm:ss}"));
                Terminal.Add(RtrTerminalLine.Blank());
            }

            // Step 2: Execute memory dump command
            var ts       = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile  = $@"C:\Windows\Temp\memdump_{DisplayHost.Replace(" ","_")}_{ts}";
            var (baseCmd, fullCmd) = BuildDumpCommand(outFile);

            Terminal.Add(RtrTerminalLine.Info($"[{Ts}] Executando: {baseCmd}…"));
            Terminal.Add(RtrTerminalLine.Info($"       Destino: {outFile}.{DumpExt}"));
            Terminal.Add(RtrTerminalLine.Blank());

            var cr = await _falcon.ExecuteRtrAsync(_session.SessionId, baseCmd, fullCmd).ConfigureAwait(true);
            if (cr.IsFailure)
            {
                Terminal.Add(RtrTerminalLine.Error($"[{Ts}] ❌ Erro RTR: {cr.Error}"));
                StatusLine = "Falha na captura."; return;
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
                Terminal.Add(RtrTerminalLine.Warn("[" + Ts + "] Tarefa assíncrona — dump ainda em andamento no endpoint."));

            OutputFilePath  = $"{outFile}.{DumpExt}";
            CaptureComplete = true;
            StatusLine      = "Dump iniciado com sucesso.";

            Terminal.Add(RtrTerminalLine.Success($"[{Ts}] ✅ Dump iniciado com sucesso!"));
            Terminal.Add(RtrTerminalLine.Info($"       Arquivo no endpoint: {OutputFilePath}"));
            Terminal.Add(RtrTerminalLine.Info($"       Para recuperar: use 'get {OutputFilePath}' no Console RTR."));
            Terminal.Add(RtrTerminalLine.Blank());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "MemoryCapture exception");
            Terminal.Add(RtrTerminalLine.Error($"[{Ts}] Exceção: {ex.Message}"));
            StatusLine = "Erro inesperado.";
        }
        finally { IsBusy = false; CanRun = !string.IsNullOrWhiteSpace(AidInput); }
    }

    [RelayCommand]
    private void GetDumpFile()
    {
        if (string.IsNullOrWhiteSpace(OutputFilePath)) return;
        // Populates the RTR console command for retrieving the file
        _nav.NavigateTo("rtr");
        _ctx.Aid      = AidInput;
        _ctx.Hostname = HostnameDisplay;
    }

    [RelayCommand] private void ClearTerminal() { Terminal.Clear(); PrintBanner(); }
    [RelayCommand] private void BackToAlerts()  => _nav.NavigateTo("alerts");

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private (string baseCmd, string fullCmd) BuildDumpCommand(string outPath)
    {
        return SelectedTool switch
        {
            MemoryTool.XMemdump => ("xmemdump", "xmemdump"),
            MemoryTool.WinPmem  => ("runscript",
                @$"runscript -Raw=if(Test-Path 'C:\Windows\Temp\winpmem.exe'){{& 'C:\Windows\Temp\winpmem.exe' '{outPath}.raw' 2>&1}}else{{'WinPmem não encontrado. Coloque o binário em C:\Windows\Temp\winpmem.exe via put no Console RTR.'}}"),
            MemoryTool.DumpIt   => ("runscript",
                @$"runscript -Raw=if(Test-Path 'C:\Windows\Temp\DumpIt.exe'){{& 'C:\Windows\Temp\DumpIt.exe' /OUTPUT '{outPath}.dmp' /Q 2>&1}}else{{'DumpIt não encontrado. Coloque o binário em C:\Windows\Temp\DumpIt.exe via put no Console RTR.'}}"),
            _ => ("xmemdump", "xmemdump")
        };
    }

    private string DumpExt => SelectedTool switch
    {
        MemoryTool.XMemdump => "raw",
        MemoryTool.WinPmem  => "raw",
        MemoryTool.DumpIt   => "dmp",
        _                   => "raw"
    };

    private string ToolLabel => SelectedTool switch
    {
        MemoryTool.XMemdump => "xmemdump (nativo Falcon RTR)",
        MemoryTool.WinPmem  => "WinPmem (Velocidex)",
        MemoryTool.DumpIt   => "DumpIt (Comae)",
        _                   => "Desconhecido"
    };

    private void PrintBanner()
    {
        Terminal.Add(RtrTerminalLine.Info("╔═══════════════════════════════════════════════════════════════╗"));
        Terminal.Add(RtrTerminalLine.Info("║  CyberThrust.IRIS — Captura de Memória RAM (Live Forensics)   ║"));
        Terminal.Add(RtrTerminalLine.Info("║  xmemdump · WinPmem · DumpIt   via Falcon RTR                 ║"));
        Terminal.Add(RtrTerminalLine.Info("║  Zero-Storage: dump criado no endpoint, não localmente.       ║"));
        Terminal.Add(RtrTerminalLine.Info("╚═══════════════════════════════════════════════════════════════╝"));
        Terminal.Add(RtrTerminalLine.Blank());
    }

    private string DisplayHost  => string.IsNullOrWhiteSpace(HostnameDisplay) ? Abbr(AidInput) : HostnameDisplay;
    private static string Abbr(string s, int max = 14) => string.IsNullOrEmpty(s) ? "?" : (s.Length > max ? s[..max] + "…" : s);
    private static string Ts => DateTime.Now.ToString("HH:mm:ss");
}
