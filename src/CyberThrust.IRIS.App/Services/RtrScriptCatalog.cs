namespace CyberThrust.IRIS.App.Services;

// ─── Risk level ──────────────────────────────────────────────────────────────
public enum RtrScriptRisk { Low, Medium, High }

// ─── Script definition ───────────────────────────────────────────────────────
/// <summary>
/// Define um script RTR executável no Falcon Real-Time Response.
/// Os CommandString com {HOST},{IP},{DOMAIN},{HASH},{USER},{PROCESS} são
/// substituídos pelos valores dos filtros de investigação em tempo de execução.
/// Source: maioria dos scripts referencia o repositório público
/// https://github.com/CrowdStrike/psfalcon e
/// https://github.com/CrowdStrike/falcon-scripts.
/// </summary>
public sealed record RtrScript(
    string         Id,
    string         Name,
    string         Category,
    string         CategoryIcon,
    string         Icon,
    string         Description,
    string         BaseCommand,   // primeiro token para ExecuteRtrAsync "command"
    string         CommandString, // string completa com argumentos
    RtrScriptRisk  Risk,
    string?        SourceUrl = null
);

// ─── Catalog ─────────────────────────────────────────────────────────────────
/// <summary>
/// Catálogo dos 20 scripts RTR derivados dos repositórios públicos da CrowdStrike,
/// organizados por categoria para a tela Console RTR.
/// </summary>
public static class RtrScriptCatalog
{
    // ── Categoria 1: Reconhecimento do Sistema ──────────────────────────────
    public static readonly IReadOnlyList<RtrScript> Reconhecimento = new[]
    {
        new RtrScript(
            Id:            "sys-info",
            Name:          "Informações do Sistema",
            Category:      "Reconhecimento",
            CategoryIcon:  "🔍",
            Icon:          "💻",
            Description:   "Hostname, SO, versão, hardware, uptime, domínio.\nSource: psfalcon/samples/rtr",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```systeminfo /fo csv 2>&1 | Select-Object -Skip 1 | ConvertFrom-Csv | Select-Object 'Host Name','OS Name','OS Version','System Manufacturer','System Model','Total Physical Memory','Domain'```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon/tree/main/samples/real-time-response"
        ),
        new RtrScript(
            Id:            "process-tree",
            Name:          "Árvore de Processos",
            Category:      "Reconhecimento",
            CategoryIcon:  "🔍",
            Icon:          "⚙",
            Description:   "Top 35 processos por CPU, com PID, PPID, memória e caminho.\nDetecta processos sem caminho (hollowing) e mascarados.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-Process | Sort-Object CPU -Descending | Select-Object -First 35 Name,Id,@{N='PPID';E={(Get-WmiObject Win32_Process -Filter ```""ProcessId=$($_.Id)"" -EA SilentlyContinue).ParentProcessId}},@{N='CPU(s)';E={[math]::Round($_.CPU,1)}},@{N='Mem(MB)';E={[math]::Round($_.WorkingSet64/1MB,1)}},Path | Format-Table -AutoSize",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon"
        ),
        new RtrScript(
            Id:            "net-connections",
            Name:          "Conexões de Rede",
            Category:      "Reconhecimento",
            CategoryIcon:  "🔍",
            Icon:          "🌐",
            Description:   "Conexões TCP ativas (Established/SynSent) com IP:porta remoto e PID dono.\nFiltrar por IP: preencha o filtro IP.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-NetTCPConnection -State Established,SynSent -EA SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} | Sort-Object RemoteAddress | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/falcon-scripts"
        ),
        new RtrScript(
            Id:            "dns-cache",
            Name:          "Cache DNS",
            Category:      "Reconhecimento",
            CategoryIcon:  "🔍",
            Icon:          "📡",
            Description:   "Entradas do cache DNS do resolvedor. Útil para detectar domínios C2 recentemente consultados.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-DnsClientCache | Select-Object Entry,RecordName,Type,TTL,DataLength | Sort-Object Entry | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon"
        ),
        new RtrScript(
            Id:            "arp-table",
            Name:          "Tabela ARP",
            Category:      "Reconhecimento",
            CategoryIcon:  "🔍",
            Icon:          "📶",
            Description:   "Cache ARP com endereços MAC → IP mapeados. Detecta ARP spoofing.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-NetNeighbor -State Reachable,Stale,Delay,Probe -EA SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | Sort-Object InterfaceAlias | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/falcon-scripts"
        ),
    };

    // ── Categoria 2: Persistência e Autoinício ──────────────────────────────
    public static readonly IReadOnlyList<RtrScript> Persistencia = new[]
    {
        new RtrScript(
            Id:            "scheduled-tasks",
            Name:          "Tarefas Agendadas",
            Category:      "Persistência",
            CategoryIcon:  "⏰",
            Icon:          "📋",
            Description:   "Todas as tarefas agendadas habilitadas com caminho, estado e próxima execução.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon/tree/main/samples/real-time-response"
        ),
        new RtrScript(
            Id:            "services",
            Name:          "Serviços em Execução",
            Category:      "Persistência",
            CategoryIcon:  "⏰",
            Icon:          "🔧",
            Description:   "Serviços Windows com status Running, tipo de inicialização e caminho do binário.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-WmiObject Win32_Service | Where-Object {$_.State -eq 'Running'} | Select-Object Name,DisplayName,StartMode,PathName | Sort-Object Name | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon"
        ),
        new RtrScript(
            Id:            "startup-items",
            Name:          "Itens de Autoinício",
            Category:      "Persistência",
            CategoryIcon:  "⏰",
            Icon:          "🚀",
            Description:   "Entradas de Run/RunOnce nos hives HKLM e HKCU + pasta Startup do usuário.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```$hives=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'); foreach($h in $hives){```""=== $h ==="" ; Get-ItemProperty $h -EA SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider | Format-List}",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/detection-strategy-scripts"
        ),
        new RtrScript(
            Id:            "wmi-subscriptions",
            Name:          "Subscrições WMI",
            Category:      "Persistência",
            CategoryIcon:  "⏰",
            Icon:          "🕵",
            Description:   "Filtros e consumidores WMI — técnica de persistência APT (T1546.003).",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```@('__EventFilter','__EventConsumer','__FilterToConsumerBinding') | ForEach-Object {$cls=$_; ```""=== $cls ===""; Get-WmiObject -Namespace root\subscription -Class $cls -EA SilentlyContinue | Select-Object Name,Query,CommandLineTemplate | Format-Table -AutoSize}",
            Risk:          RtrScriptRisk.Medium,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon/tree/main/samples/real-time-response"
        ),
        new RtrScript(
            Id:            "reg-run-keys",
            Name:          "Chaves Run do Registro",
            Category:      "Persistência",
            CategoryIcon:  "⏰",
            Icon:          "🗝",
            Description:   "Consulta reg.exe nas chaves Run/RunOnce/RunServices de HKLM e HKCU.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```@('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') | ForEach-Object {```""=== $_ ==="" ; reg query $_ 2>&1}",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/detection-strategy-scripts"
        ),
    };

    // ── Categoria 3: Usuários e Credenciais ─────────────────────────────────
    public static readonly IReadOnlyList<RtrScript> Usuarios = new[]
    {
        new RtrScript(
            Id:            "local-admins",
            Name:          "Administradores Locais",
            Category:      "Usuários",
            CategoryIcon:  "👤",
            Icon:          "🛡",
            Description:   "Membros do grupo Administradores local. Detecta contas backdoor.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```net localgroup administrators 2>&1```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon"
        ),
        new RtrScript(
            Id:            "logon-history",
            Name:          "Histórico de Logons",
            Category:      "Usuários",
            CategoryIcon:  "👤",
            Icon:          "🔐",
            Description:   "Últimos 30 logons (Event ID 4624) com usuário, tipo de logon e IP de origem.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-WinEvent -LogName Security -FilterXPath ```""*[System[EventID=4624]][System[TimeCreated[timediff(@SystemTime)<=86400000]]]"" -MaxEvents 30 -EA SilentlyContinue | ForEach-Object { $xml=[xml]$_.ToXml(); $d=$xml.Event.EventData.Data; [pscustomobject]@{Time=$_.TimeCreated; User=($d|Where-Object Name -eq 'TargetUserName').'#text'; Type=($d|Where-Object Name -eq 'LogonType').'#text'; IP=($d|Where-Object Name -eq 'IpAddress').'#text'; Process=($d|Where-Object Name -eq 'ProcessName').'#text'} } | Format-Table -AutoSize",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/falcon-scripts"
        ),
        new RtrScript(
            Id:            "active-sessions",
            Name:          "Sessões Ativas",
            Category:      "Usuários",
            CategoryIcon:  "👤",
            Icon:          "👥",
            Description:   "Sessões RDP e console ativas (query session + net session).",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```query session 2>&1 ; echo '---'; net session 2>&1```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon"
        ),
        new RtrScript(
            Id:            "domain-admins",
            Name:          "Administradores de Domínio",
            Category:      "Usuários",
            CategoryIcon:  "👤",
            Icon:          "🏢",
            Description:   "Membros do grupo Domain Admins (requer acesso ao DC) e administradores locais.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```net group ```""Domain Admins"" /domain 2>&1 ; echo '---' ; net localgroup administrators 2>&1",
            Risk:          RtrScriptRisk.Medium,
            SourceUrl:     "https://github.com/CrowdStrike/detection-strategy-scripts"
        ),
    };

    // ── Categoria 4: Artefatos Forenses ─────────────────────────────────────
    public static readonly IReadOnlyList<RtrScript> Forense = new[]
    {
        new RtrScript(
            Id:            "prefetch",
            Name:          "Arquivos Prefetch",
            Category:      "Forense",
            CategoryIcon:  "🔬",
            Icon:          "📁",
            Description:   "30 arquivos Prefetch mais recentes — comprova execução de programas (T1218).",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-ChildItem C:\Windows\Prefetch\*.pf -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 30 Name,LastWriteTime,@{N='Size(KB)';E={[math]::Round($_.Length/1KB,1)}} | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon/tree/main/samples/real-time-response"
        ),
        new RtrScript(
            Id:            "browser-history",
            Name:          "Histórico de Navegadores",
            Category:      "Forense",
            CategoryIcon:  "🔬",
            Icon:          "🌍",
            Description:   "Localiza arquivos de histórico do Chrome, Edge e Firefox (não lê conteúdo).",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```$paths=@([Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\Google\Chrome\User Data\Default\History'),[Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History'),[Environment]::ExpandEnvironmentVariables('%APPDATA%\Mozilla\Firefox\Profiles')); $paths | ForEach-Object { [pscustomobject]@{ Browser=(Split-Path (Split-Path $_ -Parent) -Leaf); Path=$_; Exists=(Test-Path $_); LastModified=if(Test-Path $_){(Get-Item $_).LastWriteTime}else{'N/A'} } } | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/falcon-scripts"
        ),
        new RtrScript(
            Id:            "usb-history",
            Name:          "Histórico USB",
            Category:      "Forense",
            CategoryIcon:  "🔬",
            Icon:          "🔌",
            Description:   "Dispositivos USB já conectados (USBSTOR no registro). Detecta exfiltração por USB.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -EA SilentlyContinue | Select-Object FriendlyName,@{N='DeviceID';E={$_.PSChildName}},ContainerID | Sort-Object FriendlyName | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/detection-strategy-scripts"
        ),
        new RtrScript(
            Id:            "recent-files",
            Name:          "Arquivos Recentes",
            Category:      "Forense",
            CategoryIcon:  "🔬",
            Icon:          "📄",
            Description:   "Atalhos de arquivos recentemente acessados pelo usuário (pasta Recent).",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-ChildItem ```""$env:APPDATA\Microsoft\Windows\Recent\*.lnk"" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 30 Name,LastWriteTime | Format-Table -AutoSize",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon"
        ),
        new RtrScript(
            Id:            "firewall-rules",
            Name:          "Regras de Firewall",
            Category:      "Forense",
            CategoryIcon:  "🔬",
            Icon:          "🔥",
            Description:   "Regras de firewall habilitadas (entrada). Detecta portas abertas por malware.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'} | Select-Object Name,DisplayName,Profile,Protocol,@{N='Port';E={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}} | Sort-Object Profile | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Low,
            SourceUrl:     "https://github.com/CrowdStrike/detection-strategy-scripts"
        ),
        new RtrScript(
            Id:            "mft-changes",
            Name:          "Alterações Recentes (MFT)",
            Category:      "Forense",
            CategoryIcon:  "🔬",
            Icon:          "🗃",
            Description:   "50 arquivos modificados nas últimas 24h em C:\\. Detecta drops de malware.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```Get-ChildItem C:\ -Recurse -Force -EA SilentlyContinue | Where-Object {!$_.PSIsContainer -and $_.LastWriteTime -gt (Get-Date).AddHours(-24)} | Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName,LastWriteTime,@{N='Size(KB)';E={[math]::Round($_.Length/1KB,1)}} | Format-Table -AutoSize```",
            Risk:          RtrScriptRisk.Medium,
            SourceUrl:     "https://github.com/CrowdStrike/psfalcon/tree/main/samples/real-time-response"
        ),
    };

    // ── Categoria 5: Coleta de Evidências (Memória + Disco) ─────────────────
    public static readonly IReadOnlyList<RtrScript> Coleta = new[]
    {
        new RtrScript(
            Id:            "memdump-xrtr",
            Name:          "Dump de Memória (xmemdump)",
            Category:      "Coleta",
            CategoryIcon:  "💾",
            Icon:          "🧠",
            Description:   "Captura imagem da memória RAM via comando nativo Falcon RTR Active Responder.\nO dump é salvo no endpoint para recuperação posterior com 'get'.",
            BaseCommand:   "xmemdump",
            CommandString: "xmemdump",
            Risk:          RtrScriptRisk.High,
            SourceUrl:     "https://falcon.crowdstrike.com/documentation/page/b8ad5c53/real-time-response-commands"
        ),
        new RtrScript(
            Id:            "memdump-winpmem",
            Name:          "Dump de Memória (WinPmem via RTR)",
            Category:      "Coleta",
            CategoryIcon:  "💾",
            Icon:          "🧠",
            Description:   "Deploy do WinPmem via RTR put-and-run para captura de RAM.\nSource: github.com/Velocidex/WinPmem",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```$out='C:\Windows\Temp\memdump_'+$env:COMPUTERNAME+'_'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'.raw'; if(Test-Path 'C:\Windows\Temp\winpmem.exe'){& 'C:\Windows\Temp\winpmem.exe' $out 2>&1}else{'WinPmem não encontrado. Use: put winpmem.exe + run winpmem.exe '+$out}```",
            Risk:          RtrScriptRisk.High,
            SourceUrl:     "https://github.com/Velocidex/WinPmem"
        ),
        new RtrScript(
            Id:            "disk-triage-kape",
            Name:          "Triage de Disco (KAPE)",
            Category:      "Coleta",
            CategoryIcon:  "💾",
            Icon:          "💿",
            Description:   "Coleta de artefatos forenses com KAPE (Kroll Artifact Parser and Extractor) via RTR.\nAlvos: EventLogs, Registry, Prefetch, Browser, LNK, JumpLists.",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```$out='C:\Windows\Temp\kape_triage_'+$env:COMPUTERNAME; if(Test-Path 'C:\Windows\Temp\kape.exe'){& 'C:\Windows\Temp\kape.exe' --tsource C: --tdest $out --target !BasicCollection --zip $env:COMPUTERNAME 2>&1}else{'KAPE não encontrado. Use: put kape.exe + run kape.exe --tsource C: --tdest '+$out+' --target !BasicCollection'}```",
            Risk:          RtrScriptRisk.High,
            SourceUrl:     "https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape"
        ),
        new RtrScript(
            Id:            "velociraptor-hunt",
            Name:          "Hunt Velociraptor (inline)",
            Category:      "Coleta",
            CategoryIcon:  "💾",
            Icon:          "🦅",
            Description:   "Executa coleta rápida de artefatos via Velociraptor inline no endpoint.\nSource: github.com/Velocidex/velociraptor",
            BaseCommand:   "runscript",
            CommandString: @"runscript -Raw=```if(Test-Path 'C:\Windows\Temp\velociraptor.exe'){& 'C:\Windows\Temp\velociraptor.exe' artifacts collect Windows.KapeFiles.Targets --args OperatingSystem=Windows BasicCollection=Y --output C:\Windows\Temp\velociraptor_triage.zip 2>&1}else{'Velociraptor não encontrado no endpoint. Faça o put do binário primeiro.'}```",
            Risk:          RtrScriptRisk.High,
            SourceUrl:     "https://github.com/Velocidex/velociraptor"
        ),
    };

    // ── Todos os scripts ──────────────────────────────────────────────────────
    public static IReadOnlyList<RtrScript> All { get; } =
        Reconhecimento
            .Concat(Persistencia)
            .Concat(Usuarios)
            .Concat(Forense)
            .Concat(Coleta)
            .ToList()
            .AsReadOnly();

    // ── Lookup por ID ──────────────────────────────────────────────────────────
    private static readonly Dictionary<string, RtrScript> _byId =
        All.ToDictionary(s => s.Id, StringComparer.OrdinalIgnoreCase);

    public static RtrScript? FindById(string id) =>
        _byId.TryGetValue(id, out var s) ? s : null;
}
