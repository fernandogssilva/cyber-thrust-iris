using System.IO;
using System.Text.Json;
using CyberThrust.IRIS.Core.Models;
using Serilog;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Lê e grava <c>appsettings.local.json</c> ao lado do executável.
/// Esse arquivo NÃO vai pro repo (gitignore) e contém os secrets reais
/// (Tenant Entra, Falcon API key). É atualizado pela tela de Configurações.
/// </summary>
public sealed class AppConfigStore
{
    public string FilePath { get; }

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = null // mantém PascalCase pra bater com appsettings.json
    };

    public AppConfigStore()
    {
        FilePath = Path.Combine(AppContext.BaseDirectory, "appsettings.local.json");
    }

    /// <summary>Carrega o arquivo local. Se não existir, devolve snapshot vazio.</summary>
    public AppConfigSnapshot Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new AppConfigSnapshot();
            var json = File.ReadAllText(FilePath);
            var snap = JsonSerializer.Deserialize<AppConfigSnapshot>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            return snap ?? new AppConfigSnapshot();
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Falha ao ler {Path}", FilePath);
            return new AppConfigSnapshot();
        }
    }

    /// <summary>Grava o arquivo. Cria backup .bak da versão anterior, se existir.</summary>
    public void Save(AppConfigSnapshot snapshot)
    {
        if (File.Exists(FilePath))
        {
            try { File.Copy(FilePath, FilePath + ".bak", overwrite: true); } catch { }
        }
        var json = JsonSerializer.Serialize(snapshot, WriteOptions);
        File.WriteAllText(FilePath, json);
        Log.Information("Configuração local gravada em {Path}", FilePath);
    }

    /// <summary>Retorna true se o arquivo já existe (config válida foi salva pelo menos uma vez).</summary>
    public bool Exists() => File.Exists(FilePath);
}
