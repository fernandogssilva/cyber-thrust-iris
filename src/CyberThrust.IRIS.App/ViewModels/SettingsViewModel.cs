using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CyberThrust.IRIS.App.Services;
using CyberThrust.IRIS.Core.Models;

namespace CyberThrust.IRIS.App.ViewModels;

public partial class SettingsViewModel : ViewModelBase
{
    private readonly AppConfigStore _store;
    private readonly ConnectionTester _tester;
    private AppConfigSnapshot _snapshot;

    // ─── Entra fields (bindable) ────────────────────────────────
    [ObservableProperty] private string _entraTenantId = "common";
    [ObservableProperty] private string _entraClientId = string.Empty;
    [ObservableProperty] private string _entraRedirectUri = "http://localhost";
    [ObservableProperty] private string _entraScopesCsv = "User.Read";
    [ObservableProperty] private bool _entraUseBroker = false;

    // ─── Falcon fields (bindable) ───────────────────────────────
    public ObservableCollection<string> FalconCloudOptions { get; } = new(new[] { "us-1", "us-2", "eu-1", "us-gov-1" });
    [ObservableProperty] private string _falconCloud = "us-1";
    [ObservableProperty] private string _falconClientId = string.Empty;
    [ObservableProperty] private string _falconClientSecret = string.Empty;
    [ObservableProperty] private int _falconHttpTimeoutSeconds = 30;

    // ─── Exfil ──────────────────────────────────────────────────
    [ObservableProperty] private string _exfilPresignedUrlTemplate = string.Empty;

    // ─── UI state ───────────────────────────────────────────────
    [ObservableProperty] private string? _falconTestResult;
    [ObservableProperty] private bool _falconTestSuccess;
    [ObservableProperty] private string? _entraTestResult;
    [ObservableProperty] private bool _entraTestSuccess;
    [ObservableProperty] private string? _saveResult;
    [ObservableProperty] private bool _saveSuccess;
    [ObservableProperty] private string _configFilePath = string.Empty;

    public SettingsViewModel(AppConfigStore store, ConnectionTester tester)
    {
        _store = store;
        _tester = tester;
        ConfigFilePath = _store.FilePath;
        _snapshot = _store.Load();
        LoadFromSnapshot(_snapshot);
    }

    private void LoadFromSnapshot(AppConfigSnapshot s)
    {
        EntraTenantId = string.IsNullOrWhiteSpace(s.EntraId.TenantId) ? "common" : s.EntraId.TenantId;
        EntraClientId = s.EntraId.ClientId.StartsWith("00000000") ? string.Empty : s.EntraId.ClientId;
        EntraRedirectUri = string.IsNullOrWhiteSpace(s.EntraId.RedirectUri) ? "http://localhost" : s.EntraId.RedirectUri;
        EntraScopesCsv = s.EntraId.Scopes is { Length: > 0 } ? string.Join(", ", s.EntraId.Scopes) : "User.Read";
        EntraUseBroker = s.EntraId.UseBroker;

        FalconCloud = string.IsNullOrWhiteSpace(s.Falcon.Cloud) ? "us-1" : s.Falcon.Cloud;
        FalconClientId = s.Falcon.ClientId;
        FalconClientSecret = s.Falcon.ClientSecret;
        FalconHttpTimeoutSeconds = s.Falcon.HttpTimeoutSeconds > 0 ? s.Falcon.HttpTimeoutSeconds : 30;

        ExfilPresignedUrlTemplate = s.Exfil.PresignedUrlTemplate;
    }

    private AppConfigSnapshot BuildSnapshot() => new()
    {
        EntraId = new EntraConfigSection
        {
            TenantId = EntraTenantId.Trim(),
            ClientId = EntraClientId.Trim(),
            RedirectUri = EntraRedirectUri.Trim(),
            Scopes = EntraScopesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            UseBroker = EntraUseBroker
        },
        Falcon = new FalconConfigSection
        {
            Cloud = FalconCloud,
            ClientId = FalconClientId.Trim(),
            ClientSecret = FalconClientSecret.Trim(),
            HttpTimeoutSeconds = FalconHttpTimeoutSeconds
        },
        Exfil = new ExfilConfigSection
        {
            PresignedUrlTemplate = ExfilPresignedUrlTemplate.Trim()
        }
    };

    [RelayCommand]
    private async Task TestFalcon()
    {
        IsBusy = true; BusyMessage = "Conectando ao Falcon…";
        FalconTestResult = null;
        try
        {
            var snap = BuildSnapshot();
            var r = await _tester.TestFalconAsync(snap.Falcon).ConfigureAwait(true);
            FalconTestSuccess = r.Success;
            var latency = r.Latency.HasValue ? $" ({r.Latency.Value.TotalMilliseconds:N0} ms)" : "";
            FalconTestResult = (r.Success ? "✓ " : "✗ ") + r.Message + latency + (r.Code is null ? "" : $" [{r.Code}]");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task TestEntra()
    {
        IsBusy = true; BusyMessage = "Validando configuração Entra…";
        EntraTestResult = null;
        try
        {
            var snap = BuildSnapshot();
            var r = await _tester.TestEntraAsync(snap.EntraId).ConfigureAwait(true);
            EntraTestSuccess = r.Success;
            EntraTestResult = (r.Success ? "✓ " : "✗ ") + r.Message + (r.Code is null ? "" : $" [{r.Code}]");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task Save()
    {
        SaveResult = null;
        try
        {
            var snap = BuildSnapshot();
            _store.Save(snap);
            _snapshot = snap;
            SaveSuccess = true;
            SaveResult = "✓ Configuração salva em " + _store.FilePath;
            await Task.Delay(150).ConfigureAwait(true);

            var reply = MessageBox.Show(
                "Configuração salva.\n\nReiniciar a aplicação agora para aplicar?\n(Recomendado — a sessão atual continua usando a config antiga.)",
                "CyberThrust.IRIS — Configuração",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.Yes);

            if (reply == MessageBoxResult.Yes)
            {
                var exe = Process.GetCurrentProcess().MainModule?.FileName;
                if (exe is not null)
                {
                    System.Diagnostics.Process.Start(exe);
                    Application.Current.Shutdown();
                }
            }
        }
        catch (Exception ex)
        {
            SaveSuccess = false;
            SaveResult = "✗ Falha ao salvar: " + ex.Message + " [IRIS-CFG-7005]";
        }
    }

    [RelayCommand]
    private void OpenConfigFolder()
    {
        try
        {
            var folder = System.IO.Path.GetDirectoryName(_store.FilePath);
            if (folder is not null) System.Diagnostics.Process.Start("explorer.exe", folder);
        }
        catch { }
    }
}
