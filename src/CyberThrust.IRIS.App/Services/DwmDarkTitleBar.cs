using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace CyberThrust.IRIS.App.Services;

/// <summary>
/// Habilita a barra de título DARK do Windows 10 22H2+ / Windows 11 para uma
/// <see cref="Window"/> WPF — usa a flag DWMWA_USE_IMMERSIVE_DARK_MODE
/// (attribute 20 no Win11, ou 19 no Win10 build &lt; 19041).
/// </summary>
public static class DwmDarkTitleBar
{
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE_19H1 = 19;
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    [DllImport("dwmapi.dll", SetLastError = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    /// <summary>Aplica imediatamente (chame depois do Window.SourceInitialized).</summary>
    public static void Apply(Window window)
    {
        if (window is null) return;
        try
        {
            var handle = new WindowInteropHelper(window).EnsureHandle();
            var enabled = 1;
            // Tenta primeiro attribute 20 (Win11 / Win10 22H2); se falhar, tenta 19 (Win10 anterior).
            var hr = DwmSetWindowAttribute(handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref enabled, sizeof(int));
            if (hr != 0)
            {
                DwmSetWindowAttribute(handle, DWMWA_USE_IMMERSIVE_DARK_MODE_19H1, ref enabled, sizeof(int));
            }
        }
        catch { /* sem dwmapi → janela usa padrão Windows */ }
    }

    /// <summary>Hook de extensão para qualquer Window — atrasa pra SourceInitialized se necessário.</summary>
    public static void EnableFor(Window window)
    {
        if (window is null) return;
        if (window.IsLoaded) { Apply(window); return; }
        window.SourceInitialized += (_, _) => Apply(window);
    }
}
