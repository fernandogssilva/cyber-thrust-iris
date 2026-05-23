namespace CyberThrust.IRIS.Core.Errors;

/// <summary>
/// Catálogo central de códigos de erro do IRIS.
/// Formato: IRIS-{CATEGORIA}-{NUMERO}.
///   AUTH 1xxx — Autenticação Entra ID
///   CS   2xxx — CrowdStrike API / RTR
///   MEM  3xxx — Coleta e análise de memória
///   DSK  4xxx — Coleta e triagem de disco
///   NET  5xxx — Rede, HTTP, conectividade
///   UI   6xxx — Camada de apresentação WPF
///   CFG  7xxx — Configuração e secrets
///   PLG  8xxx — Plugins / módulos externos
///   SYS  9xxx — Sistema, OS, runtime
/// Toda exceção exibida ao usuário DEVE carregar um código deste enum.
/// </summary>
public enum IrisErrorCode
{
    // ───────────────── AUTH 1xxx ─────────────────
    AuthEntraInteractiveFailed       = 1001,
    AuthEntraSilentFailed            = 1002,
    AuthEntraTokenExpired            = 1003,
    AuthEntraConsentRequired         = 1004,
    AuthEntraMfaRequired             = 1005,
    AuthEntraConditionalAccessBlock  = 1006,
    AuthEntraInvalidClient           = 1007,
    AuthEntraTenantMismatch          = 1008,
    AuthEntraNoRolesClaim            = 1009,
    AuthDpapiUnseaFailed             = 1010,
    AuthAccountLocked                = 1011,

    // ───────────────── CS 2xxx ─────────────────
    CsOAuth2Failed                   = 2001,
    CsOAuth2Forbidden                = 2002,
    CsOAuth2InvalidCloud             = 2003,
    CsApiUnauthorized                = 2010,
    CsApiForbidden                   = 2011,
    CsApiRateLimited                 = 2012,
    CsApiServerError                 = 2013,
    CsApiBadGateway                  = 2014,
    CsApiTimeout                     = 2015,
    CsCapabilityProbeFailed          = 2020,
    CsModuleNotLicensed              = 2021,
    CsRtrSessionInitFailed           = 2030,
    CsRtrSessionExpired              = 2031,
    CsRtrCommandRejected             = 2032,
    CsRtrCommandTimeout              = 2033,
    CsRtrGetFileTooLarge             = 2034,
    CsRtrBatchPartialFailure         = 2035,
    CsRtrScriptMissing               = 2036,
    CsHostOffline                    = 2040,
    CsHostNotFound                   = 2041,
    CsHostContainmentFailed          = 2042,
    CsIocConflict                    = 2050,
    CsDetectionNotFound              = 2060,

    // ───────────────── MEM 3xxx ─────────────────
    MemCollectorNotFound             = 3001,
    MemXmemdumpFailed                = 3002,
    MemWinpmemFailed                 = 3003,
    MemDumpitFailed                  = 3004,
    MemInsufficientDiskOnHost        = 3010,
    MemUploadFailed                  = 3020,
    MemAnalysisFailed                = 3030,
    MemSupermemMissing               = 3031,
    MemVolatilityMissing             = 3032,
    MemMemprocfsMissing              = 3033,

    // ───────────────── DSK 4xxx ─────────────────
    DskKapeMissing                   = 4001,
    DskKapeExecutionFailed           = 4002,
    DskVelociraptorMissing           = 4003,
    DskVelociraptorExecutionFailed   = 4004,
    DskUacMissing                    = 4005,
    DskUacExecutionFailed            = 4006,
    DskExfilFailed                   = 4010,
    DskExfilPresignedExpired         = 4011,
    DskInsufficientDiskLocal         = 4020,
    DskParsingFailed                 = 4030,

    // ───────────────── NET 5xxx ─────────────────
    NetDnsResolutionFailed           = 5001,
    NetTlsHandshakeFailed            = 5002,
    NetProxyAuthRequired             = 5003,
    NetConnectivityCheckFailed       = 5004,
    NetCertificateInvalid            = 5005,
    NetWebView2NavigationFailed      = 5010,

    // ───────────────── UI 6xxx ─────────────────
    UiThemeLoadFailed                = 6001,
    UiWebView2RuntimeMissing         = 6002,
    UiViewBindingFailed              = 6003,
    UiNavigationFailed               = 6004,
    UiAssetMissing                   = 6005,

    // ───────────────── CFG 7xxx ─────────────────
    CfgFileMissing                   = 7001,
    CfgFileInvalid                   = 7002,
    CfgFieldMissing                  = 7003,
    CfgSecretMissing                 = 7004,
    CfgPathInvalid                   = 7005,
    CfgEntraSectionInvalid           = 7006,
    CfgFalconSectionInvalid          = 7007,

    // ───────────────── PLG 8xxx ─────────────────
    PlgBinaryMissing                 = 8001,
    PlgBinarySignatureInvalid        = 8002,
    PlgBinaryVersionTooOld           = 8003,
    PlgExternalToolCrashed           = 8004,

    // ───────────────── SYS 9xxx ─────────────────
    SysUnknown                       = 9000,
    SysOperationCanceled             = 9001,
    SysOutOfMemory                   = 9002,
    SysUnsupportedOs                 = 9003,
    SysElevationRequired             = 9004,
    SysFileSystemError               = 9005,
    SysSerializationError            = 9006
}

/// <summary>Métodos auxiliares para formatar e categorizar códigos de erro.</summary>
public static class IrisErrorCodeExtensions
{
    public static string ToCodeString(this IrisErrorCode code) => $"IRIS-{Category(code)}-{(int)code:D4}";

    public static string Category(this IrisErrorCode code) => ((int)code) switch
    {
        >= 1000 and < 2000 => "AUTH",
        >= 2000 and < 3000 => "CS",
        >= 3000 and < 4000 => "MEM",
        >= 4000 and < 5000 => "DSK",
        >= 5000 and < 6000 => "NET",
        >= 6000 and < 7000 => "UI",
        >= 7000 and < 8000 => "CFG",
        >= 8000 and < 9000 => "PLG",
        _ => "SYS"
    };

    /// <summary>Sinaliza se o erro provavelmente é transitório e merece retry.</summary>
    public static bool IsTransient(this IrisErrorCode code) => code switch
    {
        IrisErrorCode.CsApiRateLimited
        or IrisErrorCode.CsApiServerError
        or IrisErrorCode.CsApiBadGateway
        or IrisErrorCode.CsApiTimeout
        or IrisErrorCode.NetDnsResolutionFailed
        or IrisErrorCode.NetTlsHandshakeFailed
        or IrisErrorCode.NetConnectivityCheckFailed
        or IrisErrorCode.CsRtrCommandTimeout => true,
        _ => false
    };
}
