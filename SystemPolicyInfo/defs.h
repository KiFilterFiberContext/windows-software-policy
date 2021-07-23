#pragma once


//
// struct naming is inferred
//

//
// -- clipsp overview (wip) --
// naming convention: Client License System Policy
//
// clipsp has no valid PDB in the MS symbol server unlike most system libraries
// loading the PDB in IDA will produce invalid instruction disassembly in sections
// however, symbol information is present in the pdb file
//
// llvm-pdbutil.exe dump -publics .\clipsp.pdb | Select-String ClipSp
// 
// 46852 | S_PUB32[ size = 44 ] `ClipSpIsDeviceLicensePresent`
// 55992 | S_PUB32[ size = 52 ] `ClipSpInsertTBActivationPolicyValue`
// 59096 | S_PUB32[ size = 32 ] `ClipSpDecryptFek`
// 35228 | S_PUB32[ size = 52 ] `ClipSpCreateDirectoryLicenseHeader`
// 45600 | S_PUB32[ size = 36 ] `ClipSpIsAppLicensedEx`
// 56444 | S_PUB32[ size = 36 ] `ClipSpIsWindowsToGo`
// 32460 | S_PUB32[ size = 40 ] `ClipSpDumpLicenseGroup`
// 48524 | S_PUB32[ size = 36 ] `ClipSpUpdateLicense`
// 71156 | S_PUB32[ size = 36 ] `ClipSpUninitialize`
// 36808 | S_PUB32[ size = 52 ] `ClipSpCreateFileLicenseHeaderAndKey`
// 61420 | S_PUB32[ size = 32 ] `ClipSpAcRequest`
// 38676 | S_PUB32[ size = 72 ] `_tlgDefineProvider_annotation__Tlgg_hClipSpProviderProv`
// 30388 | S_PUB32[ size = 28 ] `ClipSpFreeFek`
// 72560 | S_PUB32[ size = 28 ] `ClipSpClear`
// 35508 | S_PUB32[ size = 48 ] `ClipSpQueryLicenseValueFromHost`
// 60680 | S_PUB32[ size = 48 ] `ClipSpLicenseEfsHeaderContainsFek`
// 34312 | S_PUB32[ size = 36 ] `ClipSpCheckLicense`
// 47976 | S_PUB32[ size = 40 ] `ClipSpGetLicenseChallange`
// 45532 | S_PUB32[ size = 32 ] `ClipSpClepSign`
// 62960 | S_PUB32[ size = 28 ] `ClipSpClepKdf`
// 51836 | S_PUB32[ size = 36 ] `ClipSpDecryptFekEx`
// 70332 | S_PUB32[ size = 48 ] `ClipSpGetBaseContentKeyFromKeyID`
// 46224 | S_PUB32[ size = 36 ] `ClipSpRemoveLicense`
// 36164 | S_PUB32[ size = 56 ] `ClipSpGetActivationPolicyValueFromCache`
// 38064 | S_PUB32[ size = 44 ] `ClipSpGetCurrentHardwareID`
// 35636 | S_PUB32[ size = 44 ] `ClipSpQueryCachedOptionalInfo`
// 38476 | S_PUB32[ size = 52 ] `ClipSpGetBaseContentKeyFromLicense`
// 63444 | S_PUB32[ size = 28 ] `ClipSpAcHmac`
// 37552 | S_PUB32[ size = 28 ] `ClipSpDump`
// 34520 | S_PUB32[ size = 32 ] `ClipSpInitialize`
// 40992 | S_PUB32[ size = 48 ] `ClipSpCreateLicenseKeyIDEfsHeader`
// 40288 | S_PUB32[ size = 40 ] `ClipSpUpdateOsLicenseBlob`
// 49032 | S_PUB32[ size = 36 ] `ClipSpIsAppLicensed`
// 57056 | S_PUB32[ size = 44 ] `ClipSpCreateLicenseEfsHeader`
// 56076 | S_PUB32[ size = 40 ] `ClipSpGetAppPolicyValue`
//
//
// clipsp contains 6 PAGEwx sections with high (over 7) entropy
// potentially contains packed code
// service routine segments (.PAGEwx) must be unpacked prior to execution
//
// likely protected by WarBird (microsoft obfuscator)
// pdb file info includes WarbirdRuntimeGenAsm object file 
//
// nt!g_kernelCallbacks contain callbacks for system policy services
// kd> dqs nt!g_kernelCallbacks
// fffff801`32d3b350  00000000`00000001
// fffff801`32d3b358  fffff801`354c6c20 clipsp + 0xb6c20
// fffff801`32d3b360  fffff801`354c2c30 clipsp + 0xb2c30
// ...
//
// g_kernelCallbacks is initialized in clipsp!ClipSpInitialize
// nt!PspInitializeServerSiloDeferred -> unnamed function -> nt!ExInitLicenseData -> nt!ClipInitHandles -> clipsp!ClipSpInitialize
//
// license policy initialized from registery hive ControlSet001\Control\ProductOptions 
// license state stored in PspHostSiloGlobals->ExpLicenseState
// license state structure (_EXP_LICENSE_STATE) is undocumented in pdb type info 
//
// usermode interfaces with the software licensing API
// calls into clipc.dll (client licensing platform client) ?
// 
// global symbols reveal usage of Warbird UM cipher to encrypt/decrypt data passed into the system policy kernel service
// WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher and WarbirdUmGetDecryptionKey'::`2'::nDecryptionKey
// WarbirdUmGetEncryptionCipher'::`2'::EncryptionCipher and WarbirdUmGetEncryptionKey'::`2'::nEncryptionKey
//
// ... deal with clipsp unpacking...

//
// 4 bytes (ulong)
// methods are mostly undocumented or have no symbol names
//
typedef enum _SYSTEM_POLICY_CLASS
{
    QueryPolicy,
    UpdatePolicies,
    AuthenticateCaller,
    WaitForDisplayWindow = 5,
    FileUsnQuery = 22,
    FileIntegrityUpdate,
    FileIntegrityQuery,
    UpdateLicense = 100,
    RemoveLicense,
    NotImplemented,
    GetLicenseChallenge = 105,
    IsAppLicensed = 109,
    ClepSign = 112,
    ClepKdf,
    UpdateOsPfnInRegistry = 204, 
    CheckLicense,
    GetCurrentHardwareID,
    GetAppPolicyValue = 208
} SYSTEM_POLICY_CLASS;

//
// 160 byte structure
// used for decrypting and encrypting policy data
// +-------------------+ +-------------------+
// |       Size        | |                   |        Block B
// +-------------------+ +-------------------+     ------------  0x0
// |                   | |                   |  ^
// |                   | |    0xC998E51B     |  |
// |   Function Args   | |    0xA3A9632E     |  |
// |      8 bytes      | |                   |  |    128 bytes
// |                   | |                   |  |
// |                   | |    0x00000000     |  |
// |                   | |                   |  |
// +-------------------+ +-------------------+      ----------   0x7E
// |                   | |                   |
// |    Fn Ptr Index   | |    0x050B1902     |  ^    32 bytes
// |      2 bytes      | |    0x1F1F1F1F     |  |                0x9E
// +-------------------+ +-------------------+  |   ----------   0xA0
// 
typedef struct _WB_CIPHER
{
    //
    // arguments to encryption routines (starts from second to last)
    // index A routine: (i-6, i-5, i-4, i-3) 
    // index B routine: (i-2, i-1, i, i+1)
    //
    UCHAR FnArgs[128];

    //
    // index for encryption routine fn table (starts from second to last)
    // only called when index is below 0x1F
    // copied in two byte pairs (A, B)
    //
    UCHAR FnIndex[32];
} WB_CIPHER, * PWB_CIPHER;

//
// key used in argument encryption andd decryption
// 64 bit
//
typedef struct PWB_KEY
{
    ULONGLONG Key;
} WB_KEY, * PWB_KEY;

//
// licensemanagerapi!InvokeLicenseManagerRequired -> NtQuerySystemInformation -> ExpQuerySystemInformation -> ExHandleSPCall2 -> SPCall2ServerInternal -> SPCallServerHandleIsAppLicensed -> (no symbols) nt!g_kernelCallbacks[13] (ClipSpIsAppLicensed)
//
typedef struct _SP_APP_LICENSED_BODY
{
    ULONG UnknownSizeA;
    ULONGLONG UnknownA; // de d0 a6 da a5 10 00 00

    ULONG UnknownSizeB;
    ULONG UnknownB; // 3

    ULONG MaxStringSize;
    WCHAR AppName[ANYSIZE_ARRAY];

    ULONG UnknownSizeC; 
    WCHAR UnknownWideChar; // 0x00 
    
    ULONG UnknownSizeD; // 0x1c
    UCHAR UnknownD[28]; // 01 05 00 00 00 00 00 05 15 00 00 00 79 da-c9 84 23 e2 f9 82 2c 25 c0 58 e8 03 00 00

    ULONG UnknownSizeE;
    ULONG UnknownE; // 2
} SP_APP_LICENSED_BODY;

//
// Decrypted header
// Size specified in decrypted data
//
typedef struct _SP_DECRYPTED_HEADER
{
    ULONG PolicyTypeSize;
    SYSTEM_POLICY_CLASS PolicyType;

    ULONG EncyptArgSize;
    WB_CIPHER EncryptArgs;

    ULONG KeySize;
    WB_KEY EncryptKey;

    // SLS_APP_LICENSED_BODY Body;
} SP_DECRYPTED_HEADER;

//
// > 8 bytes
// encrypted data appended with xor checksum of decrypted data
//
typedef struct _SP_ENCRYPTED_HEADER
{
    UCHAR EncryptedBody[ANYSIZE_ARRAY];
    ULONGLONG XorChkKey;
} SLS_ENCRYPTED_HEADER;

//
// encrypted input size - 8 bytes (removing XorChkKey?)
// decrypted header data from block B decryption routine
//
typedef struct _SP_DECRYPTED_DATA
{
    ULONG ParameterCount;
    ULONG DecryptedSize;

    SP_DECRYPTED_HEADER HeaderData;

    ULONG a;
    USHORT b;
} SP_DECRYPTED_DATA;

//
// input/output structure for system call
// block sizes + 12 must equal input length
//
typedef struct _SP_ENCRYPTED_DATA
{
    ULONG EncryptedDataSize;
    SLS_ENCRYPTED_HEADER EncryptedHeaderData;

    ULONG DecryptArgSize;
    WB_CIPHER DecryptArgs;

    ULONG KeySize;
    WB_KEY DecryptKey;
} SP_ENCRYPTED_DATA, * PSP_ENCRYPTED_DATA;

//            Data
// +-------------------------+
// |                         |
// |         Header          |
// +-------------------------+
// |                         |
// |                         |
// |                         |
// |                         |
// |                         |
// |                         |
// |          Body           |
// |                         |
// |                         |
// |                         |
// |                         |
// |                         |
// |                         |
// |                         |
// +-------------------------+
//

//
// 48 bytes
// struct manages all three policy blocks in kernel
// initial data is copied from POLICY_BLOCK header
// block data is allocated on paged pool (SLS software licensing server tag) and holds POLICY_BLOCK info
//
typedef struct _SP_DATA
{
    //
    // BlockA size > 0x8
    //
    ULONG EncryptedDataSize;
    ULONG ReservedA;
    PSP_ENCRYPTED_DATA EncryptedData;

    //
    // BlockB size == 0xA0 (160)
    //
    ULONG EncyptDecryptArgSize;
    ULONG ReservedB;
    PWB_CIPHER EncryptDecryptArgs;

    //
    // BlockC size == 0x8
    //
    ULONG KeySize;
    ULONG ReservedC;
    PWB_KEY EncryptDecryptKey;
} SP_DATA;
