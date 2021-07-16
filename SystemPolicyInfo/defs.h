#pragma once

//
// 4 bytes (ulong)
// methods are mostly undocumented or have no symbol names
//
typedef enum _SYSTEM_POLICY_TYPE
{
    QueryPolicy = 0,
    UpdatePolicies,
    AuthenticateCaller,
    WaitForDisplayWindow = 5,
    FileUsnQuery = 22,
    FileIntegrityUpdate,
    FileIntegrityQuery,
    NotImplemented = 102,
    IsAppLicensed = 109,
    ClepSign = 112,
    ClepKdf,
    UpdateOsPFNInRegistry = 204, 
    GetAppPolicyValue = 208
} SYSTEM_POLICY_TYPE;

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
typedef struct _SLS_ENCRYPT_DECRYPT_ARGS
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
} SLS_ENCRYPT_DECRYPT_ARGS, * PSLS_ENCRYPT_DECRYPT_ARGS;

//
// key used in argument encryption andd decryption
// 64 bit
//
typedef struct _SLS_KEY
{
    ULONGLONG Key;
} SLS_KEY, * PSLS_KEY;

//
// licensemanagerapi!InvokeLicenseManagerRequired -> NtQuerySystemInformation -> ExpQuerySystemInformation -> ExHandleSPCall2 -> SPCall2ServerInternal -> SPCallServerHandleIsAppLicensed -> (no symbols) nt!g_kernelCallbacks[13] (clipsp.sys+0xb6ac0)
//
typedef struct _SLS_APP_LICENSED_BODY
{
    ULONG UnknownSizeA;
    ULONGLONG UnknownA; // de d0 a6 da a5 10 00 00

    ULONG UnknownSizeB;
    ULONG UnknownB; // 3

    ULONG MaxStringSize;
    WCHAR* AppName;

    ULONG UnknownSizeC; 
    USHORT UnknownC; // 0 wchar?

    ULONG UnknownSizeD; // 0x1c
    UCHAR Unknown[ 0x1C ]; // 01 05 00 00 00 00 00 05 15 00 00 00 79 da-c9 84 23 e2 f9 82 2c 25 c0 58 e8 03 00 00

    ULONG UnknownSizeE;
    ULONG UnknownE; // 2
} SLS_APP_LICENSED_BODY;

//
// Decrypted header
// Size specified in decrypted data
//
typedef struct _SLS_DECRYPTED_HEADER
{
    ULONG PolicyTypeSize;
    SYSTEM_POLICY_TYPE PolicyType;

    ULONG EncyptArgSize;
    SLS_ENCRYPT_DECRYPT_ARGS EncryptArgs;

    ULONG KeySize;
    SLS_KEY EncryptKey;

    SLS_APP_LICENSED_BODY Body;
} SLS_DECRYPTED_HEADER;

#define SLS_DATA_SIZE 296

//
// > 8 bytes
// encrypted data appended with xor checksum of decrypted data
//
typedef struct _SLS_ENCRYPTED_HEADER
{
    UCHAR EncryptedBody[ SLS_DATA_SIZE ];
    ULONGLONG XorChkKey;
} SLS_ENCRYPTED_HEADER;

//
// encrypted input size - 8 bytes (removing XorChkKey?)
// decrypted header data from block B decryption routine
//
typedef struct _SLS_DECRYPTED_DATA
{
    ULONG ParameterCount;
    ULONG DecryptedSize;

    SLS_DECRYPTED_HEADER Data;

    ULONG a;
    USHORT b;
} SLS_DECRYPTED_DATA;

//
// input/output structure for system call
// block sizes + 12 must equal input length
//
typedef struct _SLS_ENCRYPTED_DATA
{
    ULONG EncryptedDataSize;
    SLS_ENCRYPTED_HEADER EncryptedHeaderData;

    ULONG DecryptArgSize;
    SLS_ENCRYPT_DECRYPT_ARGS DecryptArgs;

    ULONG KeySize;
    SLS_KEY DecryptKey;
} SLS_ENCRYPTED_DATA, * PSLS_ENCRYPTED_DATA;

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
    PSLS_ENCRYPTED_DATA EncryptedData;

    //
    // BlockB size == 0xA0 (160)
    //
    ULONG EncyptDecryptArgSize;
    ULONG ReservedB;
    PSLS_ENCRYPT_DECRYPT_ARGS EncryptDecryptArgs;

    //
    // BlockC size == 0x8
    //
    ULONG KeySize;
    ULONG ReservedC;
    PSLS_KEY EncryptDecryptKey;
} SP_DATA;
