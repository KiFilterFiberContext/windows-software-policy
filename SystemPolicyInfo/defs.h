#pragma once

static const UCHAR DecryptFnArgs[ 128 ] = {
    0xc9, 0x98, 0xe5, 0x1b, 0xa3, 0xa9, 0x63, 0x2e, 0x56, 0xe1, 0xe2, 0x53, 0xe0, 0x65, 0x77, 0x7c,
    0x3e, 0x26, 0x3d, 0x34, 0x5f, 0xb9, 0x87, 0xce, 0x86, 0xa9, 0xe7, 0xf2, 0x98, 0x08, 0x83, 0x14,
    0x85, 0x1e, 0x83, 0x91, 0x9d, 0xbd, 0x3c, 0xc3, 0x22, 0x0c, 0x21, 0xbe, 0x4a, 0x78, 0x05, 0xb2,
    0xce, 0x2d, 0x0e, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const UCHAR DecryptFnIndex[ 32 ] = {
    0x1d, 0x0e, 0x0f, 0x09, 0x1b, 0x01, 0x1a, 0x18, 0x1e, 0x05, 0x0b, 0x19, 0x02, 0x1f, 0x1f, 0x1f,
    0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f
};

typedef struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    WCHAR* Buffer;                                                          //0x8
} UNICODE_STRING;

//
// 48 bytes
// struct manages all three policy blocks in kernel
// initial data is copied from POLICY_BLOCK header
// block data is allocated on paged pool (SLS software licensing server tag) and holds POLICY_BLOCK info
//
typedef struct _SLS_DATA
{
    //
    // BlockA size > 0x8
    //
    ULONG EncryptedDataSize;
    ULONG ReservedA;
    PSLS_ENCRYPTED_HEADER EncryptedData;

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
} SLS_DATA;

//
// 4 bytes (ulong)
// other methods are undocumented 
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
    IsAppLicense = 109,
    ClepKdf = 113,
    UpdateOsPfnInRegistry = 204, // undocumented?
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
// Decrypted data
// Size specified in decrypted header
//
typedef struct _SLS_DECRYPTED_DATA
{
    ULONG PolicyTypeSize;
    SYSTEM_POLICY_TYPE PolicyType;

    ULONG EncyptArgSize;
    SLS_ENCRYPT_DECRYPT_ARGS EncryptArgs;

    ULONG KeySize;
    SLS_KEY EncryptKey;

    ULONG PolicySize;
    UNICODE_STRING PolicyName;


} SLS_DECRYPTED_DATA;

#define SLS_DATA_SIZE 296

//
// > 8 bytes
// encrypted data appended with xor checksum of decrypted data
//
typedef struct _SLS_ENCRYPTED_DATA
{
    UCHAR EncryptedData[ SLS_DATA_SIZE ];
    ULONGLONG XorChkKey;
} SLS_ENCRYPTED_DATA;

//
// encrypted input size - 8 bytes (removing XorChkKey?)
// decrypted header data from block B decryption routine
//
typedef struct _SLS_DECRYPTED_HEADER
{
    ULONG ArgCount;

    ULONG DecryptedDataSize;
    SLS_DECRYPTED_DATA Data;

    UCHAR Unk[6];
} SLS_DECRYPTED_HEADER;

//
// input/output structure for system call
// block sizes + 12 must equal input length
//
typedef struct _SLS_ENCRYPTED_HEADER
{
    ULONG EncryptedDataSize;
    SLS_ENCRYPTED_DATA EncryptedData;

    ULONG DecryptArgSize;
    SLS_ENCRYPT_DECRYPT_ARGS DecryptArgs;

    ULONG KeySize;
    SLS_KEY DecryptKey;
} SLS_ENCRYPTED_HEADER, * PSLS_ENCRYPTED_HEADER;
