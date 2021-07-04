#include <stdio.h>
#include <windows.h>

#include "defs.h"

typedef NTSTATUS( NTAPI* pNtQuerySystemInformation )( ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength );

#define SystemPolicyInformation 134

typedef struct _SYSTEM_POLICY_INFORMATION
{
    PVOID InputData;
    PVOID OutputData;
    ULONG InputSize;
    ULONG OutputSize;
    ULONG Version;
    NTSTATUS Status;
} SYSTEM_POLICY_INFORMATION, * PSYSTEM_POLICY_INFORMATION;

int main( void )
{
    NTSTATUS status = 0;
    ULONG RetLength = 0;

    pNtQuerySystemInformation NtQuerySystemInformation = ( pNtQuerySystemInformation ) GetProcAddress( GetModuleHandleW( L"ntdll.dll" ), "NtQuerySystemInformation" );
    if ( !NtQuerySystemInformation )
        return 1;

    SYSTEM_POLICY_INFORMATION PolicyInput;

    SLS_ENCRYPTED_HEADER EncryptedData;
    SLS_ENCRYPTED_DATA SPEncryptedData;

    SLS_DECRYPTED_HEADER DecryptedData;
    SLS_DECRYPTED_DATA SPDecryptedData;

    SLS_ENCRYPT_DECRYPT_ARGS SPDecryptArgs;
    SLS_KEY SPDecryptKey;

    SLS_ENCRYPT_DECRYPT_ARGS SPEncryptArgs;
    SLS_KEY SPEncryptKey;

    //
    // setup initial decrypted (original) data
    //
    SPDecryptedData.PolicyTypeSize = sizeof( ULONG );
    SPDecryptedData.PolicyType = QueryPolicy;

    DecryptedData.ArgCount = 7;
    DecryptedData.DecryptedDataSize = 258; // EncryptedSize (w/out xorkey) - 14 decimal (280)
    
    //
    // setup input data decryption keys
    //
    SPDecryptKey.Key = 0x584ab5b117cb1ec8;

    //
    // setup input data decrypt arguments
    //
    memcpy( SPDecryptArgs.FnArgs, DecryptFnArgs, 128 );
    memcpy( SPDecryptArgs.FnIndex, DecryptFnIndex, 32 );



    printf( "status: 0x%08x\length: %i\n", status, RetLength );

    getchar();
    return 0;
}
