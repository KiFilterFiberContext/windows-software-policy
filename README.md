# SystemPolicyInfo
Notes for the `SystemPolicyInformation` class from the `NtQuerySystemInformation` syscall obtained through reverse engineering

## Overview
This section is incomplete and will be continously updated.

The `SystemPolicyInformation` class structure for data transfer has been documented by [Geoff Chappell](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/policy.htm).  The structure is shown below:
```cpp
typedef struct _SYSTEM_POLICY_INFORMATION
{
    PVOID InputData;
    PVOID OutputData;
    ULONG InputSize;
    ULONG OutputSize;
    ULONG Version;
    NTSTATUS Status;
} SYSTEM_POLICY_INFORMATION, * PSYSTEM_POLICY_INFORMATION;
```

However, not much is known about the arguments passed into the structure.  Information on the class on [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_policy_information) suggests using [SL API](https://docs.microsoft.com/en-us/windows/win32/api/slpublic/) and the documented routines there.  These routines interface with the Windows software licensing server. 
 ...
The corresponding service that deals with system policy queries (`0x67`) in `NtQuerySystemInformation` is `ExHandleSPCall2`.  The routine will verify that the buffer resides in user address boundaries and will callout to `nt!SPCall2ServerInternal` from `KeExpandKernelStackAndCalloutEx` to expand the stack to `19456` bytes.  

The routine will first parse the input structure that looks like this after a bit of reversing:
```cpp
typedef struct _SLS_ENCRYPTED_DATA
{
    ULONG EncryptedDataSize;
    SLS_ENCRYPTED_HEADER EncryptedHeaderData;

    ULONG DecryptArgSize;
    SLS_ENCRYPT_DECRYPT_ARGS DecryptArgs;

    ULONG KeySize;
    SLS_KEY DecryptKey;
} SLS_ENCRYPTED_DATA, * PSLS_ENCRYPTED_DATA;
```
Note that argument and structure names are deduced from usage and may not represent the actual naming convention.
`SPCall2ServerInternal` will perform length validation checks on the buffer and will allocate a paged pool for managing each block of information.
```cpp
typedef struct _SP_DATA
{
    //
    // size > 0x8
    //
    ULONG EncryptedDataSize;
    ULONG ReservedA;
    PSLS_ENCRYPTED_DATA EncryptedData;

    //
    // size == 0xA0 (160)
    //
    ULONG EncyptDecryptArgSize;
    ULONG ReservedB;
    PSLS_ENCRYPT_DECRYPT_ARGS EncryptDecryptArgs;

    //
    // size == 0x8
    //
    ULONG KeySize;
    ULONG ReservedC;
    PSLS_KEY EncryptDecryptKey;
} SP_DATA;
```
