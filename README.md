# SystemPolicyInfo
Research on the client licensing system in the Windows kernel exposed from the `SystemPolicyInformation` class in the `NtQuerySystemInformation` system call.

## Overview
There are two primary usermode services that interact directly with client licensing: `clipc.dll` (Client Licensing Platform Client) and `clipsvc.dll` (Client License Service).  The kernel image that handles client license queries is `clipsp.sys` (Client License System Policy).  As the focus is on the internals of the licensing routines in the kernel, not much will be mentioned about the usermode services.

The client starts the license service through the service manager and communicates with the service through [remote procedure calls (RPC)](https://docs.microsoft.com/en-us/windows/win32/rpc/rpc-start-page).  The service registers several handlers that are used in the [Software Licensing API](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/secslapi/software-licensing-api-portal).  

Handlers that must interface with kernel licensing information will invokve `NtQuerySystemInformation` with the `SystemPolicyInformation` information class.  The `SystemPolicyInformation` class structure for data transfer has been documented by [Geoff Chappell](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/policy.htm).  The structure is shown below:
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
The reference page in MSDN for the information class offers an even more incomplete structure and suggests using the higher-level SL API.  As such, the internal structures used by the kernel are undocumented.  Every internal structure documented in my research has been reverse engineered and named according to its inferred usage and may not accurately reflect the actual internal use.  

## Input Structure
Brief reverse engineering of the ClipSVC license handlers reveal that input and output structures are encrypted and decrypted using a cipher implemented by Microsoft's internal obfuscator: WarBird.  
```cpp
// setup decryption cipher and key
pDecryptionCipher = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xA0);

if ( !pDecryptionCipher )
    goto LABEL_2;

decryptionCipher = pDecryptionCipher;       

*pDecryptionCipher = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[0];
pDecryptionCipher[1] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[1];
pDecryptionCipher[2] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[2];
pDecryptionCipher[3] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[3];
pDecryptionCipher[4] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[4];
pDecryptionCipher[5] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[5];
pDecryptionCipher[6] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[6];
pDecryptionCipher[7] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[7];
pDecryptionCipher[8] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[8];
pDecryptionCipher[9] = `WarbirdUmGetDecryptionCipher'::`2'::DecryptionCipher[9];

pDecryptionKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8);
if ( !pDecryptionKey )
{
    LABEL_2:
    ReturnStatus = STATUS_NO_MEMORY;
    goto END;
}
decryptionKey = pDecryptionKey;
*pDecryptionKey = `WarbirdUmGetDecryptionKey'::`2'::nDecryptionKey;
```

Microsoft WarBird has been researched in prior years and exposes various different obfuscation passes including virtual-machine obfuscation, code packing, and even functionality integrated the windows kernel to [decrypt and execute signed payloads on the heap using a feistel cipher](https://www.youtube.com/watch?v=gu_i6LYuePg) by exposing a special system information class: `SystemControlFlowTransition`. 

The internal structure parsed by the kernel consists three blocks of data containing the encrypted data, the decryption arguments for the WarBird cipher, and a 64bit decryption key.  The decrypted input data contains the policy information type, argument count, and the cipher arguments and key to encrypt the data.  An XOR checksum for the decrypted data is appended onto the encrypted data and is verified after decryption.  The decryption cipher block is formatted with arguments for cipher subroutines positioned at the top and arguments at the bottom.  The kernel will pass the parameters in reverse order for 16 iterations.  The keys and cipher arguments are hardcoded depending on the policy class.
```cpp
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
typedef struct _WB_CIPHER
{
    UCHAR FnArgs[128];
    UCHAR FnIndex[32];
} WB_CIPHER, * WB_CIPHER;

typedef struct PWB_KEY
{
    ULONGLONG Key;
} WB_KEY, * PWB_KEY;

typedef struct _SP_ENCRYPTED_HEADER
{
    UCHAR EncryptedBody[ SP_DATA_SIZE ];
    ULONGLONG XorChkKey;
} SP_ENCRYPTED_HEADER;

typedef struct _SP_ENCRYPTED_DATA
{
    ULONG EncryptedDataSize;
    SP_ENCRYPTED_HEADER EncryptedHeaderData;

    ULONG DecryptArgSize;
    WB_CIPHER DecryptArgs;

    ULONG KeySize;
    WB_KEY DecryptKey;
} SP_ENCRYPTED_DATA, * PSP_ENCRYPTED_DATA;
```

The decrypted input structure contains the amount of parameters relative to the policy information type and a header that specifies the information type along with arguments needed for the WarBird cipher to encrypt the data.
```cpp
typedef struct _SP_DECRYPTED_HEADER
{
    ULONG PolicyTypeSize;
    SYSTEM_POLICY_CLASS PolicyType;

    ULONG EncyptArgSize;
    WB_CIPHER EncryptArgs;

    ULONG KeySize;
    WB_KEY EncryptKey;

    SP_BODY Body;
} SP_DECRYPTED_HEADER;

typedef struct _SP_DECRYPTED_DATA
{
    ULONG ParameterCount;
    ULONG DecryptedSize;

    SP_DECRYPTED_HEADER HeaderData;

    ULONG a;
    USHORT b;
} SP_DECRYPTED_DATA;
```
Once the WarBird cipher and keys needed to encrypt and decrypt the data are prepared, the data is encrypted and execution is passed onto `NtQuerySystemInformation`.  The information class switch table will eventually dispatch the data to `SPCall2ServerInternal`, where it will decrypt and verify the data and invoke one of the internal license routines.  A few of the reversed policy classes are shown:
```cpp
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
    CreateLicenseEfsHeader,
    LicenseEfsHeaderContainsFek,
    GetLicenseChallange,
    GetBaseContentKeyFromLicense,
    GetBaseContentKeyFromKeyID,
    IsAppLicensed = 109,
    DumpLicenseGroup,
    Clear,
    ClepSign,
    ClepKdf,
    UpdateOsLicenseBlob = 204, 
    CheckLicense,
    GetCurrentHardwareID,
    CreateLicenseKeyIDEfsHeader,
    GetAppPolicyValue,
    QueryCachedOptionalInfo,
    AcRequest,
    AcHmac,
    UpdateImdsResponse
} SYSTEM_POLICY_CLASS;
```
## License Initialization
A few of the licensing routines will further dispatch to a function located in a global table, `nt!g_kernelCallbacks`.  This global function table contains function pointers inside of `clipsp.sys`, which handles client license system policy.  During license data initialization, the kernel will first setup license state in a global server silo (`PspHostSiloGlobals->ExpLicenseState`) and will load license values from the registry under `ProductOptions`.  It will then call `ExInitLicenseData` which will update the license data and setup [Kernel Data Protection](https://www.microsoft.com/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/).  The routine will eventually call `ClipInitHandles`, which initializes globals used for client licensing callbacks along with `g_kernelCallbacks`.  The kernel does not actually setup the global kernel callback table in `ClipInitHandles`, but instead it will pass the table to `ClipSpInitialize` located in `clipsp.sys`.  

## Code Unpacking

The client licensing system policy image (`clipsp`) is responsible for handling the internals of system policy functionality in the kernel.  As such, it is obfuscated with Microsoft WarBird to prevent reverse engineering.  The image contains several sections with high entropy (`PAGEwx1` etc.) and names that indicate it will be unpacked and executed during runtime.

Clipsp will call upon the Warbird Runtime to unpack the code prior to execution and repack afterward.  The functions will allocate several [memory descriptor lists](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)  (MDLs) to remap the physical pages to a rwx virtual address in system space.  Dumping the image at runtime will not be reliable as the sections are repacked after execution and only those necessary for execution will be unpacked.  A simple method to automatically unpack the sections is to emulate the decryption routines with a binary emulation framework such as Qiling.  I have written a simple [unpacker script](https://github.com/encls/SystemPolicyInfo/blob/master/clipsp-unpack.py) in Python that will emulate various kernel APIs and dump the unpacked section once the MDL is freed.

## License Internals
Further analysis can be done after replacing the packed sections with the unpacked code.  `ClipSpInitialize` will call onto `SpInitialize` to populate `g_kernelCallbacks`, setup registry keys and initialize [CNG Providers](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/understanding-cryptographic-providers) and crytographic keys.

![image](https://user-images.githubusercontent.com/51222153/155431170-b1926650-e231-4bb7-a11e-ce54b9933f53.png)

The `SpInitializeDeviceExtension` subroutine will first verify access rights to a special registry key located at `\\Registry\\Machine\\System\\CurrentControlSet\\Control\\{7746D80F-97E0-4E26-9543-26B41FC22F79}` reserved for digital entitlement.  Access to the specific registry key is intended only for license use and attempts at accessing it from an unprivileged process will result in `ACCESS_DENIED`.  Furthermore, it will access several subkeys under the same key including `{A25AE4F2-1B96-4CED-8007-AA30E9B1A218}`, `{D73E01AC-F5A0-4D80-928B-33C1920C38BA}`, `{59AEE675-B203-4D61-9A1F-04518A20F359}`, `{FB9F5B62-B48B-45F5-8586-E514958C92E2}` and `{221601AB-48C7-4970-B0EC-96E66F578407}`.

Further reverse engineering of the individual callbacks requires reverse engineering of the `_EXP_LICENSE_STATE` structure in `_ESERVERSILO_GLOBALS`.

## References
- [Reversal of Warbird integration in the MSVC compiler](https://github.com/KiFilterFiberContext/warbird-obfuscate)
- [Warbird Runtime Reversed Engineered Code](https://github.com/KiFilterFiberContext/microsoft-warbird/)
- [Hooking ClipSp.sys for encrypted shellcode execution](https://github.com/KiFilterFiberContext/warbird-hook/)
