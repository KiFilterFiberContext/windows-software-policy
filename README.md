# SystemPolicyInfo
Research on the client licensing system in the Windows kernel exposed from the `SystemPolicyInformation` class in the `NtQuerySystemInformation` system call.
**This section is incomplete and will be continously updated**

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

Microsoft WarBird has been researched in prior years and exposes various different obfuscation passes including virtual-machine obfuscation, code packing, and even functionality integrated the windows kernel to [decrypt and execute signed payloads on the heap using a feistel cipher](https://www.youtube.com/watch?v=gu_i6LYuePg) by exposing a special system information class: `SystemControlFlowInformation`. 

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
    GetLicenseChallenge = 105,
    IsAppLicensed = 109,
    ClepSign = 112,
    ClepKdf,
    UpdateOsPfnInRegistry = 204, 
    GetCurrentHardwareID = 206,
    GetAppPolicyValue = 208
} SYSTEM_POLICY_CLASS;
```
## License Initialization
A few of the licensing routines will further dispatch to a function located in a global table, `nt!g_kernelCallbacks`.  This global function table contains function pointers inside of `clipsp.sys`, which handles client license system policy.  During license data initialization, the kernel will first setup license state in a global server silo (`PspHostSiloGlobals->ExpLicenseState`) and will load license values from the registry under `ProductOptions`.  It will then call `ExInitLicenseData` which will update the license data and setup [Kernel Data Production](https://www.microsoft.com/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/).  The routine will eventually call `ClipInitHandles`, which initializes globals used for client licensing callbacks along with `g_kernelCallbacks`.  The kernel does not actually setup the global kernel callback table in `ClipInitHandles`, but instead it will pass the table to `ClipSpInitialize` located in `clipsp.sys`.  

## Code Unpacking

The client licensing system policy image (`clipsp`) is responsible for handling the internals of system policy functionality in the kernel.  As such, it is obfuscated with Microsoft WarBird to prevent reverse engineering.  The image contains several sections with high entropy (`PAGEwx1` etc.) and names that indicate it will be unpacked and executed during runtime.

Despite having a PDB, it is intentionally not aligned to the image and will produce invalid naming if loaded in IDA.  Manually parsing the PDB will provide symbol names that will be useful for identifying components while reversing the image.

Internal subroutines that are invoked from the global callback table or initialization routines will unpack the code prior to execution and repack afterward.  The image will allocate several [memory descriptor lists (MDLs)](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls) to remap the physical pages to a rwx virtual address in system space.  It will then unpack the code using WarBird and pass the arguments to the real routine.  A simple method to automatically unpack the encrypted code sections is to emulate the decryption routines with a binary emulation framework such as Qiling.  I have written a simple [unpacker script](https://github.com/encls/SystemPolicyInfo/blob/master/clipsp-unpack.py) Python that will emulate various kernel APIs and dump the unpacked code once the MDL is freed.

![image](https://user-images.githubusercontent.com/51222153/126401867-818f7c0d-5b3e-447f-91fc-2d8db6210dec.png)

## License Internals
Further analysis can be done after replacing the packed sections with the unpacked code.  `ClipSpInitialize` will call onto `SpInitialize` to populate `g_kernelCallbacks`, setup registry keys and initialize [CNG Providers](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers) and crytographic keys.
