# SystemPolicyInfo
Notes for the `SystemPolicyInformation` class from the `NtQuerySystemInformation` syscall obtained through reverse engineering

## Overview
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

However, not much is known about the arguments passed into the structure.  Information on the class on [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_policy_information) suggests using [SL API](https://docs.microsoft.com/en-us/windows/win32/api/slpublic/) and the documented routines there.  These routines interface with the Windows software licensing server and likely invoke onto NtQuerySystemInformation internally. 
 
The corresponding service that deals with system policy queries (`0x67`) in `NtQuerySystemInformation` is `ExHandleSPCall2`.  
