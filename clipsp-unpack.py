from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.api import *
from qiling.os.windows.structs import *
from qiling import *

@winsdkapi(cc=STDCALL, replace_params={"FastMutex": POINTER})
def hook_ExAcquireFastMutex(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={"FastMutex": POINTER})
def hook_ExReleaseFastMutex(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={"FastMutex": POINTER})
def hook_KeReleaseGuardedMutex(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={
        "VirtualAddress": POINTER,
        "Length": ULONG,
        "SecondaryBuffer": BOOLEAN,
        "ChargeQuota": BOOLEAN,
        "Irp": POINTER,
    })
def hook_IoAllocateMdl(ql, address, params):
    objcls = {
        QL_ARCH.X86   : MDL32,
        QL_ARCH.X8664 : MDL64
    }[ql.archtype]

    mdl = objcls() # MDL64()
    addr = ql.os.heap.alloc(ctypes.sizeof(objcls))  

    mdl.Next.value = 0
    mdl.Size = params['Length']
    mdl.MdlFlags = 1 # locked
    mdl.Process.value = ql.eprocess_address    
    mdl.MappedSystemVa.value = params['VirtualAddress']
    mdl.StartVa.value = params['VirtualAddress']
    mdl.ByteCount = params['Length']
    mdl.ByteOffset = 0

    ql.mem.write(addr, bytes(mdl)[:])
    
    return addr


@winsdkapi(cc=STDCALL, replace_params={"MemoryDescriptorList": POINTER,"AccessMode": ULONG,"Operation": ULONG})
def hook_MmProbeAndLockPages(ql, addr, params):
    return None


# might need to update MDL VA member
@winsdkapi(cc=STDCALL, replace_params={
        "MemoryDescriptorList": POINTER,
        "VirtualAddress": POINTER,
        "Size": ULONG,
        "Flags": ULONG,
    })
def hook_MmChangeImageProtection(ql, addr, params):
    return True


@winsdkapi(cc=STDCALL, replace_params={"AddressWithinSection": POINTER})
def hook_MmLockPagableImageSection(ql, addr, params):
    return params["AddressWithinSection"]


@winsdkapi(cc=STDCALL, replace_params={"ImageSectionHandle": POINTER})
def hook_MmUnlockPagableImageSection(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={"MemoryDescriptorList": POINTER})
def hook_MmUnlockPages(ql, addr, params):
    MemoryDescriptorList = params['MemoryDescriptorList']
    
    if ql.archtype == QL_ARCH.X8664:
        mdl_buffer = ql.mem.read(MemoryDescriptorList, ctypes.sizeof(MDL64))
        mdl = MDL64.from_buffer(mdl_buffer)
        mdl.Flags = 0 
    else:
        mdl_buffer = ql.mem.read(MemoryDescriptorList, ctypes.sizeof(MDL32))
        mdl = MDL32.from_buffer(mdl_buffer)
        mdl.Flags = 0

    ql.mem.write(addr, bytes(mdl)[:])


@winsdkapi(cc=STDCALL, replace_params={"Mdl": POINTER})
def hook_IoFreeMdl(ql, addr, params):
    addr = params['Mdl']
    ql.os.heap.free(addr)
    
    return None


@winsdkapi(cc=STDCALL, replace_params={"BaseAddress": POINTER, "MemoryDescriptorList": POINTER})
def hook_MmUnmapLockedPages(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={"PushLock": POINTER, "Flags": ULONG})
def hook_FltAcquirePushLockSharedEx(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={"PushLock": POINTER, "Flags": ULONG})
def hook_FltAcquirePushLockExclusiveEx(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={"PushLock": POINTER, "Flags": ULONG})
def hook_FltReleasePushLockEx(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, replace_params={"PushLock": POINTER})
def hook_FltInitializePushLock(ql, addr, params):
    return None


# read string from memory address
def readstr_wide(ql, addr):
    res = ""
    while True:
        # read one byte at a time
        c = ql.mem.read(addr, 2).decode()
        if c == '\x00\x00':
            break
        res += c
        addr += 2
    return res


@winsdkapi(cc=STDCALL, replace_params={
        "SourceID": POINTER,
        "CustomValue": POINTER,
        "DefaultPath": POINTER,
        "StateLocationType": ULONG,
        "TargetPath": POINTER,
        "BufferLengthIn": ULONG,
        "BufferLengthOut": POINTER,
    })
def hook_RtlGetPersistedStateLocation(ql, address, params):
    srcid = params["SourceID"]
    custom = params["CustomValue"]
    state_type = params["StateLocationType"]
    target = params["TargetPath"]

    keys = ["\Registry\Machine\System\CurrentControlSet\Control\StateSeparation\RedirectionMap\Keys",
            "\Registry\Machine\System\CurrentControlSet\Control\StateSeparation\RedirectionMap\Files"]

    key = keys[state_type]
    print(f"key: {key}")
    print(f"srcid: {readstr_wide(ql, srcid)} {readstr_wide(ql, custom)}")
    
    ql.os.registry_manager.access(key)
    
    return 0


def trace(ql, address, size, md):
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


def dump_mem(ql):
    mem = ql.mem.read(0x1C00F3000, 0x1000)
    with open("unpacked.sys", "wb") as f: 
        f.write(mem) # write extracted code to a binary file

    ql.emu_stop()


if __name__ == "__main__":
    ql = Qiling(["ClipSp.sys"], "D:\\qiling\\examples\\rootfs\\x8664_windows", verbose=QL_VERBOSE.DEBUG)

    md = ql.create_disassembler()
    md.detail = True

    ql.set_api("ExAcquireFastMutex", hook_ExAcquireFastMutex)
    ql.set_api("ExReleaseFastMutex", hook_ExReleaseFastMutex)
    ql.set_api("IoAllocateMdl", hook_IoAllocateMdl)
    ql.set_api("MmProbeAndLockPages", hook_MmProbeAndLockPages)
    ql.set_api("MmChangeImageProtection", hook_MmChangeImageProtection)
    ql.set_api("MmLockPagableImageSection", hook_MmLockPagableImageSection)
    ql.set_api("MmUnlockPages", hook_MmUnlockPages)
    ql.set_api("IoFreeMdl", hook_IoFreeMdl)
    ql.set_api("MmUnmapLockedPages", hook_MmUnmapLockedPages)
    ql.set_api("KeReleaseGuardedMutex", hook_KeReleaseGuardedMutex)
    ql.set_api("FltAcquirePushLockSharedEx", hook_FltAcquirePushLockSharedEx)
    ql.set_api("FltReleasePushLockEx", hook_FltReleasePushLockEx)
    ql.set_api("MmUnlockPagableImageSection", hook_MmUnlockPagableImageSection)
    ql.set_api("FltAcquirePushLockExclusiveEx", hook_FltAcquirePushLockExclusiveEx)
    ql.set_api("RtlGetPersistedStateLocation", hook_RtlGetPersistedStateLocation)
    ql.set_api("FltInitializePushLock", hook_FltInitializePushLock)

    ql.reg.rcx = 0
    ql.reg.rdx = ql.os.heap.alloc(0x30)

    # ql.hook_code(trace, user_data=md)    
    ql.run(begin=0x1C00BB100, end=0x1C00BB17E)
