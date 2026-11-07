#include <cstdio>
#include <windows.h>

unsigned char payload[] = {
    0x90, 0x90, 0x90, 0x90, // NOP x4
    0xC3                    // RET
};
unsigned int payload_len = sizeof(payload);

int main(void)
{
    HANDLE h_process = NULL;
    void *p_buffer = NULL;
    DWORD cb_old_protect = 0;

    //////////////////////////////////////////////////////////////////////////
    // 1. Allocate memory
    //////////////////////////////////////////////////////////////////////////
    printf("[*] Test 1: VirtualAlloc\n");
    p_buffer = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
    if (!p_buffer)
    {
        printf("[-] VirtualAlloc FAILED\n");
        return 1;
    }

    printf("[+] VirtualAlloc OK: %p\n", p_buffer);

    //////////////////////////////////////////////////////////////////////////
    // 2. Copy payload
    //////////////////////////////////////////////////////////////////////////
    printf("[*] Test 2: memcpy\n");
    memcpy(p_buffer, payload, payload_len);
    printf("[+] memcpy OK\n");

    //////////////////////////////////////////////////////////////////////////
    // 3. Flip protection and execute
    //////////////////////////////////////////////////////////////////////////
    printf("[*] Test 3: VirtualProtect\n");
    if (!VirtualProtect(p_buffer, payload_len, PAGE_EXECUTE_READ,
                        &cb_old_protect))
    {
        printf("[-] VirtualProtect FAILED\n");
        return 1;
    }

    printf("[+] VirtualProtect OK\n");
    printf("[*] Calling shellcode...\n");

    ((void (*)())p_buffer)();

    printf("[+] Shellcode returned!\n");
    VirtualFree(p_buffer, 0, MEM_RELEASE);
    return 0;
}
