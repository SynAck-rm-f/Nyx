#include <windows.h>  
#include <stdio.h>

unsigned char payload[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP x4
    0xC3                       // RET
};
unsigned int payload_len = sizeof(payload);  

int main(void) {  
    printf("[*] Test 1: VirtualAlloc\n");
    void* buffer = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        printf("[-] VirtualAlloc FAILED\n");
        return 1;
    }
    printf("[+] VirtualAlloc OK: %p\n", buffer);

    printf("[*] Test 2: memcpy\n");
    memcpy(buffer, payload, payload_len);
    printf("[+] memcpy OK\n");

    printf("[*] Test 3: VirtualProtect\n");
    DWORD oldprotect = 0;
    if (!VirtualProtect(buffer, payload_len, PAGE_EXECUTE_READ, &oldprotect)) {
        printf("[-] VirtualProtect FAILED\n");
        return 1;
    }
    printf("[+] VirtualProtect OK\n");

    printf("[*] Calling shellcode...\n");
    void (*func_ptr)() = (void(*)())buffer;
    func_ptr();
    
    printf("[+] Shellcode returned!\n");
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}