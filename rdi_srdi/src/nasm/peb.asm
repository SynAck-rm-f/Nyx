bits 64
section .text

global get_ntdll

get_ntdll:
    xor     rax, rax
    mov     rax, [gs:0x60]
    mov     rax, [rax + 0x18]
    mov     rax, [rax + 0x20]
    mov     rax, [rax]
    mov     rax, [rax + 0x20]
    ret
    