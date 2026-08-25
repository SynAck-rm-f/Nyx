BITS 64
global _start

section .text

_start:
    jmp short call_string

code:
    pop rsi             ; Pop address of string into RSI
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    mov rdx, 6          ; length
    syscall

    mov rax, 60         ; sys_exit
    xor rdi, rdi
    syscall

call_string:
    call code
    db "Hello", 10