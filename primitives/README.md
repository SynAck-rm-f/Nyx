///////////////////////////////////////////////////////////
// quick test primitives
///////////////////////////////////////////////////////////

x86_64-w64-mingw32-g++ primitives.cpp -o test.exe -luser32 -lkernel32 -static -std=c++26
wine playground.exe 

[*] Test 1: VirtualAlloc
[+] VirtualAlloc OK: 00007ffffe8e0000
[*] Test 2: memcpy
[+] memcpy OK
[*] Test 3: VirtualProtect
[+] VirtualProtect OK
[*] Calling shellcode...
[+] Shellcode returned!
