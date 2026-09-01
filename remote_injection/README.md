/////////////////////
// remote injection
/////////////////////
x86_64-w64-mingw32-g++ remote_injection.cpp -o remote_injection.exe -luser32 -lkernel32 -static -std=c++26
nc -lvp 8443
wine remote_injection.exe 160
