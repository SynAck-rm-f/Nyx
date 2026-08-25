///////////////////////////////////////////////////////////
// Create our own process, and inject our malicious DLL
///////////////////////////////////////////////////////////
x86_64-w64-mingw32-g++ -o mouse.exe mouse.cpp -mconsole -fpermissive -static -luser32 -lkernel32 -std=c++26
wine mouse.exe

x86_64-w64-mingw32-g++ -shared -o mylibcode.dll mylibcode.cpp -static -luser32 -lkernel32 -fpermissive -std=c++26
wine dll_injection.exe 32 mylibcode.dll