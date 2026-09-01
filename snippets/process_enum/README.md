//////////////////////////////
// process enum 
/////////////////////////////
x86_64-w64-mingw32-g++ process_enum.cpp -o process_enum.exe -luser32 -lkernel32 -static -std=c++26
wine process_enum.exe