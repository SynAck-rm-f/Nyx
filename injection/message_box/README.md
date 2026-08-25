///////////////////////////////
// message box simple api test
//////////////////////////////
x86_64-w64-mingw32-g++ message_box.cpp -o messagebox.exe -luser32 -lkernel32 -static -std=c++26
wine messagebox.exe