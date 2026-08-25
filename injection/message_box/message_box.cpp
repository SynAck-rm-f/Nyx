#include <windows.h>


int main() {
    // 1. Pop la box
   MessageBoxW(
    NULL, 
    L"Message Box Test WinApi with Wine !",  // Le L force le format UTF-16 (wchar_t)
    L"Pwned", 
    MB_OK | MB_ICONINFORMATION
);
    
    return 0;
}