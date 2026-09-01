#include <windows.h>


int main() {
   MessageBoxW(
    NULL, 
    L"Message Box Test WinApi with Wine !",  // L f UTF-16 (wchar_t)
    L"Pwned", 
    MB_OK | MB_ICONINFORMATION
);
    
    return 0;
}