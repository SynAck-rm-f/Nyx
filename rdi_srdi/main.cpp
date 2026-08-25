#include <windows.h>

#define DLLEXPORT   __declspec( dllexport )

DLLEXPORT BOOL DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            MessageBox(NULL, "DLL PROCESS ATTACH", "55555", 0);

            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        default:
            break;
    }
    return TRUE;
}

//  HANDLE dll = CreateFileA("\\??\\C:\\Temp\\dll_poc.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
//  DWORD64 dll_size = GetFileSize(dll, NULL);
//  LPVOID dll_bytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dll_size);
//  DWORD out_size = 0;
//  ReadFile(dll, dll_bytes, dll_size, &out_size, NULL);

 