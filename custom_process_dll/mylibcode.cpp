#include <windows.h>

DWORD WINAPI main_thread(LPVOID lp_param)
{
    (void)lp_param;
    MessageBoxW(NULL, L"Jesus Loves You!", L"=^..^=", MB_OK);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h_module, DWORD dw_reason, LPVOID lp_reserved)
{
    (void)h_module;
    (void)lp_reserved;

    //////////////////////////////////////////////////////////////////////////
    // 1. Execute work outside the loader lock
    //////////////////////////////////////////////////////////////////////////
    if (dw_reason == DLL_PROCESS_ATTACH)
    {
        CreateThread(NULL, 0, main_thread, NULL, 0, NULL);
    }

    return TRUE;
}
