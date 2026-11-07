#include <cstring>
#include <iostream>
#include <windows.h>

int main(int argc, char *argv[])
{
    HANDLE h_process = NULL;
    HANDLE h_load_thread = NULL;
    LPVOID p_dll_path = NULL;
    DWORD cb_pid = 0;
    LPCSTR p_dll_name = NULL;

    //////////////////////////////////////////////////////////////////////////
    // 1. Validate command line arguments
    //////////////////////////////////////////////////////////////////////////
    if (argc < 3)
    {
        std::cout << "[i] Usage: " << argv[0] << " <Target_PID> <DllPath>\n";
        return 1;
    }

    cb_pid = (DWORD)atoi(argv[1]);
    p_dll_name = argv[2];

    std::cout << "[i] Injecting DLL to PID: " << cb_pid << std::endl;
    std::cout << "[i] Starting injection: " << p_dll_name << std::endl;

    //////////////////////////////////////////////////////////////////////////
    // 2. Open the target process
    //////////////////////////////////////////////////////////////////////////
    h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, cb_pid);
    if (h_process == NULL)
    {
        std::cout << "[!] Impossible d'ouvrir le processus (PID invalide ou droits insuffisants).\n";
        return 1;
    }

    //////////////////////////////////////////////////////////////////////////
    // 3. Allocate and write the DLL path into the remote process
    //////////////////////////////////////////////////////////////////////////
    p_dll_path = VirtualAllocEx(h_process, NULL, strlen(p_dll_name) + 1,
                                MEM_COMMIT, PAGE_READWRITE);
    if (p_dll_path == NULL)
    {
        std::cout << "[!] VirtualAllocEx failed.\n";
        CloseHandle(h_process);
        return 1;
    }

    if (!WriteProcessMemory(h_process, p_dll_path, (LPVOID)p_dll_name,
                            strlen(p_dll_name) + 1, NULL))
    {
        std::cout << "[!] WriteProcessMemory failed.\n";
        VirtualFreeEx(h_process, p_dll_path, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return 1;
    }

    //////////////////////////////////////////////////////////////////////////
    // 4. Spawn a remote LoadLibraryA thread
    //////////////////////////////////////////////////////////////////////////
    h_load_thread = CreateRemoteThread(
        h_process, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"),
        p_dll_path, 0, 0);

    if (h_load_thread == NULL)
    {
        std::cout << "[!] CreateRemoteThread failed.\n";
        VirtualFreeEx(h_process, p_dll_path, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return 1;
    }

    //////////////////////////////////////////////////////////////////////////
    // 5. Cleanup
    //////////////////////////////////////////////////////////////////////////
    WaitForSingleObject(h_load_thread, INFINITE);
    CloseHandle(h_load_thread);
    VirtualFreeEx(h_process, p_dll_path, 0, MEM_RELEASE);
    CloseHandle(h_process);

    return 0;
}
