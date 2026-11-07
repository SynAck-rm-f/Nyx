#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

#include "process_enum.h"

int ListProcesses(const wchar_t *p_process_name)
{
    HANDLE h_process_snapshot;
    PROCESSENTRY32W process_entry;
    DWORD cb_pid = 0;

    //////////////////////////////////////////////////////////////////////////
    // 1. Create a snapshot of running processes
    //////////////////////////////////////////////////////////////////////////
    h_process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_process_snapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[E] CreateToolhelp32Snapshot failed." << std::endl;
        return 0;
    }

    //////////////////////////////////////////////////////////////////////////
    // 2. Walk the process list and look for the requested image name
    //////////////////////////////////////////////////////////////////////////
    process_entry.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(h_process_snapshot, &process_entry))
    {
        std::cerr << "[E] Process32FirstW failed." << std::endl;
        CloseHandle(h_process_snapshot);
        return 0;
    }

    do
    {
        if (lstrcmpiW(process_entry.szExeFile, p_process_name) == 0)
        {
            cb_pid = process_entry.th32ProcessID;
            break;
        }
    } while (Process32NextW(h_process_snapshot, &process_entry));

    //////////////////////////////////////////////////////////////////////////
    // 3. Cleanup and return result
    //////////////////////////////////////////////////////////////////////////
    CloseHandle(h_process_snapshot);
    return cb_pid;
}
