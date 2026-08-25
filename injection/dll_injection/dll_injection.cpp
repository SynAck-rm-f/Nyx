
#include <iostream>
#include <windows.h>

int main(int argc, char *argv[]) {

  //  HANDLE pHandle; // process handle
  //  LPVOID pDllPath;
  //  HANDLE hLoadThread;  // RAII (Resource Acquisition Is Initialization) >>
  //  LPCSTR DllPath; DWORD procID; LPCSTR DllPath; bonne partiques RAII

  // arg cmd
  DWORD procID = atoi(argv[1]);
  std::cout << "[i] Injecting DLL to PID: " << procID << std::endl;

  LPCSTR DllPath = argv[2]; // The Path to our DLL
  std::cout << "[i] Starting injection: " << DllPath << std::endl;

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
                                procID); // Opening the Process with All Access
  if (hProcess == NULL) {
    std::cout << "[!] Impossible d'ouvrir le processus (PID invalide ou droits "
                 "insuffisants).\n";
    return 1;
  }

  // Allocate memory for the dllpath in the target process, length of the path
  // string + null terminator
  LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1, MEM_COMMIT,
                                   PAGE_READWRITE);

  // Write the path to the address of the memory we just allocated in the target
  // process
  WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1,
                     0);

  // Create a Remote Thread in the target process which calls LoadLibraryA as
  // our dllpath as an argument -> program loads our dll
  HANDLE hLoadThread =
      CreateRemoteThread(hProcess, 0, 0,
                         (LPTHREAD_START_ROUTINE)GetProcAddress(
                             GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"),
                         pDllPath, 0, 0);
  WaitForSingleObject(
      hLoadThread,
      INFINITE); // Wait for the execution of our loader thread to finish
  CloseHandle(hProcess);

  return 0;
}