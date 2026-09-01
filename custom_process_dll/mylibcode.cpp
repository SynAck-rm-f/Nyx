#include <windows.h>

// Fonction exécutée en dehors du Loader Lock
DWORD WINAPI MainThread(LPVOID lpParam) {
  MessageBoxW(NULL, L"Jesus Loves You!", L"=^..^=", MB_OK);
  return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    // thread indépen and quit immédiatement DllMain
    CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    break;
  case DLL_PROCESS_DETACH:
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
    break;
  }
  return TRUE;
}