#include <windows.h>
#pragma comment(lib, "user32.lib")
#include <iostream> // Pour std::cin

int main() {
  // Charge la DLL (Assurez-vous que mylibcode.dll est dans le même dossier)
  // HMODULE hDll = LoadLibraryW(L"mylibcode.dll");

  // if (hDll == NULL) {
  //     // Optionnel : Permet de voir si Wine ne trouve pas la DLL
  //     DWORD error = GetLastError();
  //     MessageBoxW(NULL, L"Error de Load DLL", L"Error", MB_OK);
  //     return 1;
  // }

  MessageBoxW(NULL, L"I'm a mouse!", L"<:( )~~", MB_OK);

  std::cout << "DLL chargee." << std::endl;
  std::cin.get();

  return 0;
}