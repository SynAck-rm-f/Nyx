#include <windows.h>  
#include <tlhelp32.h>  
#include <iostream>

void ListProcesses() {  
  HANDLE hProcessSnap;  
  PROCESSENTRY32 pe32;

  // TH32CS_SNAPPROCESS Includes all processes in the system in the snapshot. 
  // To enumerate the processes, see Process32First.
  // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
  hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  // 
  if (hProcessSnap == INVALID_HANDLE_VALUE) {  
    std::cerr << "[E] CreateToolhelp32Snapshot failed." << std::endl;  
    return;  
  }  
  pe32.dwSize = sizeof(PROCESSENTRY32);  
  if (!Process32First(hProcessSnap, &pe32)) {  
    CloseHandle(hProcessSnap);  
    std::cerr << "[E] Process32First failed." << std::endl;  
    return;  
  }  
  do {  
    std::wcout << L"[i] Process name: " << pe32.szExeFile << L"\n[*] Process ID: " << pe32.th32ProcessID << std::endl;  
  } while (Process32Next(hProcessSnap, &pe32));  
  CloseHandle(hProcessSnap);  
}  
int main() {  
  ListProcesses();  
  return 0;
}