#include "src/h/structs.h"
#include "src/h/utils.h"
#include <cstdint>
#include <minwindef.h>
#include <windows.h>

typedef BOOL(WINAPI *DLLEntry)(HINSTANCE, DWORD, LPVOID);

int main(int argc, char *argv[]) {

  //////////////////////////////////////////////////////////////////////////////
  // Disk Staging & Buffer Ingestion
  /////////////////////////////////////////////////////////////////////////////

  // Creates or opens a file or I/O device.
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FCreateFileA
  HANDLE hFildLL = CreateFileA("main.dll", GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);

  LoggInfo("Creates file h_andler");
  LoggAddress("hFildLL", (void *)hFildLL);
  LoggHex32("hFildLL", (DWORD)(uintptr_t)hFildLL);

  if (hFildLL == INVALID_HANDLE_VALUE) {
    LoggAddress("INVALID_HANDLE_VALUE", (void *)INVALID_HANDLE_VALUE);
    return 1;
  }
  //////////////////////////////////
  // Retrieves the size of the specified file.
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FGetFileSizeEx
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FCloseHandle
  LARGE_INTEGER liFileSize;
  if (!GetFileSizeEx(hFildLL, &liFileSize)) {
    CloseHandle(hFildLL);
    LoggError("GetFileSizeEx failed");
    return 1;
  }
  DWORD dwFileSize = static_cast<DWORD>(liFileSize.QuadPart);
  LoggInfo("Retrieves the size of the specified file.");
  LoggHex64("liFileSize.QuadPart", liFileSize.QuadPart);
  LoggHex32("dwFileSize", dwFileSize);

  /////////////////////////////////
  // Allocates a block of memory from a heap. The allocated memory is not
  // movable. << HeapAlloc Retrieves a handle to the default heap of the calling
  // process << GetProcessHeap
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FHeapAlloc
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FGetProcessHeap
  PBYTE pRawBuffer = static_cast<PBYTE>(
      HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize));

  LoggInfo("Allocates a block of memory from a heap");
  LoggAddress("pRawBuffer", pRawBuffer);
  LoggHex32("dwFileSize", dwFileSize);
  if (!pRawBuffer) {
    CloseHandle(hFildLL);
    return 1;
  }
  /////////////////////////////////
  // Reads data from the specified file or input/output (I/O) device. <<
  // ReadFile Frees a memory block allocated from a heap << HeapFree
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FReadFile
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FHeapFree
  DWORD dwBytesRead = 0;

  LoggInfo("Reads data ");
  LoggHex32("dwBytesRead", dwBytesRead);

  if (!ReadFile(hFildLL, pRawBuffer, dwFileSize, &dwBytesRead, NULL)) {
    HeapFree(GetProcessHeap(), 0, pRawBuffer);
    CloseHandle(hFildLL);
    return 1;
  }
  CloseHandle(hFildLL);
  hFildLL = INVALID_HANDLE_VALUE;

  //////////////////////////////////////////////////////////////////////////////
  //  PE Header Parsing and Structural Validation
  /////////////////////////////////////////////////////////////////////////////
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pRawBuffer;
  LoggInfo("PE Header Parsing and Structural Validation");
  LoggAddress("pDosHeader", pDosHeader);
  LoggHex16("e_magic", pDosHeader->e_magic);
  LoggHex32("e_lfanew", pDosHeader->e_lfanew);

  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    LoggError("Invalid DOS signature Error");
    HeapFree(GetProcessHeap(), 0, pRawBuffer);
    return 1;
  }

  if (pDosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
      pDosHeader->e_lfanew >
          static_cast<LONG>(dwFileSize - sizeof(IMAGE_NT_HEADERS))) {
    LoggError("Invalid e_lfanew");
    HeapFree(GetProcessHeap(), 0, pRawBuffer);
    return 1;
  }

  //////////////////////////////////////////////////////////////////////////////
  // Parsing NT
  // structures to find the size of the DLL file, which is stored in the
  // nt_headers->OptionalHeader.SizeOfImage member variable. > //55
  /////////////////////////////////////////////////////////////////////////////

  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)(pRawBuffer + pDosHeader->e_lfanew);
  LoggInfo("Parsing NT NT_HEADERS");
  LoggAddress("pNtHeaders", pNtHeaders);
  LoggHex32("PE Signature", pNtHeaders->Signature);
  LoggHex32("ImageBase", (DWORD)pNtHeaders->OptionalHeader.ImageBase);
  LoggHex32("SizeOfImage", pNtHeaders->OptionalHeader.SizeOfImage);
  LoggHex32("AddressOfEntryPoint",
            pNtHeaders->OptionalHeader.AddressOfEntryPoint);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
    HeapFree(GetProcessHeap(), 0, pRawBuffer);
    return 1;
  }
  ////////////////////////////////////////////////
  //  Virtual Allocation & Section Mapping
  //
  DWORD dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
  ///////////////////////////////////////////////
  // 55 nt_headers->OptionalHeader.SizeOfImage
  PBYTE pImageBase = (PBYTE)VirtualAlloc(
      (LPVOID)pNtHeaders->OptionalHeader.ImageBase, dwImageSize,
      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  LoggInfo(" Virtual Allocation & Section Mapping");
  LoggAddress("allocated", pImageBase);
  if (!pImageBase) {
    pImageBase = (PBYTE)VirtualAlloc(
        NULL, dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  }

  if (!pImageBase) {
    LoggError("VirtualAlloc failed");
    HeapFree(GetProcessHeap(), 0, pRawBuffer);
    return 1;
  }
  ////////////////////////////////////
  // delta reloc
  ULONG_PTR uDeltaBase =
      (ULONG_PTR)pImageBase - pNtHeaders->OptionalHeader.ImageBase;
  LoggInfo(" 7 Delat Reloc");
  LoggDelta("LoggDelta", uDeltaBase);

  ////////////////////////////////////
  // memcpy headers
  memcpy(pImageBase, pRawBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);
  LoggInfo("8 Cpoy headers");
  ////////////////////////////////////
  // Mapp sect
  PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
  LoggInfo("9 Mappage des sections");
  for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
    PVOID pSectionDest = pImageBase + pSection->VirtualAddress;
    PVOID pSectionSrc = pRawBuffer + pSection->PointerToRawData;

    if (pSection->SizeOfRawData > 0) {
      memcpy(pSectionDest, pSectionSrc, pSection->SizeOfRawData);
    }
    pSection++;
    LoggAddress("pSection", pSection);
    // LoggHex16("pSection", (WORD)(uintptr_t)pSection);
    // LoggHex32("pSection", (DWORD)(uintptr_t)pSection);
  }

  //////////////////////////////////////////////////////////////////////////////
  // Relocations
  /////////////////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////
  // Delta calculation for ASLR/Rebase fixups
  IMAGE_DATA_DIRECTORY relocations =
      pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  LoggInfo("Relocations");
  if (relocations.VirtualAddress != 0 && relocations.Size > 0) {
    DWORD_PTR relocationTable =
        (DWORD_PTR)pImageBase + relocations.VirtualAddress;
    DWORD relocationsProcessed = 0;
    ////////////////////////////////////////////
    // Traverse the raw relocation table byte by byte
    while (relocationsProcessed < relocations.Size) {
      PBASE_RELOCATION_BLOCK relocationBlock =
          (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
      relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);

      if (relocationBlock->BlockSize == 0)
        break;
      ////////////////////////////////////////////
      // Dynamically calculate the number of entries in the current block
      DWORD relocationsCount =
          (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) /
          sizeof(BASE_RELOCATION_ENTRY);

      PBASE_RELOCATION_ENTRY relocationEntries =
          (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

      for (DWORD i = 0; i < relocationsCount; i++) {
        relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);
        // IMAGE_REL_BASED_ABSOLUTE (Type 0) is used for padding alignment
        if (relocationEntries[i].Type == 0) {
          continue;
        }

        DWORD_PTR relocationRVA =
            relocationBlock->PageAddress + relocationEntries[i].Offset;
        /////////////////////////////////////////
        // Security/Boundary check to prevent OOB writes on malformed PEs

        if (relocationRVA > dwImageSize - sizeof(DWORD_PTR)) {
          continue;
        }
        ////////////////////////////////////////
        // Resolve the absolute memory address and apply the ASLR Delta
        DWORD_PTR *pPatchAddress =
            (DWORD_PTR *)((DWORD_PTR)pImageBase + relocationRVA);
        *pPatchAddress += uDeltaBase;
      }
    }
    LoggAddress("relocationTable", (PVOID)relocationTable);
    LoggHex32("relocations.Size", relocations.Size);
  }

  //////////////////////////////////////////////////////////////////////////////
  // Imports
  /////////////////////////////////////////////////////////////////////////////
  IMAGE_DATA_DIRECTORY importsDirectory =
      pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  LoggInfo("11 Inports");
  if (importsDirectory.VirtualAddress != 0) {
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pImageBase +
                                   importsDirectory.VirtualAddress);

    // Extract DLL name from RVA
    while (pImportDescriptor->Name != 0) {
      PCHAR pLibraryName =
          (PCHAR)((DWORD_PTR)pImageBase + pImportDescriptor->Name);
      LoggInfo("--- DLL ---");
      LoggInfo(pLibraryName);
      LoggAddress("pLibraryName", pLibraryName);
      LoggHex32("pImportDescriptor->Name", (DWORD)pImportDescriptor->Name);
      // Load the dependency into memory
      HMODULE hLibrary = LoadLibraryA(pLibraryName);
      if (hLibrary == NULL) {
        LoggError("Failed to load DLL");
        break;
      }
      ///////////////////////////////////////////
      // Setup IAT (FirstThunk) and INT (OriginalFirstThunk) pointers
      //////////////////////////////////////////
      PIMAGE_THUNK_DATA thunk =
          (PIMAGE_THUNK_DATA)((DWORD_PTR)pImageBase +
                              pImportDescriptor->FirstThunk);
      // LoggInfo("AT (Import Address Table)");

      //////////////////////////////////////////
      // INT (Import Name Table) - noms/ordinaux des fonctions
      PIMAGE_THUNK_DATA originalThunk =
          (PIMAGE_THUNK_DATA)((DWORD_PTR)pImageBase +
                              pImportDescriptor->OriginalFirstThunk);
      // LoggInfo("INT Import Name Table");

      LoggAddress("pImportDescriptor", pImportDescriptor);
      LoggInfo("-------------------");
      // Si OriginalFirstThunk est 0, on utilise FirstThunk (certains linkers)
      if (!originalThunk) {
        originalThunk = thunk;
      }

      while (thunk->u1.AddressOfData != 0) {
        DWORD_PTR functionAddress = 0;

        if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
          // Resolve by Ordinal (Highest bit of u1.Ordinal is set to 1)
          LPCSTR functionOrdinal =
              (LPCSTR)IMAGE_ORDINAL(originalThunk->u1.Ordinal);
          functionAddress =
              (DWORD_PTR)GetProcAddress(hLibrary, functionOrdinal);
        } else {
          // Resolve by Name
          PIMAGE_IMPORT_BY_NAME functionName =
              (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pImageBase +
                                      originalThunk->u1.AddressOfData);

          functionAddress =
              (DWORD_PTR)GetProcAddress(hLibrary, functionName->Name);
          LoggInfo("Resolving function:");
          LoggAddress(" functionName", functionName);
          LoggInfo((char *)functionName->Name);
          LoggInfo("-------------------");
        }
        // Overwrite the IAT entry with the resolved absolute address
        thunk->u1.Function = functionAddress;

        thunk++;
        originalThunk++;
      }

      pImportDescriptor++;
    }
  }

  //////////////////////////////////////////////////////////////////////////////
  // Payload Execution & Memory Cleanup (Entry Point Resolution)
  /////////////////////////////////////////////////////////////////////////////

  // Define the function pointer signature for DllMain
  typedef BOOL(APIENTRY * pfnDllMain)(HINSTANCE hinstDLL, DWORD fdwReason,
                                      LPVOID lpvReserved);
  // Resolve the absolute address of the Entry Point
  pfnDllMain pDllMain =
      (pfnDllMain)(pImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

  // OpSec: Free the raw downloaded/read buffer to remove heap artifacts
  LoggAddress("pDllMain", reinterpret_cast<void *>(pDllMain));
  // Libération du buffer brut
  HeapFree(GetProcessHeap(), 0, pRawBuffer);
  pRawBuffer = NULL;

  // Execute the payload
  if (pDllMain != NULL) {
   // Simulate Windows Loader behavior for DLLs
    BOOL bSuccess = pDllMain((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL);
    LoggInfo("Call DllMain");

    // Adhere to PE specification: if DllMain fails, cleanup memory
    if (!bSuccess) {
      LoggError("DllMain returned FALSE");
      VirtualFree(pImageBase, 0, MEM_RELEASE);
      return 1;
    }
    return 0;
  }
  return 1;
}