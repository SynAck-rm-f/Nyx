#include "src/h/structs.h"
#include "src/h/utils.h"
#include <cstdint>
#include <minwindef.h>
#include <windows.h>

typedef BOOL(WINAPI *DLLEntry)(HINSTANCE, DWORD, LPVOID);

int main(int argc, char *argv[]) {

  ////////////////////////////////////////////////////////////////////////////
  // 1. Disk staging & buffer ingestion
  ////////////////////////////////////////////////////////////////////////////

  // Creates or opens a file or I/O device.
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FCreateFileA
  HANDLE h_file = CreateFileA("main.dll", GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);

  LoggInfo("Creates file h_andler");
  LoggAddress("h_file", (void *)h_file);
  LoggHex32("h_file", (DWORD)(uintptr_t)h_file);

  if (h_file == INVALID_HANDLE_VALUE) {
    LoggAddress("INVALID_HANDLE_VALUE", (void *)INVALID_HANDLE_VALUE);
    return 1;
  }
  ////////////////////////////////////////////////////////////////////////////
  // 2. Read file size
  ////////////////////////////////////////////////////////////////////////////
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FGetFileSizeEx
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FCloseHandle
  LARGE_INTEGER file_size;
  if (!GetFileSizeEx(h_file, &file_size)) {
    CloseHandle(h_file);
    LoggError("GetFileSizeEx failed");
    return 1;
  }
  DWORD cb_file_size = static_cast<DWORD>(file_size.QuadPart);
  LoggInfo("Retrieves the size of the specified file.");
  LoggHex64("file_size.QuadPart", file_size.QuadPart);
  LoggHex32("cb_file_size", cb_file_size);

  ////////////////////////////////////////////////////////////////////////////
  // 3. Allocate raw staging buffer
  ////////////////////////////////////////////////////////////////////////////
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FHeapAlloc
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FGetProcessHeap
  PBYTE p_raw_buffer = static_cast<PBYTE>(
      HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb_file_size));

  LoggInfo("Allocates a block of memory from a heap");
  LoggAddress("p_raw_buffer", p_raw_buffer);
  LoggHex32("cb_file_size", cb_file_size);
  if (!p_raw_buffer) {
    CloseHandle(h_file);
    return 1;
  }
  ////////////////////////////////////////////////////////////////////////////
  // 4. Read file contents into memory
  ////////////////////////////////////////////////////////////////////////////
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FReadFile
  // obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01%20-%20Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2F02%20-%20Windows%2FWin32%2FAPI%2FHeapFree
  DWORD cb_bytes_read = 0;

  LoggInfo("Reads data ");
  LoggHex32("cb_bytes_read", cb_bytes_read);

  if (!ReadFile(h_file, p_raw_buffer, cb_file_size, &cb_bytes_read, NULL)) {
    HeapFree(GetProcessHeap(), 0, p_raw_buffer);
    CloseHandle(h_file);
    return 1;
  }
  CloseHandle(h_file);
  h_file = INVALID_HANDLE_VALUE;

  ////////////////////////////////////////////////////////////////////////////
  // 5. Parse PE headers and validate structure
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)p_raw_buffer;
  LoggInfo("PE Header Parsing and Structural Validation");
  LoggAddress("p_dos_header", p_dos_header);
  LoggHex16("e_magic", p_dos_header->e_magic);
  LoggHex32("e_lfanew", p_dos_header->e_lfanew);

  if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    LoggError("Invalid DOS signature Error");
    HeapFree(GetProcessHeap(), 0, p_raw_buffer);
    return 1;
  }

  if (p_dos_header->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
      p_dos_header->e_lfanew >
          static_cast<LONG>(cb_file_size - sizeof(IMAGE_NT_HEADERS))) {
    LoggError("Invalid e_lfanew");
    HeapFree(GetProcessHeap(), 0, p_raw_buffer);
    return 1;
  }

  ////////////////////////////////////////////////////////////////////////////
  // 6. Resolve NT headers and image size
  ////////////////////////////////////////////////////////////////////////////

  PIMAGE_NT_HEADERS p_nt_headers =
      (PIMAGE_NT_HEADERS)(p_raw_buffer + p_dos_header->e_lfanew);
  LoggInfo("Parsing NT NT_HEADERS");
  LoggAddress("p_nt_headers", p_nt_headers);
  LoggHex32("PE Signature", p_nt_headers->Signature);
  LoggHex32("ImageBase", (DWORD)p_nt_headers->OptionalHeader.ImageBase);
  LoggHex32("SizeOfImage", p_nt_headers->OptionalHeader.SizeOfImage);
  LoggHex32("AddressOfEntryPoint",
            p_nt_headers->OptionalHeader.AddressOfEntryPoint);
  if (p_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    HeapFree(GetProcessHeap(), 0, p_raw_buffer);
    return 1;
  }
  ////////////////////////////////////////////////////////////////////////////
  // 7. Allocate image memory and map sections
  ////////////////////////////////////////////////////////////////////////////
  DWORD cb_image_size = p_nt_headers->OptionalHeader.SizeOfImage;
  ///////////////////////////////////////////////
  // 55 nt_headers->OptionalHeader.SizeOfImage
  PBYTE p_image_base = (PBYTE)VirtualAlloc(
      (LPVOID)p_nt_headers->OptionalHeader.ImageBase, cb_image_size,
      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  LoggInfo(" Virtual Allocation & Section Mapping");
  LoggAddress("allocated", p_image_base);
  if (!p_image_base) {
    p_image_base = (PBYTE)VirtualAlloc(
        NULL, cb_image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  }

  if (!p_image_base) {
    LoggError("VirtualAlloc failed");
    HeapFree(GetProcessHeap(), 0, p_raw_buffer);
    return 1;
  }
  ////////////////////////////////////////////////////////////////////////////
  // 8. Apply base reloc_dir
  ////////////////////////////////////////////////////////////////////////////
  ULONG_PTR delta_base =
      (ULONG_PTR)p_image_base - p_nt_headers->OptionalHeader.ImageBase;
  LoggInfo(" 7 Delat Reloc");
  LoggDelta("LoggDelta", delta_base);

  ////////////////////////////////////////////////////////////////////////////
  // 9. Copy PE headers
  ////////////////////////////////////////////////////////////////////////////
  memcpy(p_image_base, p_raw_buffer, p_nt_headers->OptionalHeader.SizeOfHeaders);
  LoggInfo("8 Cpoy headers");
  ////////////////////////////////////////////////////////////////////////////
  // 10. Map section data
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_SECTION_HEADER p_section = IMAGE_FIRST_SECTION(p_nt_headers);
  LoggInfo("9 Mappage des sections");
  for (WORD index = 0; index < p_nt_headers->FileHeader.NumberOfSections; index++) {
    PVOID pSectionDest = p_image_base + p_section->VirtualAddress;
    PVOID pSectionSrc = p_raw_buffer + p_section->PointerToRawData;

    if (p_section->SizeOfRawData > 0) {
      memcpy(pSectionDest, pSectionSrc, p_section->SizeOfRawData);
    }
    p_section++;
    LoggAddress("p_section", p_section);
    // LoggHex16("p_section", (WORD)(uintptr_t)p_section);
    // LoggHex32("p_section", (DWORD)(uintptr_t)p_section);
  }

  ////////////////////////////////////////////////////////////////////////////
  // 11. Process reloc_dir
  ////////////////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////
  // Delta calculation for ASLR/Rebase fixups
  IMAGE_DATA_DIRECTORY reloc_dir =
      p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  LoggInfo("Relocations");
  if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size > 0) {
    DWORD_PTR relocation_table =
        (DWORD_PTR)p_image_base + reloc_dir.VirtualAddress;
    DWORD cb_relocations_processed = 0;
    ////////////////////////////////////////////
    // Traverse the raw relocation table byte by byte
    while (cb_relocations_processed < reloc_dir.Size) {
      PBASE_RELOCATION_BLOCK p_relocation_block =
          (PBASE_RELOCATION_BLOCK)(relocation_table + cb_relocations_processed);
      cb_relocations_processed += sizeof(BASE_RELOCATION_BLOCK);

      if (p_relocation_block->BlockSize == 0)
        break;
      ////////////////////////////////////////////
      // Dynamically calculate the number of entries in the current block
      DWORD cb_relocations_count =
          (p_relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) /
          sizeof(BASE_RELOCATION_ENTRY);

      PBASE_RELOCATION_ENTRY p_relocation_entries =
          (PBASE_RELOCATION_ENTRY)(relocation_table + cb_relocations_processed);

      for (DWORD index = 0; index < cb_relocations_count; index++) {
        cb_relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
        // IMAGE_REL_BASED_ABSOLUTE (Type 0) is used for padding alignment
        if (p_relocation_entries[index].Type == 0) {
          continue;
        }

        DWORD_PTR rva_relocation =
            p_relocation_block->PageAddress + p_relocation_entries[index].Offset;
        /////////////////////////////////////////
        // Security/Boundary check to prevent OOB writes on malformed PEs

        if (rva_relocation > cb_image_size - sizeof(DWORD_PTR)) {
          continue;
        }
        ////////////////////////////////////////
        // Resolve the absolute memory address and apply the ASLR Delta
        DWORD_PTR *p_patch_address =
            (DWORD_PTR *)((DWORD_PTR)p_image_base + rva_relocation);
        *p_patch_address += delta_base;
      }
    }
    LoggAddress("relocation_table", (PVOID)relocation_table);
    LoggHex32("reloc_dir.Size", reloc_dir.Size);
  }

  ////////////////////////////////////////////////////////////////////////////
  // 12. Resolve imports
  ////////////////////////////////////////////////////////////////////////////
  IMAGE_DATA_DIRECTORY import_directory =
      p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  LoggInfo("11 Inports");
  if (import_directory.VirtualAddress != 0) {
    PIMAGE_IMPORT_DESCRIPTOR p_import_descriptor =
        (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)p_image_base +
                                   import_directory.VirtualAddress);

    // Extract DLL name from RVA
    while (p_import_descriptor->Name != 0) {
      PCHAR p_library_name =
          (PCHAR)((DWORD_PTR)p_image_base + p_import_descriptor->Name);
      LoggInfo("--- DLL ---");
      LoggInfo(p_library_name);
      LoggAddress("p_library_name", p_library_name);
      LoggHex32("p_import_descriptor->Name", (DWORD)p_import_descriptor->Name);
      // Load the dependency into memory
      HMODULE h_library = LoadLibraryA(p_library_name);
      if (h_library == NULL) {
        LoggError("Failed to load DLL");
        break;
      }
      ///////////////////////////////////////////
      // Setup IAT (FirstThunk) and INT (OriginalFirstThunk) pointers
      //////////////////////////////////////////
      PIMAGE_THUNK_DATA p_thunk =
          (PIMAGE_THUNK_DATA)((DWORD_PTR)p_image_base +
                              p_import_descriptor->FirstThunk);
      // LoggInfo("AT (Import Address Table)");

      //////////////////////////////////////////
      // INT (Import Name Table) - noms/ordinaux des fonctions
      PIMAGE_THUNK_DATA p_original_thunk =
          (PIMAGE_THUNK_DATA)((DWORD_PTR)p_image_base +
                              p_import_descriptor->OriginalFirstThunk);
      // LoggInfo("INT Import Name Table");

      LoggAddress("p_import_descriptor", p_import_descriptor);
      LoggInfo("-------------------");
      // Si OriginalFirstThunk est 0, on utilise FirstThunk (certains linkers)
      if (!p_original_thunk) {
        p_original_thunk = p_thunk;
      }

      while (p_thunk->u1.AddressOfData != 0) {
        DWORD_PTR fn_address = 0;

        if (IMAGE_SNAP_BY_ORDINAL(p_original_thunk->u1.Ordinal)) {
          // Resolve by Ordinal (Highest bit of u1.Ordinal is set to 1)
          LPCSTR p_function_ordinal =
              (LPCSTR)IMAGE_ORDINAL(p_original_thunk->u1.Ordinal);
          fn_address =
              (DWORD_PTR)GetProcAddress(h_library, p_function_ordinal);
        } else {
          // Resolve by Name
          PIMAGE_IMPORT_BY_NAME p_function_name =
              (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)p_image_base +
                                      p_original_thunk->u1.AddressOfData);

          fn_address =
              (DWORD_PTR)GetProcAddress(h_library, p_function_name->Name);
          LoggInfo("Resolving function:");
          LoggAddress(" p_function_name", p_function_name);
          LoggInfo((char *)p_function_name->Name);
          LoggInfo("-------------------");
        }
        // Overwrite the IAT entry with the resolved absolute address
        p_thunk->u1.Function = fn_address;

        p_thunk++;
        p_original_thunk++;
      }

      p_import_descriptor++;
    }
  }

  //////////////////////////////////////////////////////////////////////////////
  // Payload Execution & Memory Cleanup (Entry Point Resolution)
  /////////////////////////////////////////////////////////////////////////////

  // Define the function pointer signature for DllMain
  typedef BOOL(APIENTRY * pfnDllMain)(HINSTANCE hinstDLL, DWORD fdwReason,
                                      LPVOID lpvReserved);
  // Resolve the absolute address of the Entry Point
  pfnDllMain p_dll_main =
      (pfnDllMain)(p_image_base + p_nt_headers->OptionalHeader.AddressOfEntryPoint);

  // OpSec: Free the raw downloaded/read buffer to remove heap artifacts
  LoggAddress("p_dll_main", reinterpret_cast<void *>(p_dll_main));
  // Libération du buffer brut
  HeapFree(GetProcessHeap(), 0, p_raw_buffer);
  p_raw_buffer = NULL;

  // Execute the payload
  if (p_dll_main != NULL) {
   // Simulate Windows Loader behavior for DLLs
    BOOL b_success = p_dll_main((HINSTANCE)p_image_base, DLL_PROCESS_ATTACH, NULL);
    LoggInfo("Call DllMain");

    // Adhere to PE specification: if DllMain fails, cleanup memory
    if (!b_success) {
      LoggError("DllMain returned FALSE");
      VirtualFree(p_image_base, 0, MEM_RELEASE);
      return 1;
    }
    return 0;
  }
  return 1;
}