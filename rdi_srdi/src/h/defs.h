#include "structs.h"


#define EXIT(code) do { \
    void *_p_ntdll_exit = get_ntdll(); \
    typedef NTSTATUS (*NtTerminateProcess_t)(HANDLE, NTSTATUS); \
    NtTerminateProcess_t _NtTerminateProcess = (NtTerminateProcess_t) \
        get_proc_address_by_hash(_p_ntdll_exit, HASH("NtTerminateProcess")); \
    if (_NtTerminateProcess) _NtTerminateProcess((HANDLE)-1, (code)); \
    __builtin_unreachable(); \
} while(0)

#define NtCurrentThread() ((HANDLE)(LONG_PTR) - 2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR) - 1)
#define RTL_CONSTANT_STRING(s) {sizeof(s) - sizeof((s)[0]), sizeof(s), s}


#define OBJ_INHERIT 0x00000002L
#define OBJ_PERMANENT 0x00000010L
#define OBJ_EXCLUSIVE 0x00000020L
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_OPENIF 0x00000080L
#define OBJ_OPENLINK 0x00000100L
#define OBJ_KERNEL_HANDLE 0x00000200L
#define OBJ_FORCE_ACCESS_CHECK 0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 0x00000800
#define OBJ_DONT_REPARSE 0x00001000
#define OBJ_VALID_ATTRIBUTES 0x00001FF2

#define InitializeObjectAttributes(p, n, a, r, s)                              \
  {                                                                            \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);                                 \
    (p)->RootDirectory = r;                                                    \
    (p)->Attributes = a;                                                       \
    (p)->ObjectName = n;                                                       \
    (p)->SecurityDescriptor = s;                                               \
    (p)->SecurityQualityOfService = NULL;                                      \
  }

#define FILL_STRING(string, buffer)                                            \
  string.Length = (USHORT)strlen(buffer);                                      \
  string.MaximumLength = string.Length;                                        \
  string.Buffer = buffer


typedef BOOL(__stdcall *DLLEntry)(HINSTANCE dll, unsigned long reason,
                                  void *reserved);
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef NTSTATUS LdrLoadDll(_In_opt_ PCWSTR DllPath,
                            _In_opt_ PULONG DllCharacteristics,
                            _In_ PCUNICODE_STRING DllName,
                            _Out_ PVOID *DllHandle);

typedef VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString,
                                  PWSTR SourceString);

typedef NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes,
                              PIO_STATUS_BLOCK IoStatusBlock,
                              PLARGE_INTEGER AllocationSize,
                              ULONG FileAttributes, ULONG ShareAccess,
                              ULONG CreateDisposition, ULONG CreateOptions,
                              PVOID EaBuffer, ULONG EaLength);

typedef NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                         PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                         PSIZE_T RegionSize,
                                         ULONG AllocationType, ULONG Protect);

typedef NTSTATUS
NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                       PVOID FileInformation, ULONG Length,
                       _FILE_INFORMATION_CLASS FileInformationClass);

typedef void(__attribute__((stdcall)) *
             PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

typedef NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event,
                            PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                            PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                            ULONG Length, PLARGE_INTEGER ByteOffset,
                            PULONG Key);
typedef NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event,
                     PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                     PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
                     PLARGE_INTEGER ByteOffset, PULONG Key);
                     
typedef NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                     PVOID Buffer, SIZE_T BufferSize,
                                     PSIZE_T NumberOfBytesRead);

typedef NTSTATUS RtlMultiByteToUnicodeN(PWCH UnicodeString,
                                        ULONG MaxBytesInUnicodeString,
                                        PULONG BytesInUnicodeString,
                                        const CHAR *MultiByteString,
                                        ULONG BytesInMultiByteString);

typedef NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle,
                                        _Inout_ PVOID *BaseAddress,
                                        _Inout_ PSIZE_T RegionSize,
                                        _In_ ULONG NewProtection,
                                        _Out_ PULONG OldProtection);

typedef NTSTATUS NtFlushInstructionCache(_In_ HANDLE ProcessHandle,
                                         _In_opt_ PVOID BaseAddress,
                                         _In_ SIZE_T RegionSize);

typedef const ANSI_STRING *PCANSI_STRING;

typedef NTSTATUS LdrGetProcedureAddress(_In_ PVOID DllHandle,
                                        _In_opt_ PCANSI_STRING ProcedureName,
                                        _In_opt_ ULONG ProcedureNumber,
                                        _Out_ PVOID *ProcedureAddress);

typedef NTSTATUS NtFreeVirtualMemory(_In_ HANDLE ProcessHandle,
                                     _Inout_ __drv_freesMem(Mem)
                                         PVOID *BaseAddress,
                                     _Inout_ PSIZE_T RegionSize,
                                     _In_ ULONG FreeType);
typedef NTSTATUS NtClose(_In_ _Post_ptr_invalid_ HANDLE Handle);
