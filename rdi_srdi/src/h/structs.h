// #define WIN32_LEAN_AND_MEAN
#pragma once
#include <windows.h>

//////////////////////////////////////////////////////////////////////////////
// 1. Relocation block structures
//////////////////////////////////////////////////////////////////////////////
typedef struct BASE_RELOCATION_BLOCK {
  DWORD PageAddress;
  DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
  WORD Offset : 12;
  WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

//////////////////////////////////////////////////////////////////////////////
// 2. PE structure overrides
//////////////////////////////////////////////////////////////////////////////
// struct 8 bytes 2 fields ntimage.h:1310
typedef struct __IMAGE_BASE_RELOCATION {
  /* 0x0000 */ ULONG VirtualAddress;                  /* size: 4, align: 4 */
  /* 0x0004 */ ULONG SizeOfBlock;                     /* size: 4, align: 4 */
} __IMAGE_BASE_RELOCATION, *__PIMAGE_BASE_RELOCATION; /* total size: 0x8 (8) */

// struct 8 bytes 2 fields ntimage.h:255
typedef struct __IMAGE_DATA_DIRECTORY {
  /* 0x0000 */ ULONG VirtualAddress;                /* size: 4, align: 4 */
  /* 0x0004 */ ULONG Size;                          /* size: 4, align: 4 */
} __IMAGE_DATA_DIRECTORY, *__PIMAGE_DATA_DIRECTORY; /* total size: 0x8 (8) */

//////////////////////////////////////////////////////////////////////////////
// 3. Native NT structure typedefs
//////////////////////////////////////////////////////////////////////////////
// obsidian://open?vault=vault-obsidian-backup&file=10-Malware%20%20Development%2F01-Windows%20Research%2F02%20-%20Windows%2F05%20-%20C%2B%2B%2Ftypedef%20struc%20union%2Fstruct%20typedef%20*PIO_STATUS%20in%20headers%20WindowsNT
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
// struct 8 bytes 2 fields wdm.h:7685
typedef struct _IO_STATUS_BLOCK {
  union {
    /* 0x0000 | 0x0000 */ NTSTATUS Status; /* size: 4, align: 4 */
    /* 0x0000 | 0x0000 */ PVOID Pointer;   /* size: 4, align: 4 */
  }; /* size: 4, align: 4 */
  /* 0x0004 */ ULONG_PTR Information; /* size: 4, align: 4 */
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK; /* total size: 0x8 (8) */

// struct 8 bytes 3 fields ntdef.h:1623
// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
typedef struct _UNICODE_STRING {
  /* 0x0000 */ USHORT Length;        /* size: 2, align: 2 */
  /* 0x0002 */ USHORT MaximumLength; /* size: 2, align: 2 */
  /* 0x0004 */ PWCH Buffer;          /* size: 4, align: 4 */
} UNICODE_STRING, *PUNICODE_STRING;  /* total size: 0x8 (8) */

typedef struct _OBJECT_ATTRIBUTES {
  /* 0x0000 */ ULONG Length;                   /* size: 4, align: 4 */
  /* 0x0004 */ HANDLE RootDirectory;           /* size: 4, align: 4 */
  /* 0x0008 */ PUNICODE_STRING ObjectName;     /* size: 4, align: 4 */
  /* 0x000C */ ULONG Attributes;               /* size: 4, align: 4 */
  /* 0x0010 */ PVOID SecurityDescriptor;       /* size: 4, align: 4 */
  /* 0x0014 */ PVOID SecurityQualityOfService; /* size: 4, align: 4 */
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;      /* total size: 0x18 (24) */
// struct 48 bytes 6 fields ntdef.h:1854
// typedef struct _OBJECT_ATTRIBUTES64 {
//   /* 0x0000 */ ULONG Length;                     /* size: 4, align: 4 */
//   /* 0x0008 */ ULONG64 RootDirectory;            /* size: 8, align: 8 */
//   /* 0x0010 */ ULONG64 ObjectName;               /* size: 8, align: 8 */
//   /* 0x0018 */ ULONG Attributes;                 /* size: 4, align: 4 */
//   /* 0x0020 */ ULONG64 SecurityDescriptor;       /* size: 8, align: 8 */
//   /* 0x0028 */ ULONG64 SecurityQualityOfService; /* size: 8, align: 8 */
// } OBJECT_ATTRIBUTES64, *POBJECT_ATTRIBUTES64;    /* total size: 0x30 (48) */

// struct24 bytes 5 fields wdm.h:7964
typedef struct _FILE_STANDARD_INFORMATION {
  /* 0x0000 */ LARGE_INTEGER AllocationSize; /* size: 8, align: 8 */
  /* 0x0008 */ LARGE_INTEGER EndOfFile;      /* size: 8, align: 8 */
  /* 0x0010 */ ULONG NumberOfLinks;          /* size: 4, align: 4 */
  /* 0x0014 */ BOOLEAN DeletePending;        /* size: 1, align: 1 */
  /* 0x0015 */ BOOLEAN Directory;            /* size: 1, align: 1 */
} FILE_STANDARD_INFORMATION,
    *PFILE_STANDARD_INFORMATION; /* total size: 0x18 (24) */

// 84 variants wdm.h type: int
typedef enum _FILE_INFORMATION_CLASS {
  FileDirectoryInformation = 1,
  FileFullDirectoryInformation = 2,
  FileBothDirectoryInformation = 3,
  FileBasicInformation = 4,
  FileStandardInformation = 5,
  FileInternalInformation = 6,
  FileEaInformation = 7,
  FileAccessInformation = 8,
  FileNameInformation = 9,
  FileRenameInformation = 10,
  FileLinkInformation = 11,
  FileNamesInformation = 12,
  FileDispositionInformation = 13,
  FilePositionInformation = 14,
  FileFullEaInformation = 15,
  FileModeInformation = 16,
  FileAlignmentInformation = 17,
  FileAllInformation = 18,
  FileAllocationInformation = 19,
  FileEndOfFileInformation = 20,
  FileAlternateNameInformation = 21,
  FileStreamInformation = 22,
  FilePipeInformation = 23,
  FilePipeLocalInformation = 24,
  FilePipeRemoteInformation = 25,
  FileMailslotQueryInformation = 26,
  FileMailslotSetInformation = 27,
  FileCompressionInformation = 28,
  FileObjectIdInformation = 29,
  FileCompletionInformation = 30,
  FileMoveClusterInformation = 31,
  FileQuotaInformation = 32,
  FileReparsePointInformation = 33,
  FileNetworkOpenInformation = 34,
  FileAttributeTagInformation = 35,
  FileTrackingInformation = 36,
  FileIdBothDirectoryInformation = 37,
  FileIdFullDirectoryInformation = 38,
  FileValidDataLengthInformation = 39,
  FileShortNameInformation = 40,
  FileIoCompletionNotificationInformation = 41,
  FileIoStatusBlockRangeInformation = 42,
  FileIoPriorityHintInformation = 43,
  FileSfioReserveInformation = 44,
  FileSfioVolumeInformation = 45,
  FileHardLinkInformation = 46,
  FileProcessIdsUsingFileInformation = 47,
  FileNormalizedNameInformation = 48,
  FileNetworkPhysicalNameInformation = 49,
  FileIdGlobalTxDirectoryInformation = 50,
  FileIsRemoteDeviceInformation = 51,
  FileUnusedInformation = 52,
  FileNumaNodeInformation = 53,
  FileStandardLinkInformation = 54,
  FileRemoteProtocolInformation = 55,
  FileRenameInformationBypassAccessCheck = 56,
  FileLinkInformationBypassAccessCheck = 57,
  FileVolumeNameInformation = 58,
  FileIdInformation = 59,
  FileIdExtdDirectoryInformation = 60,
  FileReplaceCompletionInformation = 61,
  FileHardLinkFullIdInformation = 62,
  FileIdExtdBothDirectoryInformation = 63,
  FileDispositionInformationEx = 64,
  FileRenameInformationEx = 65,
  FileRenameInformationExBypassAccessCheck = 66,
  FileDesiredStorageClassInformation = 67,
  FileStatInformation = 68,
  FileMemoryPartitionInformation = 69,
  FileStatLxInformation = 70,
  FileCaseSensitiveInformation = 71,
  FileLinkInformationEx = 72,
  FileLinkInformationExBypassAccessCheck = 73,
  FileStorageReserveIdInformation = 74,
  FileCaseSensitiveInformationForceAccessCheck = 75,
  FileKnownFolderInformation = 76,
  FileStatBasicInformation = 77,
  FileId64ExtdDirectoryInformation = 78,
  FileId64ExtdBothDirectoryInformation = 79,
  FileIdAllExtdDirectoryInformation = 80,
  FileIdAllExtdBothDirectoryInformation = 81,
  FileStreamReservationInformation = 82,
  FileMupProviderInfo = 83,
  FileMaximumInformation = 84
} _FILE_INFORMATION_CLASS;

typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
  _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;
