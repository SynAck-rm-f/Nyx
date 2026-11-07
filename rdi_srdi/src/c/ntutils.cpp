// ntutils.cpp
#include "../h/ntutils.h"
#include "../h/defs.h"
#include "../h/peb.h"

static void ConsoleWrite(const char *buf, int len) {
  WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL, NULL);
}

void LoggInfo(const char *msg) {
  char buf[512];
  int len = wsprintfA(buf, "[INFO  ]  %s\n", msg);
  OutputDebugStringA(buf);
  ConsoleWrite(buf, len);
}


//////////////////////////////////////////////////////////////////////////////
// 1. Custom formatting helpers
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
// 2. Convert a DWORD to hexadecimal text
//////////////////////////////////////////////////////////////////////////////
static int DwordToHex(char *buf, DWORD value) {
    const char *hex = "0123456789ABCDEF";
    for (int i = 7; i >= 0; i--) {
        buf[i] = hex[value & 0xF];
        value >>= 4;
    }
    return 8;
}

//////////////////////////////////////////////////////////////////////////////
// 3. Convert a QWORD to hexadecimal text
//////////////////////////////////////////////////////////////////////////////
static int QwordToHex(char *buf, unsigned long long value) {
    const char *hex = "0123456789ABCDEF";
    for (int i = 15; i >= 0; i--) {
        buf[i] = hex[value & 0xF];
        value >>= 4;
    }
    return 16;
}

//////////////////////////////////////////////////////////////////////////////
// 4. Convert a DWORD to decimal text
//////////////////////////////////////////////////////////////////////////////
static int DwordToDec(char *buf, DWORD value) {
    if (value == 0) {
        buf[0] = '0';
        return 1;
    }
    char temp[16];
    int i = 0;
    while (value > 0) {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    }
    for (int j = 0; j < i; j++) {
        buf[j] = temp[i - 1 - j];
    }
    return i;
}

//////////////////////////////////////////////////////////////////////////////
// 5. Native write path via NTAPI
//////////////////////////////////////////////////////////////////////////////

void ConsoleWriteNative(const char *buf, int len) {
    IO_STATUS_BLOCK ioStatus;
    
    void *p_ntdll = get_ntdll();
    NtWriteFile *g_nt_write_file = (NtWriteFile *)get_proc_address_by_hash(
        p_ntdll, NtWriteFile_CRC32b);
    
    if (!g_nt_write_file) return;  // Sécurité si le hash est pas trouvé
    
    // STD_OUTPUT_HANDLE = -11
    HANDLE hStdout = (HANDLE)(-11);
    
    g_nt_write_file(hStdout, NULL, NULL, NULL, &ioStatus,
                    (PVOID)buf, (ULONG)len, NULL, NULL);
}

//////////////////////////////////////////////////////////////////////////////
// 6. Logging helpers
//////////////////////////////////////////////////////////////////////////////

void LoggInfoNative(const char *msg) {
    char buf[512];
    int len = 0;
    
    const char *prefix = "[INFO  ] ";
    while (*prefix) buf[len++] = *prefix++;
    while (*msg) buf[len++] = *msg++;
    buf[len++] = '\n';
    
    ConsoleWriteNative(buf, len);
}

void LoggErrorNative(const char *msg) {
    char buf[512];
    int len = 0;
    
    const char *prefix = "[ERROR ] ";
    while (*prefix) buf[len++] = *prefix++;
    while (*msg) buf[len++] = *msg++;
    buf[len++] = '\n';
    
    ConsoleWriteNative(buf, len);
}

void LoggAddressNative(const char *label, void *address) {
    char buf[256];
    int len = 0;
    
    const char *p = "[ADDR] ";
    while (*p) buf[len++] = *p++;
    
    p = label;
    while (*p) buf[len++] = *p++;
    
    buf[len++] = ' '; buf[len++] = '='; buf[len++] = ' '; buf[len++] = '0'; buf[len++] = 'x';
    len += QwordToHex(buf + len, (unsigned long long)address);
    buf[len++] = '\n';
    
    ConsoleWriteNative(buf, len);
}

void LoggHex32Native(const char *label, DWORD value) {
    char buf[256];
    int len = 0;
    
    const char *p = "[HEX32] ";
    while (*p) buf[len++] = *p++;
    
    p = label;
    while (*p) buf[len++] = *p++;
    
    buf[len++] = ' '; buf[len++] = '='; buf[len++] = ' '; buf[len++] = '0'; buf[len++] = 'x';
    len += DwordToHex(buf + len, value);
    
    buf[len++] = ' '; buf[len++] = '(';
    len += DwordToDec(buf + len, value);
    buf[len++] = ')'; buf[len++] = '\n';
    
    ConsoleWriteNative(buf, len);
}

void LoggHex16Native(const char *label, WORD value) {
    char buf[256];
    int len = 0;
    
    const char *p = "[HEX16] ";
    while (*p) buf[len++] = *p++;
    
    p = label;
    while (*p) buf[len++] = *p++;
    
    buf[len++] = ' '; buf[len++] = '='; buf[len++] = ' '; buf[len++] = '0'; buf[len++] = 'x';
    len += DwordToHex(buf + len, (DWORD)value);  // Pad à 8 digits
    
    buf[len++] = ' '; buf[len++] = '(';
    len += DwordToDec(buf + len, (DWORD)value);
    buf[len++] = ')'; buf[len++] = '\n';
    
    ConsoleWriteNative(buf, len);
}

void LoggDeltaNative(const char *label, LONG_PTR delta) {
    char buf[256];
    int len = 0;
    
    const char *p = "[DELTA] ";
    while (*p) buf[len++] = *p++;
    
    p = label;
    while (*p) buf[len++] = *p++;
    
    buf[len++] = ' '; buf[len++] = '='; buf[len++] = ' '; buf[len++] = '0'; buf[len++] = 'x';
    len += QwordToHex(buf + len, (unsigned long long)delta);
    buf[len++] = '\n';
    
    ConsoleWriteNative(buf, len);
}