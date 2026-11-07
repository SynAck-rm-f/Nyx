// utils.cpp
#include "../h/utils.h"

static void ConsoleWrite(const char *buf, int len) {
  WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL, NULL);
}

void LoggAddress(const char *label, void *address) {
  char buf[256];
  int len = wsprintfA(buf, "[ADDRES] %-20s = %p\n", label, address);
  OutputDebugStringA(buf);
  ConsoleWrite(buf, len);
}

void LoggHex32(const char *label, DWORD value) {
  char buf[256];
  int len =
      wsprintfA(buf, "[HEX 32] %-20s = 0x%08X (%lu)\n", label, value, value);
  OutputDebugStringA(buf);
  ConsoleWrite(buf, len);
}

void LoggHex16(const char *label, WORD value) {
  char buf[256];
  int len = wsprintfA(buf, "[HEX 16] %-20s = 0x%04X (%u)\n", label, value, value);
  OutputDebugStringA(buf);
  ConsoleWrite(buf, len);
}
//////////////////////////////////////////////////////////////////////////////
// 1. Output formatting helpers
//////////////////////////////////////////////////////////////////////////////
// void LoggDelta(const char *label, LONG_PTR delta) {
//   char buf[256];
//   int len = wsprintfA(buf, "[DELTA ] %-19s = 0x%016llX (%lld)\n", label,
//                       (unsigned long long)delta, (long long)delta);
//   OutputDebugStringA(buf);
//   ConsoleWrite(buf, len);
// }
void LoggDelta(const char *label, LONG_PTR delta) {
    char buf[256];
    int len = wsprintfA(buf, "[DELTA ] %-19s = 0x%016I64X (%I64d)\n", label,
                        (unsigned __int64)delta, (__int64)delta);
    OutputDebugStringA(buf);
    ConsoleWrite(buf, len);
}
// void LoggDelta(const char *label, LONG_PTR delta) {
//     char buf[256];
//     int len = wsprintfA(buf, "[DELTA ] %-19s = %p (%I64d)\n", label,
//                         (void*)delta, (__int64)delta);
//     OutputDebugStringA(buf);
//     ConsoleWrite(buf, len);
// }
void LoggHex64(const char *label, ULONGLONG value) {
    char buf[256];
    int len = wsprintfA(buf, "[HEX 64] %-20s = 0x%016I64X (%I64u)\n", label, value, value);
    OutputDebugStringA(buf);
    ConsoleWrite(buf, len);
}
void LoggPointer(const char *label, LONG_PTR delta) {
  char buf[256];
  int len = wsprintfA(buf, "[*] %-19s = %p\n", label, (void*)delta);
  OutputDebugStringA(buf);
  ConsoleWrite(buf, len);
}
//////////////////////////////////////////////////////////////////////////////
// 2. Human-readable logging helpers
//////////////////////////////////////////////////////////////////////////////
void LoggInfo(const char *msg) {
  char buf[512];
  int len = wsprintfA(buf, "[INFO  ]  %s\n", msg);
  OutputDebugStringA(buf);
  ConsoleWrite(buf, len);
}

void LoggError(const char *msg) {
  char buf[512];
  int len = wsprintfA(buf, "[ERROR ] %s\n", msg);
  OutputDebugStringA(buf);
  ConsoleWrite(buf, len);
}