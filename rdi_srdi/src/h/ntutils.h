
#pragma once
#include <windows.h>

//////////////////////////////////////////////////////////////////////////////
// 1. Custom formatting helpers
//////////////////////////////////////////////////////////////////////////////
static int DwordToHex(char *buf, DWORD value);
static int QwordToHex(char *buf, unsigned long long value);
static int DwordToDec(char *buf, DWORD value);
//////////////////////////////////////////////////////////////////////////////
// 2. Native write path via NTAPI
//////////////////////////////////////////////////////////////////////////////
void ConsoleWriteNative(const char *buf, int len);

//////////////////////////////////////////////////////////////////////////////
// 3. Logging helpers
//////////////////////////////////////////////////////////////////////////////
void LoggInfoNative(const char *msg);
void LoggErrorNative(const char *msg);
void LoggAddressNative(const char *label, void *address) ;
void LoggHex32Native(const char *label, DWORD value); 
void LoggHex16Native(const char *label, WORD value);
void LoggDeltaNative(const char *label, LONG_PTR delta);



//////
// void LoggInfo(const char *msg);

// void ConsoleWriteNative(const char *buf, int len);
// void LoggInfoNative(const char *msg);
// void LoggErrorNative(const char *msg);
// void LoggAddressNative(const char *label, void *address);
// void LoggHex32Native(const char *label, DWORD value);
// void LoggHex16Native(const char *label, WORD value);
// void LoggDeltaNative(const char *label, LONG_PTR delta);

