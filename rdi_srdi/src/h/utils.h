#pragma once
#include <windows.h>



void LoggAddress(const char *label, void *address);
void LoggHex32(const char *label, DWORD value) ;
void LoggHex16(const char *label, WORD value);
void LoggHex64(const char *label, ULONGLONG value) ;
void LoggDelta(const char *label, LONG_PTR delta);
void LoggPointer(const char *label, LONG_PTR delta);
void LoggInfo(const char *msg);
void LoggError(const char *msg);
