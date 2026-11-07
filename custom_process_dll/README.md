# custom_process_dll
```
Minimal Windows x64 sample showing a custom process plus a DLL payload built around DllMain + worker thread startup.
```
## Overview

- **Target OS:** Windows
- **Architecture:** x64
- **Language:** C++
- **Type:** DLL / Demo Loader

## Key Capabilities & OpSec

- **Evasion Features:** DllMain thread offload, dynamic DLL loading
- **Execution Model:** In-process DLL execution
- **Dependencies:** Win32 API only

## Compilation & Usage

### Prerequisites
```bash
- x86_64-w64-mingw32-g++
- wine (optional)
```

### Build Commands

#### DLL
```bash
x86_64-w64-mingw32-g++ -shared -o mylibcode.dll mylibcode.cpp -static -luser32 -lkernel32 -fpermissive -std=c++26
```

#### Host process
```bash
x86_64-w64-mingw32-g++ -o mouse.exe mouse.cpp -mconsole -fpermissive -static -luser32 -lkernel32 -std=c++26
```

## Workspace Extraction & Clean Checkout
```bash
git clone --filter=blob:none --no-checkout <REPOSITORY_URL>
cd <REPO_FOLDER>
git sparse-checkout init --cone
git sparse-checkout set "custom_process_dll"
git checkout
rm -rf .git
```

## Disclaimer

Educational and authorized security testing only.
