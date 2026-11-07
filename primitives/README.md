# primitives
```
Small Windows x64 sandbox for core primitives: VirtualAlloc, memcpy, VirtualProtect, and direct shellcode execution.
```
## Overview

- **Target OS:** Windows
- **Architecture:** x64
- **Language:** C++
- **Type:** Primitive Test Harness

## Key Capabilities & OpSec

- **Evasion Features:** None; minimal execution primitive validation
- **Execution Model:** Local memory execution
- **Dependencies:** Win32 API only

## Compilation & Usage

### Prerequisites
```bash
- x86_64-w64-mingw32-g++
```

### Build Commands
```bash
x86_64-w64-mingw32-g++ primitives.cpp -o test.exe -luser32 -lkernel32 -static -std=c++26
```

## Workspace Extraction & Clean Checkout
```bash
git clone --filter=blob:none --no-checkout <REPOSITORY_URL>
cd <REPO_FOLDER>
git sparse-checkout init --cone
git sparse-checkout set "primitives"
git checkout
rm -rf .git
```

## Disclaimer

Educational and authorized security testing only.
