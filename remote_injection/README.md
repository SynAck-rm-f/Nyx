# remote_injection
```
Remote process injection utilities for Windows x64. The folder contains a PID-based injector and a process-name resolver variant.
```
## Overview

- **Target OS:** Windows
- **Architecture:** x64
- **Language:** C / C++
- **Type:** Loader / Process Injection Utility

## Key Capabilities & OpSec

- **Evasion Features:** Remote memory allocation, shellcode staging, process-name PID lookup
- **Execution Model:** In-memory remote thread execution
- **Dependencies:** Win32 API only

## Compilation & Usage

### Prerequisites
```bash
- x86_64-w64-mingw32-g++
- make (optional)
```

### Build Commands

#### PID-based injector
```bash
x86_64-w64-mingw32-g++ remote_arg_cmd.cpp -o remote_injection.exe -luser32 -lkernel32 -static -std=c++26
```

#### Process-name injector
```bash
x86_64-w64-mingw32-g++ -I../inch process_enum.cpp remote_list_prcss_togg.c -o remote_list_process.exe -luser32 -lkernel32 -static
```

## Workspace Extraction & Clean Checkout

### Option 1: Selective Folder Checkout (Sparse Checkout)
```bash
git clone --filter=blob:none --no-checkout <REPOSITORY_URL>
cd <REPO_FOLDER>
git sparse-checkout init --cone
git sparse-checkout set "remote_injection"
git checkout
rm -rf .git
```

### Option 2: Direct API Extraction via GitHub CLI (`gh`)
```bash
gh api repos/<OWNER>/<REPO>/zipball/main > workspace.zip
unzip workspace.zip && rm workspace.zip

# Or extract a single file directly
gh api repos/<OWNER>/<REPO>/contents/"<FILE_PATH>" --jq '.content' | base64 -d > <OUTPUT_FILE>
```

## Disclaimer

Educational and authorized security testing only.
