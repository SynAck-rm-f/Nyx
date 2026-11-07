# pe-parser-lght
```
Lightweight PE parser that maps a file, validates DOS/NT headers, walks sections, and prints import/export metadata.
```
## Overview

- **Target OS:** Windows
- **Architecture:** x64
- **Language:** C++
- **Type:** PE Parser / Introspection Utility

## Key Capabilities & OpSec

- **Evasion Features:** None; analysis-only
- **Execution Model:** File-backed PE parsing
- **Dependencies:** Win32 API only

## Compilation & Usage

### Prerequisites
```bash
- x86_64-w64-mingw32-g++
```

### Build Commands
```bash
x86_64-w64-mingw32-g++ parser-main.c -o pe-parser-lght.exe -luser32 -lkernel32 -static
```

## Workspace Extraction & Clean Checkout
```bash
git clone --filter=blob:none --no-checkout <REPOSITORY_URL>
cd <REPO_FOLDER>
git sparse-checkout init --cone
git sparse-checkout set "pe-parser-lght"
git checkout
rm -rf .git
```

## Disclaimer

Educational and authorized security testing only.
