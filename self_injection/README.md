# Self-Injection Primitives
```
This module provides various implementations of self-injection techniques for Windows x64, ranging from basic RWX allocations to stealthier Memory Protection Toggling (RW -> RX).
```

## Overview

- **Target OS:** Windows 10/11 x64
- **Architecture:** x64
- **Language:** C / C++26
- **Type:** Shellcode Loader / Primitive

## Key Capabilities & OpSec

- **Evasion Features:** 
    - **Protection Toggling:** Transitioning from `PAGE_READWRITE` to `PAGE_EXECUTE_READ` to avoid permanent `RWX` memory signatures.
    - **Self-Handle Acquisition:** Demonstration of `OpenProcess` on `GetCurrentProcessId()` vs direct usage of `VirtualAlloc`.
- **Execution Models:** 
    - **Direct Execution:** Invoking the shellcode via a function pointer (Sync).
    - **Threaded Execution:** Using `CreateThread` for asynchronous execution.
- **Memory Management:** Use of `VirtualAlloc` and `VirtualProtect` for precise control over the allocation lifecycle.

## Compilation & Usage

### Prerequisites
- `x86_64-w64-mingw32-g++` (MinGW-w64)

### Build Commands

To compile the primary self-injection template with C++26 support:

```bash
x86_64-w64-mingw32-g++ self_togg.cpp -o self_injection.exe -luser32 -lkernel32 -static -std=c++26
```

### Lab Setup

1. Start a listener on your attacker machine:
```bash
nc -lvp 8443
```
2. Execute the binary (via Wine for testing or natively on Windows):
```bash
wine self_injection.exe
```

## Implementation Details

| File | Technique | Execution | OpSec Note |
| :--- | :--- | :--- | :--- |
| `self_togg.cpp` | RW -> RX Toggle | Function Pointer | Stealthier; avoids RWX. |
| `virtualprotect.c`| OpenProcess Handle | CreateThread | Higher telemetry (Process Access). |
| `openprocess.c` | OpenProcess Handle | CreateThread | Classic template for process manipulation. |

## Disclaimer
Educational and authorized security testing purposes only.
