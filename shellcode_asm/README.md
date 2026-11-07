# shellcode_asm
```
Linux x86_64 assembly payload lab focused on turning PIC-friendly NASM into raw opcodes through objdump/objcopy extraction.
```
## Overview

- **Target OS:** Linux x64
- **Architecture:** x86_64
- **Language:** Assembly
- **Type:** Shellcode / PIC Payload Lab

## Key Capabilities & OpSec

- **Evasion Features:** Position-independent code, relocation avoidance, raw opcode extraction
- **Execution Model:** Assembly -> ELF object -> raw binary shellcode
- **Dependencies:** NASM, binutils

## Compilation & Usage

### Prerequisites
```bash
- nasm
- objdump
- objcopy
- hexdump or xxd
```

### Build Commands
```bash
nasm -f elf64 hello.asm -o hello.o
objdump -d hello.o
readelf -r hello.o
objcopy -O binary --only-section=.text hello.o payload.bin
xxd -i payload.bin
```

## Notes

- `objcopy -O binary` strips ELF metadata and keeps the raw section bytes.
- Shellcode must stay PIC-safe to survive arbitrary load addresses.
- Prefer RIP-relative patterns and avoid relocations where possible.

## Workspace Extraction & Clean Checkout
```bash
git clone --filter=blob:none --no-checkout <REPOSITORY_URL>
cd <REPO_FOLDER>
git sparse-checkout init --cone
git sparse-checkout set "shellcode_asm"
git checkout
rm -rf .git
```

## Disclaimer

Educational and authorized security testing only.
