# shellcode_asm
Understanding payload execution at the binary level requires stripping away high-level abstractions and observing how the CPU processes raw machine code. Whether generating payloads via Metasploit (msfvenom) or compiling custom position-independent shellcode (PIC), the underlying compilation pipeline follows a deterministic path from assembly source code down to raw opcodes... ... ...

https://synack-rm-f.github.io/post/2026-07-10-intro-shellcode--pipeline-toolschain/
## Overview

- **Target OS:** Linux x64
- **Architecture:** x86_64
- **Language:** Assembly
- **Type:** Shellcode / PIC Payload Lab

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
