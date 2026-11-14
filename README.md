# Offensive C/C++ Research Arsenal

A collection of low-level C and C++ research projects focused on Windows internals, process execution, PE loading, memory management, and adversary techniques.

The repository documents practical implementations, technical experiments, and research into mechanisms commonly encountered in offensive security, malware analysis, and endpoint security research.

## Research Areas

- Windows Internals and Process Management
- Process Execution and Memory Manipulation
- PE Format and Manual Mapping
- Shellcode and Position-Independent Code
- Dynamic API Resolution
- System Calls and Native Windows APIs
- Endpoint Security and EDR Telemetry
- Cryptography and Payload Formats
- Anti-Analysis Mechanisms

## Implemented Projects

Projects currently available in the repository:

- `self_injection` — Basic self-injection research.
- `remote_injection` — Windows x64 process injection experiments.
- `custom_process_dll` — Custom process and DLL initialization.
- `dll_injection` — Classic Windows DLL injection research.
- `primitives` — Windows memory allocation, protection, and execution primitives.
- `pe-parser-lght` — Lightweight PE parser and import/export inspection.
- `rdi_srdi` — Reflective DLL loading research.
- `shellcode_asm` — Linux x86_64 position-independent assembly and shellcode lab.

## Research Roadmap

Additional research topics are maintained separately from implemented projects. Their presence in the roadmap does not imply an existing implementation.

## Environment

- Windows x64
- C / C++
- Windows API and Native API
- NASM
- Linux x86_64

All experiments are intended for controlled research and laboratory environments.