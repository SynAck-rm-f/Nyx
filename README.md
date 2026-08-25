# Offensive C/C++ Arsenal

This repository is a comprehensive collection of low-level C and C++ source codes, mirroring techniques actively used by Red Teamers, APTs (Advanced Persistent Threats), and modern malware. 

The primary focus is on **stealth**, **EDR/AV evasion**, **process manipulation**, and **cryptography**. All implementations are designed to be educational, modular, and adaptable for offensive security research and red team operations.

---
[PlaceHolder]
## Process Injection & Execution
Advanced techniques for executing arbitrary code within the context of another process.
*   **injection:** Base Primitives process injection snippets. ---
*   **rdi_srdi:** [PlaceHolder] ---
*   **Process Ghosting:** File-less execution leveraging NTFS transactional semantics.
*   **Process Hypnosis:** Manipulating process memory structures for covert execution.
*   **Process Herpaderping:** Modifying a binary on disk after the image is mapped.
*   **Dirty Vanity:** Forking processes to bypass EDRs during shellcode execution.
*   **Early Cascade Injection:** Injecting shellcode at a very early stage of process initialization.
*   **Thread Hijacking:** Synchronous and Waiting thread hijacking (overwriting return addresses).
*   **DLL Injection & Versatile DLL Injector:** Standard DLL loading into remote processes.
*   **NtCreateUserProcess:** Low-level process creation via undocumented NTAPIs.
[PlaceHolder]
## Evasion & EDR Bypass
Techniques to blind or bypass Endpoint Detection and Response solutions and Antiviruses.
*   **Direct / Indirect / Parallel Syscalls:** Bypassing user-land API hooking using STUB methods.
*   **Unhooking:** Tartarus Gate, Recycle Gate (combining Hells/Halos/Tartarus).
*   **API Hammering:** Overwhelming EDR telemetry channels.
*   **Sleep Obfuscation:** Encrypting memory in-place during sleep periods to evade memory scanners.
*   **Proxy DLL Load:** Hiding execution from ETWTI (Event Tracing for Windows) stack tracing.
*   **AMSI Bypass Techniques:** Patching and bypassing the Anti-Malware Scan Interface.
*   **ETW Patching:** Disabling Event Tracing for Windows telemetry.
*   **Early Exception Handler:** Custom exception handling to disrupt EDR monitoring routines.

## Dynamic Resolution & Stealth
Avoiding static API imports to evade static analysis and import table monitoring.
*   **Dynamic Export Table (PEB):** Calling Windows functions by manually walking the PEB structures.
*   **Dynamic Resolver:** Dynamically resolving and invoking WinAPI functions at runtime.
*   **Manual Resource Fetching:** Replacing `FindResource`, `LoadResource`, `LockResource`, and `SizeofResource` with custom manual implementations.
*   **PEB Offset Finder:** Utility to dynamically find PEB offsets for stealth operations.
*   **Parent Process Spoofing:** Spawning a process that appears to be created by a legitimate parent (e.g., `explorer.exe`).
[PlaceHolder]
## Cryptography & Payload Protection
Obfuscating payloads and shellcodes using various encryption algorithms and formats.
*   **Standard Ciphers:** AES, RC4, XOR, Camellia, ECC Encryption.
*   **Obscure/Custom Ciphers:** Khufu, A5/1 (modified), Madryga Algorithm, Lucifer Algorithm, DFC Algorithm.
*   **Native Windows Crypto:** `SystemFunction032` / `SystemFunction033` (undocumented WinAPI encryption).
*   **Format-Based Obfuscation:** Hiding shellcode inside IPv4, IPv6, MAC, or UUID structures.
*   **Payload Manipulation:** NullxFigure (null byte parsing), Payload Shuffling.
*   **Metadata Modification:** Extracting and embedding custom metadata into binaries.
[PlaceHolder]
## Anti-Analysis & Environment Detection
Detecting sandboxes, virtual machines, and debugging tools.
*   **Anti-Debugging:** Various methods to detect user-mode and kernel-mode debuggers.
*   **Anti-VM (CPU Fan Detection):** Hardware-level check to determine if the system is a physical PC (checks for CPU fan RPM).
*   **Sandbox Evasion:** PoC methods to detect automated analysis environments.
*   **EDR Checker:** Actively detecting the presence of known EDR tools, AV software, and security agents.
[PlaceHolder]
## Post-Exploitation & Utility
Tools and modules for maintaining access, data gathering, and system manipulation.
*   **Persistence:** Various mechanisms to maintain footholds on a target system.
*   **UAC Bypass (CMSTP):** Elevating privileges via the CMSTP.exe COM interface.
*   **Self-Deletion:** Techniques for a binary to delete itself from disk after execution.
*   **Reverse Shell:** Custom C/C++ client-server reverse shell implementation.
*   **Keyloggers:** Custom keystroke logging modules.
*   **Data Exfiltration & C2:** GitHub Stealers (via API), Telegram Operator (remote EXE execution/commands).
*   **System Enumeration:** Modules for efficient target profiling.
*   **Network & IPC:** Interprocess communication using Windows Named Pipes.
*   **Credential Access:** Extracting stored WiFi passwords.
*   **Destructive Actions:** `Rand_Fill` (secure file deletion/disk filling), `Encryfer-X` (Ransomware PoC combining multiple techniques), BSOD Trigger.
*   **Misc:** BlockHandle (SDDL PoC), Timer mechanisms, API Hooking (Trampoline), Debug Library macros.

---

## Disclaimer
**This repository is strictly for educational purposes and authorized security research only.** The techniques provided here can be used to understand how malware operates and how to defend against it. Do not use this code for any illegal or unauthorized activities. The author assumes no liability for misuse.
