```
///////////////////////////////
// DLL
//////////////////////////////
x86_64-w64-mingw32-g++ -shared -o main.dll main.cpp -static -luser32 -lkernel32 -fpermissive -std=c++26
wine rundll32.exe main.dll,DllMain


///////////////////////////////
// make loader.cpp
//////////////////////////////
x86_64-w64-mingw32-g++ loader.cpp src/c/utils.cpp -o loader.exe -static -static-libgcc -static-libstdc++ -luser32 -lkernel32 -std=c++26 -g
wine loader.exe



grep '#arch' ~/.wine/system.reg
wine cmd /c ver
winecfg 
winecfg 
winetricks -q dotnet48
winetricks 


bear semantic --output raw_events.json -- make x86_64-w64-mingw32-g++ -shared -o main.dll main.cpp -static -luser32 -lkernel32 -fpermissive -std=c++

cd /chemin/vers/ton/build

x86_64-w64-mingw32-g++ \
    -c ../src/loader_r.cpp -o loader_r.o
x86_64-w64-mingw32-g++ \
    -c ../src/ntutils.cpp -o ntutils.o
x86_64-w64-mingw32-g++ \
    -c ../src/peb.cpp -o peb.o

# Link
x86_64-w64-mingw32-g++ \
    loader_r.o ntutils.o peb.o \
    -o loader.exe \
    -nostdlib \
    -nostartfiles \
    -nodefaultlibs \
    -Wl,-eentry \
    -lkernel32


// final test 
nc -nlvp 4444
Z:\home\nabiasa\Desktop\LEARN\cpp_injection\rdi_srdi\out\build\GCC 16.1.0 x86_64-w64-mingw32>dir
Volume in drive Z has no label.
Volume Serial Number is ae54-7910

Directory of Z:\home\nabiasa\Desktop\LEARN\cpp_injection\rdi_srdi\out\build\GCC 16.1.0 x86_64-w64-mingw32

08/15/2026  02:42 PM    <DIR>          .
08/12/2026  11:43 PM    <DIR>          ..
04/01/2026  04:33 PM        47,976,360 capa
04/01/2026  04:33 PM        47,477,971 capa-v9.4.0-linux.zip
08/15/2026  01:45 PM            16,418 CMakeCache.txt
08/15/2026  02:31 PM    <DIR>          CMakeFiles
08/15/2026  01:52 PM             2,338 cmake_install.cmake
08/15/2026  01:52 PM               958 compile_commands.json
08/15/2026  02:31 PM            37,376 loader.exe
08/15/2026  01:52 PM             6,256 Makefile
08/13/2026  12:16 AM    <DIR>          src
       7 files               95,517,677 bytes
       4 directories     65,309,253,632 bytes free



printf("RtlInitUnicodeString         = 0x%x\n", HASH("RtlInitUnicodeString"));
printf("NtCreateFile                 = 0x%x\n", HASH("NtCreateFile"));
printf("NtQueryInformationFile       = 0x%x\n", HASH("NtQueryInformationFile"));
printf("NtAllocateVirtualMemory      = 0x%x\n", HASH("NtAllocateVirtualMemory"));
printf("NtReadFile                   = 0x%x\n", HASH("NtReadFile"));
printf("NtWriteFile                  = 0x%x\n", HASH("NtWriteFile"));
printf("RtlMultiByteToUnicodeN       = 0x%x\n", HASH("RtlMultiByteToUnicodeN"));
printf("LdrLoadDll                   = 0x%x\n", HASH("LdrLoadDll"));
printf("LdrGetProcedureAddress       = 0x%x\n", HASH("LdrGetProcedureAddress"));
printf("NtClose                      = 0x%x\n", HASH("NtClose"));
printf("NtReadVirtualMemory          = 0x%x\n", HASH("NtReadVirtualMemory"));
printf("NtFreeVirtualMemory          = 0x%x\n", HASH("NtFreeVirtualMemory"));
printf("NtProtectVirtualMemory       = 0x%x\n", HASH("NtProtectVirtualMemory"));
printf("NtFlushInstructionCache      = 0x%x\n", HASH("NtFlushInstructionCache"));

  // printf("\n=== defs.h ===\n");
  // printf("RtlInitUnicodeString         attendu: 0xe17f353f\n");
  // printf("NtCreateFile                 attendu: 0x962c4683\n");
  // printf("NtQueryInformationFile       attendu: 0xb54956cb\n");
  // printf("NtAllocateVirtualMemory      attendu: 0xec50426f\n");
  // printf("NtReadFile                   attendu: 0xab569438\n");
  // printf("RtlMultiByteToUnicodeN       attendu: 0xaba11095\n");
  // printf("LdrLoadDll                   attendu: 0x43638559\n");
  // printf("LdrGetProcedureAddress       attendu: 0x3b93e684\n");
  // printf("NtClose                      attendu: 0xf78fd98f\n");
  // printf("NtReadVirtualMemory          attendu: 0x58bdb7be\n");
  // printf("NtFreeVirtualMemory          attendu: 0xf29625d3\n");
  // printf("NtProtectVirtualMemory       attendu: 0x357d60b3\n");
  // printf("NtFlushInstructionCache      attendu: 0xc5f7ca5e\n");
  ```
