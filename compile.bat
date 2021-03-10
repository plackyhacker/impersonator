@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimpersonator.cpp /link /OUT:impersonator.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
