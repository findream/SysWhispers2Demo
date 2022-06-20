English | [简体中文](https://github.com/findream/SysWhispers2Demo/blob/main/README.zh-CN.md)

## 0x00 Project Description
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo is a reverse analysis of the kernel32.dll or kernelbase.dll file, so as to imitate the implementation logic of part of the Win32 API, so as to solve the development difficulties encountered by some SysWhispers2 users when using SysWhispers2 for EDR evasion. When SysWhispers2Demo imitates the Win32 API, **partly adopts the principle of minimum development**, that is, some parameters need to use the default parameters stipulated in the Microsoft API document to reduce the workload of imitation.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2 is mainly developed by jthuraisamy to avoid EDR through Syscall. SysWhispers2 is very convenient to use. It is not necessary to specify the version of the windows operating system. It only needs to generate the function parameters and calling conventions required by the Nt* function through syswhispers.py. However, Ring3's logic needs to be implemented by itself, which is the purpose of SysWhispers2Demo.

## 0x01 File Description
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo mainly has 3 files`SysWhispers2Demo.cpp`,`SysWhispers2Demo.h`,`prototypes.h`.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; SysWhispers2Demo.cpp file is the implementation logic of the Ring3 layer. At present, it mainly implements file operations, registry operations, process operations, and thread operations.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
File operation basically realizes file creation, reading and writing, deletion and other operations. The specific supported Win32 APIs are as follows:
```
CreateFileA
CreateFileW
ReadFile
WriteFile
NtQueryInformationFile
NtSetInformationFile
NtOpenFile
NtQueryDirectoryFile
DeleteFileA
DeleteFileW
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Registry operations also implement common API functions used by the registry, and support two ANSI and UNICODE characters.
```
RegCreateKeyExA(W)
RegCreateKeyA(W)
RegSetValueExA(W)
RegDeleteValueA(W)
RegQueryValueExA(W)
RegOpenKeyExA(W)
RegOpenKeyA(W)
RegCloseKey
RegQueryInfoKeyA(W)
RegEnumKeyExA(W)
RegEnumKeyA(W)
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Process operations also implement common API functions used by processes. ***Because the internal implementation of CreateProcess is too complicated, currently only the process can be created, but after the process is created, the parameters that need to be passed out, such as ProcessInformation, are not implemented***
```
CreateProcessA(W)
WinExec
OpenProcess
TerminateProcess
ReadProcessMemory
WriteProcessMemory
GetExitCodeProcess
GetLogicalProcessorInformation
GetProcessAffinityMask
IsWow64Process
GetProcessId
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Thread operations also implement common thread API functions.
```
CreateThread
CreateRemoteThreadEx
ResumeThread
OpenThread
GetThreadContext
GetExitCodeThread
GetProcessIdOfThread
TerminateThread
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo.h is the header file, which contains the function declarations of SysWhispers2Demo.cpp, and the Nt* function pointers required by the library. The previous typedef contains the function pointer, followed by the function declaration.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In order to enhance the convenience of development, SysWhispers2Demo uses the same function prototype as the win32 API, and using SysWhispers2Demo is exactly the same as using native Win32. Just add a Stub after the name of the Win32 API you need to show the difference. For example, if you need to use NtCreateFile to create a file, then you need to call CreateFileA in Ring3, then you only need to call CreateFileA_Stub built in SysWhispers2Demo.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;prototypes.h contains some required variable types and other data. This is the function declaration I deleted the ntdll.h file.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The above three files need to be imported into a new project when they are used. In addition, there are two files, ntdll.h stores some function declarations and traversal types, users can view function prototypes here. The main.cpp part of the test cases I wrote is about the use of part of the Win32 API. **These two files do not need to be imported into the project. **

## 0x02 Steps for usage
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo only supports x64, x86 will encounter inexplicable problems in Syscall, which can be solved, but it is not universal, so we will not consider supporting x86 for the time being. Compiled on win10 x64 vs2017. Other untested.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
After you have generated the files using SysWhispers2, assume the generated files are `syscall.c`, `syscall.h`, and `syscall.asm`.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The first step is to delete all variable definitions in the generated syscall.h file. Because SysWhispers2 generates variable definitions, and SysWhispers2Demo also has variable definitions, the two will conflict.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The second step, in the generated Syscall.h file, import the prototypes.h header file.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The third step, in the SysWhispers2Demo library file SysWhioers2Demo.c file, import the syscall.h header file, the purpose is to modify the linked Nt function.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The fourth step, comment in the SysWhispers2Demo library file SysWhioers2Demo.c file, specify the statement of the function to dynamically obtain the function address.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;In addition, you can also choose to directly Copy the function you want to use in SysWhispers2Demo.cpp. No Care! This should be the easiest.

## 0x03 Version Information
### v0.1.0（2022-06-20）
* The initial version supports common file, registry, process, thread API operations.

## 0x05 FAQ
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Welcome everyone to submit PR

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;If there are still kernel layer API functions that need to be implemented, or bugs, please contact wanghacky@qq.com.