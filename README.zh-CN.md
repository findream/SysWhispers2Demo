[English](https://github.com/findream/SysWhispers2Demo/blob/main/README.md) | 简体中文
## 0x00 项目简介
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo是通过逆向分析kernel32.dll或者kernelbase.dll文件，从而仿写部分Win32 API的实现逻辑，以解决部分SysWhispers2使用者在利用SysWhispers2做EDR规避时候所遇到的开发困难。SysWhispers2Demo在仿写Win32 API的时候，**部分采用最小开发原则**，即部分参数需要使用微软API文档所约定的默认参数，以减轻仿写的工作量。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)主要是由jthuraisamy开发的通过Syscall用来规避EDR。SysWhispers2使用很方便，无需指定windows 操作系统版本，只需要通过syswhispers.py生成Nt*函数所需要的函数参数，调用约定等。但是，Ring3的逻辑需要自己实现，这就是SysWhispers2Demo的目的。

## 0x01 文件描述
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo主要有3个文件`SysWhispers2Demo.cpp`,`SysWhispers2Demo.h`,`prototypes.h`。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; SysWhispers2Demo.cpp文件是Ring3层的实现逻辑。目前，主要实现了包括文件操作，注册表操作，进程操作，以及线程操作。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 文件操作，基本实现了文件的创建，读写，删除等操作，具体支持的Win32 API如下：
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

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 注册表操作，也实现了注册表使用的常见API函数,支持两种ANSI和UNICODE字符。
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

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 进程操作，也实现了常见的进程使用的API函数。***因为CreateProcess内部实现的过于复杂，目前仅仅实现了能创建进程，但是创建进程之后，需要传出的参数，如ProcessInformation没有实现***
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

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;线程操作，也实现了常见的线程使用的API函数。
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

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo.h是头文件，包含了SysWhispers2Demo.cpp的函数声明，和库所需要Nt*函数指针。前面typedef包含的是函数指针，后面是函数声明。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;为了增强开发的方便程度，SysWhispers2Demo采用的是和win32 API同样的函数原型，使用SysWhispers2Demo就像使用原生的Win32一模一样。仅仅需要在你所需要的Win32 API名称后面加一个Stub以示区别，例如，假如需要使用NtCreateFile创建文件，那么在Ring3需要调用CreateFileA，那只需要调用SysWhispers2Demo内置的CreateFileA_Stub。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;prototypes.h包含的是一些所需要的变量类型等数据。这个是我删除了ntdll.h文件的函数声明。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;上面三个文件，在使用的时候，需要导入新项目。除此以外，还有两个文件，ntdll.h存储了一些函数声明和遍历类型，使用者可以在这里查看函数原型。而main.cpp我写的部分测试用例，是关于部分Win32 API的使用。**这两个文件不需要导入项目。**

## 0x02 使用步骤
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SysWhispers2Demo仅仅支持x64，x86在Syscall会遇到莫名其妙的问题，可以解决，但是不具有通用性，暂时不考虑支持x86。在win10 x64 vs2017编译通过。其他未测。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;在你使用SysWhispers2生成了文件之后，假设生成了文件是`syscall.c`,`syscall.h`，以及`syscall.asm`。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;第一步，在生成的syscall.h文件中，删除所有的变量定义。因为SysWhispers2会生成变量定义，而SysWhispers2Demo也带有变量定义，两者会冲突。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;第二歩，在生成的Syscall.h文件中，导入prototypes.h头文件。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;第三歩，在SysWhispers2Demo库文件SysWhioers2Demo.c文件中，导入syscall.h头文件，目的是修改链接的Nt函数。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;第四步，注释SysWhispers2Demo库文件SysWhioers2Demo.c文件中，指定函数的动态获取函数地址的语句。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;除此以外，也可以选择直接Copy SysWhispers2Demo.cpp中，你想要使用的函数。 No Care！这应该是最容易的。

## 0x03 版本信息
### v0.1.0（2022-06-20）
* 初始版本，支持常见的文件，注册表，进程，线程 API操作。

## 0x04 协议
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;直接用就是了。

## 0x05 FAQ
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;欢迎大家提PR

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;如果还有需要实现的kernel层API函数，或者bug，欢迎联系wanghacky@qq.com。