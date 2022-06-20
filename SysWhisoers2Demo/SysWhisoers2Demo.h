#pragma once
#include <stdio.h>
#include <windows.h>
#include <ntstatus.h>
#include <winnt.h>
#include "prototypes.h"
#pragma warning(disable:4996)


/*
	Other Optional
*/

typedef VOID (*pfnRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef BOOLEAN (*pfnRtlDosPathNameToNtPathName_U)(
	PCWSTR DosFileName,
	PUNICODE_STRING NtFileName,
	PWSTR* FilePart,
	PVOID Reserved
	);

typedef NTSTATUS(*pfnNtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
	);

typedef NTSYSAPI ULONG(*pfnRtlNtStatusToDosError)(
	NTSTATUS Status
	);

typedef POBJECT_ATTRIBUTES(*pfnBaseFormatObjectAttributes)(
	POBJECT_ATTRIBUTES ObjectAttributes,
	PSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL,
	PUNICODE_STRING ObjectName);

typedef PTEB(*pfnNtCurrentTeb)();

typedef PVOID(*pfnRtlAllocateHeap)(
	PVOID HeapHandle,
	ULONG Flags,
	SIZE_T Size);

typedef BOOLEAN(*pfnRtlFreeHeap)(
	PVOID HeapHandle,
	ULONG Flags,
	PVOID BaseAddress
	);

typedef VOID(*pfnRtlSetLastWin32Error)(DWORD err);
/*
	File Optional
*/


typedef NTSTATUS(*pfnNtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	);


typedef NTSTATUS (*pfnNtDeleteFile)(
	POBJECT_ATTRIBUTES ObjectAttributes
);


typedef NTSTATUS (*pfnNtReadFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PVOID            ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
);

typedef NTSTATUS (*pfnNtWriteFile)(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
);

typedef NTSTATUS (*pfnNtQueryInformationFile)
(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS(*pfnNtSetInformationFile)(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS(*pfnNtOpenFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions
);

typedef NTSTATUS (*pfnNtQueryDirectoryFile)(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN ReturnSingleEntry,
	PUNICODE_STRING FileName,
	BOOLEAN RestartScan
);

typedef NTSTATUS (*pfnNtFlushBuffersFile)(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock
);


//RegOptional
typedef NTSTATUS (*pfnNtCreateKey)(
	PHANDLE            KeyHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG              TitleIndex,
	PUNICODE_STRING    Class,
	ULONG              CreateOptions,
	PULONG             Disposition
);

typedef NTSTATUS (*pfnRtlFormatCurrentUserKeyPath)(
	 PUNICODE_STRING CurrentUserKeyPath
);

typedef NTSTATUS (*pfnNtOpenKey)(
	PHANDLE            KeyHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);


typedef NTSTATUS (*pfnNtOpenKeyEx)(
	PHANDLE            KeyHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG              OpenOptions
);

typedef void (*pfnRtlFreeUnicodeString)(
	PUNICODE_STRING UnicodeString
);

typedef NTSTATUS (*pfnNtSetValueKey)(
	HANDLE          KeyHandle,
	PUNICODE_STRING ValueName,
	ULONG           TitleIndex,
	ULONG           Type,
	PVOID           Data,
	ULONG           DataSize
);

typedef NTSTATUS (*pfnNtDeleteValueKey)(
	HANDLE          KeyHandle,
	PUNICODE_STRING ValueName
);

typedef NTSTATUS (*pfnNtQueryValueKey)(
	HANDLE                      KeyHandle,
	PUNICODE_STRING             ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID                       KeyValueInformation,
	ULONG                       Length,
	PULONG                      ResultLength
);

typedef NTSTATUS (*pfnRtlMultiByteToUnicodeN)(
	PWCH       UnicodeString,
	ULONG      MaxBytesInUnicodeString,
	PULONG     BytesInUnicodeString,
	const CHAR *MultiByteString,
	ULONG      BytesInMultiByteString
);

typedef NTSTATUS (*pfnNtOpenKey)(
	PHANDLE            KeyHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (*pfnNtClose)(
	HANDLE Handle
);

typedef NTSTATUS (*pfnNtQueryKey)(
	HANDLE                KeyHandle,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength
);

typedef NTSTATUS (*pfnNtEnumerateKey)(
	HANDLE                KeyHandle,
	ULONG                 Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength
);




/*
	Process Optional
*/

typedef BOOL (*pfnCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL (*pfnCreateProcessW)(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);



typedef NTSTATUS (*pfnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING ImagePathName,
	PUNICODE_STRING DllPath,
	PUNICODE_STRING CurrentDirectory,
	PUNICODE_STRING CommandLine,
	PVOID Environment,
	PUNICODE_STRING WindowTitle,
	PUNICODE_STRING DesktopInfo,
	PUNICODE_STRING ShellInfo,
	PUNICODE_STRING RuntimeData,
	ULONG Flags // Pass RTL_USER_PROCESS_PARAMETERS_NORMALIZED to keep parameters normalized
);



typedef NTSTATUS (*pfnRtlDestroyProcessParameters)(
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters
);

typedef NTSTATUS (*pfnNtCreateUserProcess)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PPS_CREATE_INFO CreateInfo,
	PPS_ATTRIBUTE_LIST AttributeList
);


typedef NTSTATUS (*pfnNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);



typedef NTSTATUS (*pfnNtTerminateProcess)(
	HANDLE   ProcessHandle,
	NTSTATUS ExitStatus
);

typedef NTSTATUS (*pfnNtReadVirtualMemory)(
	HANDLE              ProcessHandle,
	PVOID               BaseAddress,
	PVOID               Buffer,
	ULONG               NumberOfBytesToRead,
	PULONG              NumberOfBytesReaded
	);

typedef NTSTATUS(*pfnNtWriteVirtualMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	ULONG  *lpNumberOfBytesWritten
	);

typedef NTSTATUS (*pfnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

typedef VOID(*pfnRtlGetCurrentProcessorNumberEx)(PROCESSOR_NUMBER *processor);

typedef NTSTATUS (*pfnNtQuerySystemInformationEx)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	ULONG *ReturnLength);

/*
	Thread Optional
*/

typedef NTSTATUS(*pfnNtCreateThreadEx)
(
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID lpStartAddress,
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer
	);

typedef NTSTATUS (*pfnNtQueryInformationThread)(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
);

typedef NTSTATUS (*pfnNtGetContextThread)(
	HANDLE               ThreadHandle,
	PCONTEXT            pContext);


typedef NTSTATUS (*pfnNtOpenThread)(
	PHANDLE            ThreadHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);


typedef NTSTATUS (*pfnNtResumeThread)(
	HANDLE   ThreadHandle,
	PULONG   SuspendCount);


typedef NTSTATUS (*pfnNtSetContextThread)(
	HANDLE    ThreadHandle,
	PCONTEXT  Context);

typedef NTSTATUS (*pfnNtSetThreadExecutionState)(
	EXECUTION_STATE NewFlags,
	EXECUTION_STATE *PreviousFlags);

typedef NTSTATUS (*pfnNtSuspendThread)(
	HANDLE   ThreadHandle,
	PULONG   PreviousSuspendCount);

typedef NTSTATUS (*pfnNtTerminateThread)(
	HANDLE               ThreadHandle,
	NTSTATUS             ExitStatus);



//==============================================
//函数申明区

/*
	文件操作：
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

*/
HANDLE CreateFileA_Stub(LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile);

HANDLE CreateFileW_Stub(LPCWSTR  lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile);

BOOL ReadFile_Stub(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

BOOL WriteFile_Stub(
	HANDLE       hFile,
	LPVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped);

NTSTATUS NtQueryInformationFile_Stub(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS NtSetInformationFile_Stub(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS NtOpenFile_Stub(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
);

NTSTATUS NtQueryDirectoryFile_Stub(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
);

BOOL DeleteFileA_Stub(
	LPCSTR lpFileName
);

BOOL DeleteFileW_Stub(
	LPCWSTR lpFileName
);

HANDLE CreateThread_Stub(LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId);


DWORD WaitForSingleObjectEx_Stub(
	HANDLE hHandle,
	DWORD  dwMilliseconds,
	BOOL   bAlertable
);






/*
    注册表操作
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

*/
LSTATUS RegCreateKeyExW_Stub(
	HKEY                        hKey,
	LPCWSTR                     lpSubKey,
	DWORD                       Reserved,
	LPWSTR                      lpClass,
	DWORD                       dwOptions,
	REGSAM                      samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY                       phkResult,
	LPDWORD                     lpdwDisposition
);

LSTATUS RegCreateKeyExA_Stub(
	HKEY                        hKey,
	LPCSTR                      lpSubKey,
	DWORD                       Reserved,
	LPSTR                       lpClass,
	DWORD                       dwOptions,
	REGSAM                      samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY                       phkResult,
	LPDWORD                     lpdwDisposition
);

LSTATUS RegCreateKeyA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
);
LSTATUS RegCreateKeyW_Stub(
	HKEY   hKey,
	LPCWSTR  lpSubKey,
	PHKEY  phkResult
);
LSTATUS RegSetValueExA_Stub(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
);

LSTATUS RegSetValueExW_Stub(
	HKEY       hKey,
	LPCWSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
);

LSTATUS RegSetValueA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  dwType,
	LPCSTR lpData,
	DWORD  cbData
);

LSTATUS RegSetValueW_Stub(
	HKEY   hKey,
	LPCWSTR lpSubKey,
	DWORD  dwType,
	LPCWSTR lpData,
	DWORD  cbData
);

LSTATUS RegDeleteValueA_Stub(
	HKEY   hKey,
	LPCSTR lpValueName
);

LSTATUS RegDeleteValueW_Stub(
	HKEY    hKey,
	LPCWSTR lpValueName
);

LSTATUS RegQueryValueExW_Stub(
	HKEY    hKey,
	LPCWSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
);

LSTATUS RegQueryValueExA_Stub(
	HKEY    hKey,
	LPCSTR  lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
);

LSTATUS RegQueryValueW_Stub(
	HKEY    hKey,
	LPCWSTR lpSubKey,
	LPWSTR  lpData,
	PLONG   lpcbData
);

LSTATUS RegQueryValueA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	LPSTR  lpData,
	PLONG  lpcbData
);

LSTATUS RegOpenKeyExW_Stub(
	HKEY    hKey,
	LPCWSTR lpSubKey,
	DWORD   ulOptions,
	REGSAM  samDesired,
	PHKEY   phkResult
);

LSTATUS RegOpenKeyExA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
);

LSTATUS RegOpenKeyW_Stub(
	HKEY   hKey,
	LPCWSTR lpSubKey,
	PHKEY  phkResult
);

LSTATUS RegOpenKeyA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
);

LSTATUS RegCloseKey_Stub(
	HKEY hKey
);
LSTATUS RegQueryInfoKeyW_Stub(
	HKEY      hKey,
	LPWSTR    lpClass,
	LPDWORD   lpcchClass,
	LPDWORD   lpReserved,
	LPDWORD   lpcSubKeys,
	LPDWORD   lpcbMaxSubKeyLen,
	LPDWORD   lpcbMaxClassLen,
	LPDWORD   lpcValues,
	LPDWORD   lpcbMaxValueNameLen,
	LPDWORD   lpcbMaxValueLen,
	LPDWORD   lpcbSecurityDescriptor,
	PFILETIME lpftLastWriteTime
);

LSTATUS RegQueryInfoKeyA_Stub(
	HKEY      hKey,
	LPSTR     lpClass,
	LPDWORD   lpcchClass,
	LPDWORD   lpReserved,
	LPDWORD   lpcSubKeys,
	LPDWORD   lpcbMaxSubKeyLen,
	LPDWORD   lpcbMaxClassLen,
	LPDWORD   lpcValues,
	LPDWORD   lpcbMaxValueNameLen,
	LPDWORD   lpcbMaxValueLen,
	LPDWORD   lpcbSecurityDescriptor,
	PFILETIME lpftLastWriteTime
);


LSTATUS RegEnumKeyExW_Stub(
	HKEY      hKey,
	DWORD     dwIndex,
	LPWSTR     lpName,
	LPDWORD   lpcchName,
	LPDWORD   lpReserved,
	LPWSTR     lpClass,
	LPDWORD   lpcchClass,
	PFILETIME lpftLastWriteTime
);

LSTATUS RegEnumKeyExA_Stub(
	HKEY      hKey,
	DWORD     dwIndex,
	LPSTR     lpName,
	LPDWORD   lpcchName,
	LPDWORD   lpReserved,
	LPSTR     lpClass,
	LPDWORD   lpcchClass,
	PFILETIME lpftLastWriteTime
);

LSTATUS RegEnumKeyW_Stub(
	HKEY   hKey,
	DWORD  dwIndex,
	LPWSTR lpName,
	DWORD  cchName
);

LSTATUS RegEnumKeyA_Stub(
	HKEY  hKey,
	DWORD dwIndex,
	LPSTR lpName,
	DWORD cchName
);

/*
	进程操作:
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
*/

BOOL CreateProcessA_Stub(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

BOOL CreateProcessW_Stub(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

UINT WinExec_Stub(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
);

HANDLE OpenProcess_Stub(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
);


BOOL TerminateProcess_Stub(
	HANDLE hProcess,
	UINT   uExitCode
);

BOOL ReadProcessMemory_Stub(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesRead
);


BOOL WriteProcessMemory_Stub(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
);

BOOL GetExitCodeProcess_Stub(
	HANDLE  hProcess,
	LPDWORD lpExitCode
);


BOOL GetLogicalProcessorInformation_Stub(
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer,
	PDWORD                                ReturnedLength
);

BOOL GetProcessAffinityMask_Stub(
	HANDLE     hProcess,
	PDWORD_PTR lpProcessAffinityMask,
	PDWORD_PTR lpSystemAffinityMask
);

BOOL IsWow64Process_Stub(
	HANDLE hProcess,
	PBOOL  Wow64Process
);

DWORD GetProcessId_Stub(
	HANDLE Process
);


/*
	线程操作:
	CreateThread
	CreateRemoteThreadEx
	ResumeThread
	OpenThread
	GetThreadContext
	GetExitCodeThread
	GetProcessIdOfThread
	TerminateThread
*/

HANDLE CreateThread_Stub(LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId);

HANDLE CreateRemoteThreadEx_Stub(
	HANDLE                       hProcess,
	LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	SIZE_T                       dwStackSize,
	LPTHREAD_START_ROUTINE       lpStartAddress,
	LPVOID                       lpParameter,
	DWORD                        dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD                      lpThreadId
);

DWORD ResumeThread_Stub(
	HANDLE hThread
);

HANDLE OpenThread_Stub(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
);

BOOL GetThreadContext_Stub(
	HANDLE    hThread,
	LPCONTEXT lpContext
);


BOOL GetExitCodeThread_Stub(
	HANDLE  hThread,
	LPDWORD lpExitCode
);


DWORD GetProcessIdOfThread_Stub(
	HANDLE Thread
);

BOOL TerminateThread_Stub(HANDLE hThread, 
	DWORD dwExitCode);