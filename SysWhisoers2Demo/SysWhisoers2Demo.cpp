#include "SysWhisoers2Demo.h"

//=========================================
//FileOptional
//========================================

HANDLE CreateFileA_Stub(LPCSTR lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	WCHAR wcFileName[MAX_PATH] = { 0 };
	swprintf(wcFileName, L"%S",lpFileName);
	return CreateFileW_Stub(wcFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE CreateFileW_Stub(LPCWSTR  lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnNtCreateFile NtCreateFile = (pfnNtCreateFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");

	HANDLE hFile = NULL;
	NTSTATUS ntStatus = 0;

	//https://www.programminghunter.com/article/9054520795/
	WCHAR wcFileName[MAX_PATH] = { 0 };
	swprintf(wcFileName, L"%s%s", L"\\??\\", lpFileName);

	UNICODE_STRING DestinationString = { 0 };
	DestinationString.Buffer = (PWSTR)malloc(256);
	RtlInitUnicodeString(&DestinationString, wcFileName); 

	OBJECT_ATTRIBUTES ObjectAttributes;
	ZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = NULL;
	ObjectAttributes.ObjectName = &DestinationString;
	ObjectAttributes.Attributes = ~(FILE_ATTRIBUTE_NORMAL >> 18) & 0x40;
	ObjectAttributes.SecurityDescriptor = 0;

	IO_STATUS_BLOCK IoStatusBlock;

	//DWORD dwCreationDisposition = CREATE_ALWAYS;
	DWORD CreateDisposition = 0;
	switch (dwCreationDisposition)
	{
	case 1:
		CreateDisposition = 2;
		break;
	case 2:
		CreateDisposition = 5;
		break;
	case 3:
		CreateDisposition = 1;
		break;
	case 4:
		CreateDisposition = 3;
		break;
	}

	//DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
	DWORD v10 = dwFlagsAndAttributes;
	//DWORD dwDesiredAccess = FILE_SHARE_WRITE | FILE_SHARE_READ;
	dwCreationDisposition = (~(v10 >> 25) & 0x20 | ((v10 & 0x2000000 | ((v10 & 0x10000000 | ((v10 & 0x8000000 | ((v10 & 0x20000000 | (v10 >> 4) & 0x8000000) >> 1)) >> 8)) >> 6)) >> 11) | 0);
	if ((v10 & 0x4000000) != 0)
	{
		dwCreationDisposition = (dwCreationDisposition | 0x1000);
		dwDesiredAccess |= 0x10000u;
	}
	if ((v10 & 0x200000) != 0)
		dwCreationDisposition = (dwCreationDisposition | 0x200000);
	if ((v10 & 0x100000) != 0)
		dwCreationDisposition = (dwCreationDisposition | 0x400000);
	if ((v10 & 0x2000000) != 0)
	{
		if ((v10 & 0x10) != 0 && (v10 & 0x1000000) != 0 && CreateDisposition == 2)
			dwCreationDisposition = (dwCreationDisposition | 1);
	}
	else
	{
		dwCreationDisposition = (dwCreationDisposition | 0x40);
	}

	dwFlagsAndAttributes &= 0x7FA7;
	dwDesiredAccess |= 0x100080;

	//DWORD dwShareMode = FILE_SHARE_WRITE | FILE_SHARE_READ;

	ntStatus = NtCreateFile(&hFile,
		dwDesiredAccess,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		dwFlagsAndAttributes,
		dwShareMode,
		CreateDisposition,
		dwCreationDisposition, NULL, 0);
	return hFile;
}


BOOL ReadFile_Stub(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	pfnNtReadFile NtReadFile = (pfnNtReadFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile");
	if (hFile == NULL || lpBuffer == NULL)
		return FALSE;
	IO_STATUS_BLOCK IoStatusBlock;
	IoStatusBlock.Information = 0;
	IoStatusBlock.Status = 0;
	NTSTATUS ntStatus = -1;
	ntStatus = NtReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, lpBuffer, nNumberOfBytesToRead, 0, 0);
	if (ntStatus >= 0)
	{
		*lpNumberOfBytesRead = IoStatusBlock.Information;
		return TRUE;
	}
	return ntStatus==STATUS_SUCCESS;
}

BOOL WriteFile_Stub(
	HANDLE       hFile,
	LPVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
{
	pfnNtWriteFile NtWriteFile = (pfnNtWriteFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteFile");
	if (hFile == NULL || lpBuffer == NULL)
		return FALSE;
	IO_STATUS_BLOCK IoStatusBlock;
	IoStatusBlock.Information = 0;
	IoStatusBlock.Status = 0;
	NTSTATUS ntStatus = -1;
	ntStatus = NtWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, lpBuffer, nNumberOfBytesToWrite, 0, 0);
	if (ntStatus >= 0)
	{
		*lpNumberOfBytesWritten = IoStatusBlock.Information;
		return TRUE;
	}
	return ntStatus == STATUS_SUCCESS;
}


NTSTATUS NtQueryInformationFile_Stub(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
)
{
	pfnNtQueryInformationFile NtQueryInformationFile = (pfnNtQueryInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationFile");
	return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS NtSetInformationFile_Stub(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
)
{
	pfnNtSetInformationFile NtSetInformationFile = (pfnNtSetInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
	return NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS NtOpenFile_Stub(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
)
{
	pfnNtOpenFile NtOpenFile = (pfnNtOpenFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
	return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}


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
)
{
	pfnNtQueryDirectoryFile  NtQueryDirectoryFile = (pfnNtQueryDirectoryFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryDirectoryFile");
	return NtQueryDirectoryFile(FileHandle, 
		Event, 
		ApcRoutine, 
		ApcContext, 
		IoStatusBlock, 
		FileInformation, 
		Length, 
		FileInformationClass, 
		ReturnSingleEntry, 
		FileName, 
		RestartScan);
}


BOOL DeleteFileA_Stub(
	LPCSTR lpFileName
)
{
	WCHAR wcFileName[MAX_PATH] = { 0 };
	swprintf(wcFileName, L"%S", lpFileName);
	return DeleteFileW_Stub(wcFileName);
}

BOOL DeleteFileW_Stub(
	LPCWSTR lpFileName
)
{

	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlDosPathNameToNtPathName_U RtlDosPathNameToNtPathName_U = (pfnRtlDosPathNameToNtPathName_U)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDosPathNameToNtPathName_U");
	pfnNtDeleteFile NtDeleteFile = (pfnNtDeleteFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDeleteFile");

	UNICODE_STRING usFileName;
	RtlInitUnicodeString(&usFileName, (PWSTR)lpFileName);

	if (!RtlDosPathNameToNtPathName_U(lpFileName, &usFileName, NULL, NULL))
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}


	NTSTATUS ntStatus = -1;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
		&usFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	
	ntStatus = NtDeleteFile(&ObjectAttributes);
	return ntStatus == STATUS_SUCCESS;
}

BOOL FlushFileBuffers_Stub(
	HANDLE hFile
)
{
	pfnNtFlushBuffersFile NtFlushBuffersFile = (pfnNtFlushBuffersFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFlushBuffersFile");
	if (NtFlushBuffersFile == NULL)
		return FALSE;

	NTSTATUS ntStatus; 
	IO_STATUS_BLOCK IoStatusBlock; 

	if ((DWORD)hFile == 0xFFFFFFF4)
	{
		hFile = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->StandardError;
	}
	else if ((DWORD)hFile == 0xFFFFFFF5)
	{
		hFile = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->StandardOutput;
	}
	else if ((DWORD)hFile == 0xFFFFFFF6)
	{
		hFile = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->StandardInput;
	}
	ntStatus = NtFlushBuffersFile(hFile, &IoStatusBlock);
	if (ntStatus >= 0)
		return TRUE;
	return FALSE;
}


//RegOptional
//https://cloud.tencent.com/developer/article/1677518
//https://www.cnblogs.com/Quincy/p/4838600.html
//https://blog.csdn.net/breaksoftware/article/details/7653810
NTSTATUS MapDefaultKey(PHANDLE pHandle, HKEY hKey)
{
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlFormatCurrentUserKeyPath RtlFormatCurrentUserKeyPath = (pfnRtlFormatCurrentUserKeyPath)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlFormatCurrentUserKeyPath");
	pfnNtOpenKey NtOpenKey = (pfnNtOpenKey)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtOpenKey");
	pfnRtlFreeUnicodeString RtlFreeUnicodeString = (pfnRtlFreeUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlFreeUnicodeString");

	NTSTATUS ntStatus = -1;
	if (hKey == NULL)
		return ntStatus;

	HANDLE KeyHandle = NULL;
	if ((((ULONG_PTR)(hKey) & 0xF0000000) != 0x80000000))
	{
		KeyHandle = (HANDLE)((ULONG_PTR)hKey & ~0x1);
		ntStatus = STATUS_SUCCESS;
	}

	OBJECT_ATTRIBUTES Attributes;
	switch ((ULONG)hKey)
	{
	case (ULONG)HKEY_CURRENT_USER:
	{
		UNICODE_STRING CurrentUserKeyPath = { 0 };
		if (RtlFormatCurrentUserKeyPath(&CurrentUserKeyPath) == STATUS_SUCCESS)
		{
			InitializeObjectAttributes(&Attributes,
				&CurrentUserKeyPath,
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL);
			ntStatus = NtOpenKey(&KeyHandle, MAXIMUM_ALLOWED, &Attributes);
		}
		break;
	}

	case (ULONG)HKEY_LOCAL_MACHINE:
	{
		UNICODE_STRING LocalMachineKeyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine");
		InitializeObjectAttributes(
			&Attributes,
			&LocalMachineKeyPath,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);
		ntStatus = NtOpenKey(&KeyHandle, MAXIMUM_ALLOWED, &Attributes);
		break;
	}

	case (ULONG)HKEY_CLASSES_ROOT:
	{
		UNICODE_STRING ClassRootKeyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\CLASSES");

		InitializeObjectAttributes(
			&Attributes,
			&ClassRootKeyPath,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		ntStatus = NtOpenKey(&KeyHandle,MAXIMUM_ALLOWED,&Attributes);
		break;
	}

	case (ULONG)HKEY_USERS:
	{
		UNICODE_STRING UsersKeyPath = RTL_CONSTANT_STRING(L"\\Registry\\User");

		InitializeObjectAttributes(&Attributes,
			&UsersKeyPath,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);
		ntStatus = NtOpenKey(&KeyHandle,MAXIMUM_ALLOWED,&Attributes);
		break;
	}
	case (ULONG)HKEY_CURRENT_CONFIG:
	{
		UNICODE_STRING CurrentConfigKeyPath =
			RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current");

		InitializeObjectAttributes(&Attributes,
			&CurrentConfigKeyPath,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);
		ntStatus = NtOpenKey(&KeyHandle,MAXIMUM_ALLOWED,&Attributes);
		break;
	}
	default:
		break;
	}
	if (ntStatus != STATUS_SUCCESS)
		return ntStatus;
	*pHandle = KeyHandle;
	return ntStatus;
}

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
)
{
	WCHAR wcSubKey[MAX_PATH] = { 0 };
	swprintf(wcSubKey, L"%S", lpSubKey);
	WCHAR wcClass[MAX_PATH] = { 0 };
	swprintf(wcClass, L"%S", lpClass);
	return RegCreateKeyExW_Stub(hKey,
		wcSubKey,
		Reserved,
		wcClass,
		dwOptions,
		samDesired,
		lpSecurityAttributes,
		phkResult,
		lpdwDisposition);
}


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
)
{
	//初始化需要的Nt函数
	NTSTATUS ntStatus = -1;
	pfnNtCreateKey NtCreateKey = (pfnNtCreateKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	//处理hKey，已知hKey和Handle是不一样的，之间存在转化关系
	//https://www.cnblogs.com/Quincy/p/4838600.html
	HANDLE KeyHandle = NULL;

	//获取注册表项的句柄
	if(MapDefaultKey(&KeyHandle,hKey)== STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	//R3层的参数转化为Nt函数的参数
	ACCESS_MASK DesiredAccess = samDesired;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING SubKey = { 0 };
	UNICODE_STRING  Class = { 0 };
	if(lpSubKey != NULL)
		RtlInitUnicodeString(&SubKey, (LPWSTR)lpSubKey);
	else
		RtlInitUnicodeString(&SubKey, (LPWSTR)L"");
	if(lpClass != NULL)
		RtlInitUnicodeString(&Class, lpClass);


	InitializeObjectAttributes(&ObjectAttributes,
		&SubKey,
		OBJ_CASE_INSENSITIVE,
		KeyHandle,
		NULL);
	ULONG  TitleIndex = 0;
	ULONG CreateOptions = dwOptions;
	PULONG Disposition = lpdwDisposition;
	ntStatus = NtCreateKey(&KeyHandle,
		DesiredAccess,
		&ObjectAttributes,
		TitleIndex,
		(lpClass == NULL) ? NULL : &Class,
		CreateOptions,
		Disposition);
	if (ntStatus != STATUS_SUCCESS)
		return RtlNtStatusToDosError(ntStatus);;

	*phkResult = (HKEY)KeyHandle;
	return RtlNtStatusToDosError(ntStatus);
}

LSTATUS RegCreateKeyA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
)
{
	WCHAR wcSubKey[MAX_PATH] = { 0 };
	swprintf(wcSubKey, L"%S", lpSubKey);
	return RegCreateKeyW_Stub(hKey, wcSubKey, phkResult);
}
LSTATUS RegCreateKeyW_Stub(
	HKEY   hKey,
	LPCWSTR  lpSubKey,
	PHKEY  phkResult
)
{
	NTSTATUS ntStatus = -1;
	ULONG  TitleIndex = 0;
	ULONG CreateOptions = REG_OPTION_NON_VOLATILE;
	PULONG Disposition = NULL;
	ACCESS_MASK  DesiredAccess = KEY_ALL_ACCESS;

	pfnNtCreateKey NtCreateKey = (pfnNtCreateKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	//处理hKey，已知hKey和Handle是不一样的，之间存在转化关系,获取注册表项的句柄
	//https://www.cnblogs.com/Quincy/p/4838600.html
	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	//初始化 ObjectAttributes
	UNICODE_STRING SubKey = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	if (lpSubKey != NULL)
		RtlInitUnicodeString(&SubKey, (LPWSTR)lpSubKey);
	else
		RtlInitUnicodeString(&SubKey, (LPWSTR)L"");

	InitializeObjectAttributes(&ObjectAttributes,
		&SubKey,
		OBJ_CASE_INSENSITIVE,
		KeyHandle,
		NULL);
	ntStatus = NtCreateKey(&KeyHandle,
		DesiredAccess,
		&ObjectAttributes,
		0,
		NULL,
		CreateOptions,
		Disposition);

	if (ntStatus != STATUS_SUCCESS)
		return RtlNtStatusToDosError(ntStatus);

	*phkResult = (HKEY)KeyHandle;
	return RtlNtStatusToDosError(ntStatus);
}

LSTATUS RegSetValueA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  dwType,
	LPCSTR lpData,
	DWORD  cbData
)
{
	WCHAR wcSubKey[16383] = { 0 };
	swprintf(wcSubKey, L"%S", lpSubKey);
	PWCHAR wcData = (PWCHAR)malloc(1024 * 1024);
	swprintf(wcData, L"%S", lpData);
	return RegSetValueW_Stub(hKey, wcSubKey, dwType, wcData, cbData);
}

LSTATUS RegSetValueW_Stub(
	HKEY   hKey,
	LPCWSTR lpSubKey,
	DWORD  dwType,
	LPCWSTR lpData,
	DWORD  cbData
)
{
	pfnNtSetValueKey NtSetValueKey = (pfnNtSetValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetValueKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	NTSTATUS ntStatus = -1;
	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;


	UNICODE_STRING ValueName = { 0 };
	RtlInitUnicodeString(&ValueName, lpSubKey);
	ULONG TitleIndex = 0;
	ULONG Type = dwType;
	PVOID Data = (PVOID)lpData;
	if ((dwType == REG_SZ) || (dwType == REG_EXPAND_SZ) || (dwType == REG_MULTI_SZ) && (cbData != 0))
	{
		PWSTR pwsData = (PWSTR)lpData;
		if ((pwsData[cbData / sizeof(WCHAR) - 1] != L'\0') &&
			(pwsData[cbData / sizeof(WCHAR)] == L'\0'))
		{
			cbData = (cbData + sizeof(WCHAR)) * 2;
		}
		else
		{
			cbData = (cbData + sizeof(WCHAR)) * 2;
		}
		cbData = (cbData + sizeof(WCHAR)) * 2;
	}
	ULONG DataSize = cbData;
	ntStatus = NtSetValueKey(KeyHandle, &ValueName, TitleIndex, Type, Data, DataSize);
	return RtlNtStatusToDosError(ntStatus);
}

LSTATUS RegSetValueExA_Stub(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
)
{
	WCHAR wcValueName[16383] = { 0 };
	swprintf(wcValueName, L"%S", lpValueName);
	pfnRtlMultiByteToUnicodeN RtlMultiByteToUnicodeN = (pfnRtlMultiByteToUnicodeN)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlMultiByteToUnicodeN");

	PWCH v10 = (PWCH)malloc(2 * cbData);
	RtlMultiByteToUnicodeN(v10, 2 * cbData, NULL, (char*)lpData, cbData);
	return RegSetValueExW_Stub(hKey, (LPCWSTR)wcValueName, Reserved, dwType, (BYTE*)v10, cbData*2);
}

LSTATUS RegSetValueExW_Stub(
	HKEY       hKey,
	LPCWSTR    lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
)
{
	pfnNtSetValueKey NtSetValueKey = (pfnNtSetValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetValueKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	NTSTATUS ntStatus = -1;
	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;


	UNICODE_STRING ValueName = { 0 };
	RtlInitUnicodeString(&ValueName, lpValueName);
	ULONG TitleIndex = 0;
	ULONG Type = dwType;
	
	if ((dwType == REG_SZ) || (dwType == REG_EXPAND_SZ) || (dwType == REG_MULTI_SZ) && (cbData != 0))
	{
		PWSTR pwsData = (PWSTR)lpData;

		if ((pwsData[cbData / sizeof(WCHAR) - 1] != L'\0') &&
			(pwsData[cbData / sizeof(WCHAR)] == L'\0'))
		{
			cbData = (cbData + sizeof(WCHAR))*2;
		}
		else
		{
			cbData = (cbData + sizeof(WCHAR)) * 2;
		}
	}
	//PVOID Data = (PVOID)lpData;
	ULONG DataSize = cbData;
	ntStatus = NtSetValueKey(KeyHandle, &ValueName, TitleIndex, Type, (PVOID)lpData, DataSize);
	return RtlNtStatusToDosError(ntStatus);
}


LSTATUS RegDeleteValueA_Stub(
	HKEY   hKey,
	LPCSTR lpValueName
)
{
	WCHAR wcValueName[MAX_PATH] = { 0 };
	swprintf(wcValueName, L"%S", lpValueName);
	return  RegDeleteValueW_Stub(hKey, wcValueName);
}

LSTATUS RegDeleteValueW_Stub(
	HKEY    hKey,
	LPCWSTR lpValueName
)
{
	if(lpValueName == NULL)
		STATUS_INVALID_PARAMETER;

	pfnNtDeleteValueKey NtDeleteValueKey = (pfnNtDeleteValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDeleteValueKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	NTSTATUS ntStatus = -1;
	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING ValueName = { 0 };
	RtlInitUnicodeString(&ValueName, lpValueName);

	ntStatus = NtDeleteValueKey(KeyHandle, &ValueName);
	return RtlNtStatusToDosError(ntStatus);
}


LSTATUS RegQueryValueA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	LPSTR  lpData,
	PLONG  lpcbData
)
{
	WCHAR wclpSubKey[MAX_PATH] = { 0 };
	swprintf(wclpSubKey, L"%S", lpSubKey);

	//pfnRtlMultiByteToUnicodeN RtlMultiByteToUnicodeN = (pfnRtlMultiByteToUnicodeN)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlMultiByteToUnicodeN");
	//LONG lpcbData_ = 2 * (*lpcbData);
	//LPWSTR v10 = (PWCH)malloc(lpcbData_);
	//RtlMultiByteToUnicodeN(v10, lpcbData_, NULL, (char*)lpData, *lpcbData);

	pfnNtQueryValueKey NtQueryValueKey = (pfnNtQueryValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryValueKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	NTSTATUS ntStatus = -1;
	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING  ValueName = { 0 };
	RtlInitUnicodeString(&ValueName, wclpSubKey);


	//KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
	//KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
	//KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass = (KEY_VALUE_INFORMATION_CLASS)(*lpcbData != 0 ? KeyValuePartialInformation : KeyValueBasicInformation);

	DWORD dwLength = 0;
	if (lpcbData)
	{
		dwLength = *lpcbData + 12;
		if (dwLength >= 0x90 || dwLength < 0xC)
			dwLength = 0x90;
	}
	else
	{
		dwLength = 0x10;
	}

	PCHAR KeyValueInformation = (PCHAR)malloc(dwLength);
	ULONG uResultlength = 0;
	ntStatus = NtQueryValueKey(KeyHandle, &ValueName, KeyValueInformationClass, (PVOID)KeyValueInformation, dwLength, &uResultlength);

	if (ntStatus == STATUS_BUFFER_OVERFLOW && lpData == NULL)
	{
		*lpcbData = uResultlength;
		ntStatus = STATUS_SUCCESS;
	}

	DWORD dwBufferLength = uResultlength;
	PCHAR Buffer = (PCHAR)malloc(dwBufferLength);
	if (ntStatus == STATUS_BUFFER_OVERFLOW)
	{
		if (KeyValueInformationClass == KeyValuePartialInformation && *lpcbData >= ((PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation)->DataLength)
		{
			ntStatus = NtQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, (PVOID)Buffer, dwBufferLength, &uResultlength);
		}
	}

	if (ntStatus == STATUS_SUCCESS && lpData != NULL)
	{
		if (*lpcbData >= ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength)
		{
			memcpy(lpData, ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->Data, ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength);
			*lpcbData = ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength;
		}
		else
		{
			ntStatus = STATUS_BUFFER_OVERFLOW;
		}
	}
	return RtlNtStatusToDosError(ntStatus);

}

LSTATUS RegQueryValueW_Stub(
	HKEY    hKey,
	LPCWSTR lpSubKey,
	LPWSTR  lpData,
	PLONG   lpcbData
)
{
	pfnNtQueryValueKey NtQueryValueKey = (pfnNtQueryValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryValueKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	NTSTATUS ntStatus = -1;
	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING  ValueName = { 0 };
	RtlInitUnicodeString(&ValueName, lpSubKey);


	//KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
	//KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
	//KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass = (KEY_VALUE_INFORMATION_CLASS)(*lpcbData != 0 ? KeyValuePartialInformation : KeyValueBasicInformation);

	DWORD dwLength = 0;
	if (lpcbData)
	{
		dwLength = *lpcbData + 12;
		if (dwLength >= 0x90 || dwLength < 0xC)
			dwLength = 0x90;
	}
	else
	{
		dwLength = 0x10;
	}

	PCHAR KeyValueInformation = (PCHAR)malloc(dwLength);
	ULONG uResultlength = 0;
	ntStatus = NtQueryValueKey(KeyHandle, &ValueName, KeyValueInformationClass, (PVOID)KeyValueInformation, dwLength, &uResultlength);

	if (ntStatus == STATUS_BUFFER_OVERFLOW && lpData == NULL)
	{
		*lpcbData = uResultlength;
		ntStatus = STATUS_SUCCESS;
	}

	DWORD dwBufferLength = uResultlength;
	PCHAR Buffer = (PCHAR)malloc(dwBufferLength);
	if (ntStatus == STATUS_BUFFER_OVERFLOW)
	{
		if (KeyValueInformationClass == KeyValuePartialInformation && *lpcbData >= ((PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation)->DataLength)
		{
			ntStatus = NtQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, (PVOID)Buffer, dwBufferLength, &uResultlength);
		}
	}

	if (ntStatus == STATUS_SUCCESS && lpData != NULL)
	{
		if (*lpcbData >= ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength)
		{
			memcpy(lpData, ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->Data, ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength);
			*lpcbData = ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength;
		}
		else
		{
			ntStatus = STATUS_BUFFER_OVERFLOW;
		}
	}
	return RtlNtStatusToDosError(ntStatus);
}

LSTATUS RegQueryValueExA_Stub(
	HKEY    hKey,
	LPCSTR  lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
)
{
	WCHAR wcValueName[MAX_PATH] = { 0 };
	swprintf(wcValueName, L"%S", lpValueName);
	return RegQueryValueExW_Stub(hKey,wcValueName,lpReserved,lpType,lpData,lpcbData);
}

LSTATUS RegQueryValueExW_Stub(
	HKEY    hKey,
	LPCWSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
)
{
	pfnNtQueryValueKey NtQueryValueKey = (pfnNtQueryValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryValueKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	NTSTATUS ntStatus = -1;
	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING  ValueName = { 0 };
	RtlInitUnicodeString(&ValueName, lpValueName);


	//KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
	//KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
	//KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass = (KEY_VALUE_INFORMATION_CLASS)(*lpcbData != 0 ? KeyValuePartialInformation: KeyValueBasicInformation);

	DWORD dwLength = 0;
	if (lpcbData)
	{
		dwLength = *lpcbData + 12;
		if (dwLength >= 0x90 || dwLength < 0xC)
			dwLength = 0x90;
	}
	else
	{
		dwLength = 0x10;
	}

	PCHAR KeyValueInformation = (PCHAR)malloc(dwLength) ;
	ULONG uResultlength = 0;
	ntStatus = NtQueryValueKey(KeyHandle, &ValueName, KeyValueInformationClass, (PVOID)KeyValueInformation, dwLength, &uResultlength);

	if (ntStatus == STATUS_BUFFER_OVERFLOW && lpData == NULL)
	{
		*lpcbData = uResultlength;
		ntStatus = STATUS_SUCCESS;
	}

	DWORD dwBufferLength = uResultlength;
	PCHAR Buffer = (PCHAR)malloc(dwBufferLength);
	if (ntStatus == STATUS_BUFFER_OVERFLOW)
	{
		if (KeyValueInformationClass == KeyValuePartialInformation && *lpcbData >= ((PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation)->DataLength)
		{
			ntStatus = NtQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, (PVOID)Buffer, dwBufferLength, &uResultlength);
		}
	}

	if (ntStatus == STATUS_SUCCESS && lpData != NULL)
	{
		if (*lpcbData >= ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength)
		{
			memcpy(lpData, ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->Data, ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength);
		}
		else
		{
			ntStatus = STATUS_BUFFER_OVERFLOW;
		}
	}

	if (((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->Data != NULL)
	{
		if (((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->Type != NULL && lpType != NULL)
		{
			*lpType = ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->Type;
		}
		if (((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength && lpcbData != NULL)
		{
			*lpcbData = ((PKEY_VALUE_PARTIAL_INFORMATION)Buffer)->DataLength;
		}
		else
		{
			*lpcbData = 0;
		}
	}

	return RtlNtStatusToDosError(ntStatus);
}

LSTATUS RegOpenKeyExA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
)
{
	WCHAR wclpSubKey[MAX_PATH] = { 0 };
	swprintf(wclpSubKey, L"%S", lpSubKey);
	return RegOpenKeyExW_Stub(hKey, wclpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS RegOpenKeyExW_Stub(
	HKEY    hKey,
	LPCWSTR lpSubKey,
	DWORD   ulOptions,
	REGSAM  samDesired,
	PHKEY   phkResult
)
{
	NTSTATUS ntStatus = -1;
	pfnNtOpenKey NtOpenKey = (pfnNtOpenKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING SubKey = { 0 };
	if (lpSubKey != NULL)
		RtlInitUnicodeString(&SubKey, lpSubKey);
	else
		RtlInitUnicodeString(&SubKey, (LPWSTR)L"");

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
		&ObjectAttributes,
		&SubKey,
		OBJ_CASE_INSENSITIVE,
		KeyHandle,
		NULL
	);

	ntStatus = NtOpenKey((PHANDLE)phkResult, samDesired, &ObjectAttributes);
	return RtlNtStatusToDosError(ntStatus);
}

LSTATUS RegOpenKeyA_Stub(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
)
{
	WCHAR wclpSubKey[MAX_PATH] = { 0 };
	swprintf(wclpSubKey, L"%S", lpSubKey);
	DWORD ulOptions = 0;
	REGSAM samDesired = KEY_ALL_ACCESS;
	return RegOpenKeyExW_Stub(hKey, wclpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS RegOpenKeyW_Stub(
	HKEY   hKey,
	LPCWSTR lpSubKey,
	PHKEY  phkResult
)
{
	DWORD ulOptions = 0;
	REGSAM samDesired = KEY_ALL_ACCESS;
	return RegOpenKeyExW_Stub(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS RegCloseKey_Stub(
	HKEY hKey
)
{
	NTSTATUS ntStatus =-1;
	pfnNtClose NtClose = (pfnNtClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");
	if (hKey == NULL)
	{
		return ERROR_INVALID_HANDLE;
	}
	ntStatus = NtClose(hKey);
	return RtlNtStatusToDosError(ntStatus);
}


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
)
{
	NTSTATUS ntStatus;
	pfnNtQueryKey NtQueryKey = (pfnNtQueryKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	if (!lpReserved && (!lpClass || lpcchClass))
	{
		HANDLE KeyHandle = NULL;
		if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
			return RtlNtStatusToDosError(STATUS_INVALID_PARAMETER);

		KEY_INFORMATION_CLASS KeyInformationClass = KeyFullInformation;
		ULONG  uLength = sizeof(KEY_FULL_INFORMATION);
		PVOID  KeyInfor = malloc(uLength);
		ULONG ResultLength = 0;

		ntStatus = NtQueryKey(KeyHandle, KeyInformationClass, KeyInfor, uLength, &ResultLength);


		if (ntStatus == STATUS_BUFFER_OVERFLOW)
		{
			KeyInfor = malloc(ResultLength);
			if (KeyInfor == NULL)
			{
				return RtlNtStatusToDosError(STATUS_NO_MEMORY);
			}
			else
			{
				ntStatus = NtQueryKey(KeyHandle, KeyInformationClass, KeyInfor, ResultLength, &ResultLength);
			}
		}

		if (ntStatus != STATUS_SUCCESS)
			return RtlNtStatusToDosError(ntStatus);

		if (lpcSubKeys != NULL)
		{
			*lpcSubKeys = ((PKEY_FULL_INFORMATION)KeyInfor)->SubKeys;
		}
		if (lpcbMaxSubKeyLen != NULL)
		{
			*lpcbMaxSubKeyLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxNameLen / sizeof(WCHAR) + 1;
		}
		if (lpcbMaxClassLen != NULL)
		{
			*lpcbMaxClassLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxClassLen / sizeof(WCHAR) + 1;
		}
		if (lpcValues != NULL)
		{
			*lpcValues = ((PKEY_FULL_INFORMATION)KeyInfor)->Values;
		}

		if (lpcbMaxValueNameLen != NULL)
		{
			*lpcbMaxValueNameLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxValueNameLen / sizeof(WCHAR) + 1;
		}

		if (lpcbMaxValueLen != NULL)
		{
			*lpcbMaxValueLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxValueDataLen;
		}

		if (lpftLastWriteTime != NULL)
		{
			lpftLastWriteTime->dwLowDateTime = ((PKEY_FULL_INFORMATION)KeyInfor)->LastWriteTime.u.LowPart;
			lpftLastWriteTime->dwHighDateTime = ((PKEY_FULL_INFORMATION)KeyInfor)->LastWriteTime.u.HighPart;
		}
		if (lpClass != NULL)
		{
			if (((PKEY_FULL_INFORMATION)KeyInfor)->ClassLength > *lpcchClass)
			{
				return RtlNtStatusToDosError(ERROR_BUFFER_OVERFLOW);
			}
			memcpy(lpClass, ((PKEY_FULL_INFORMATION)KeyInfor)->Class, ((PKEY_FULL_INFORMATION)KeyInfor)->ClassLength);
			*lpcchClass = ((PKEY_FULL_INFORMATION)KeyInfor)->ClassLength / sizeof(WCHAR);
		}

	}
	return RtlNtStatusToDosError(STATUS_SUCCESS);
}

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
)
{
	NTSTATUS ntStatus;
	pfnNtQueryKey NtQueryKey = (pfnNtQueryKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	if (!lpReserved && (!lpClass || lpcchClass))
	{
		HANDLE KeyHandle = NULL;
		if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
			return RtlNtStatusToDosError(STATUS_INVALID_PARAMETER);


		KEY_INFORMATION_CLASS KeyInformationClass = KeyFullInformation;
		ULONG  uLength = sizeof(KEY_FULL_INFORMATION);
		PVOID  KeyInfor = malloc(uLength);
		ULONG ResultLength = 0;

		ntStatus = NtQueryKey(KeyHandle, KeyInformationClass, KeyInfor, uLength, &ResultLength);


		if (ntStatus == STATUS_BUFFER_OVERFLOW)
		{
			KeyInfor = malloc(ResultLength);
			if (KeyInfor == NULL)
			{
				return RtlNtStatusToDosError(STATUS_NO_MEMORY);
			}
			else
			{
				ntStatus = NtQueryKey(KeyHandle, KeyInformationClass, KeyInfor, ResultLength, &ResultLength);
			}
		}

		if (ntStatus != STATUS_SUCCESS)
			return RtlNtStatusToDosError(ntStatus);

		if (lpcSubKeys != NULL)
		{
			*lpcSubKeys = ((PKEY_FULL_INFORMATION)KeyInfor)->SubKeys;
		}
		if (lpcbMaxSubKeyLen != NULL)
		{
			*lpcbMaxSubKeyLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxNameLen / sizeof(CHAR) + 1;
		}
		if (lpcbMaxClassLen != NULL)
		{
			*lpcbMaxClassLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxClassLen / sizeof(CHAR) + 1;
		}
		if (lpcValues != NULL)
		{
			*lpcValues = ((PKEY_FULL_INFORMATION)KeyInfor)->Values;
		}

		if (lpcbMaxValueNameLen != NULL)
		{
			*lpcbMaxValueNameLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxValueNameLen / sizeof(CHAR) + 1;
		}

		if (lpcbMaxValueLen != NULL)
		{
			*lpcbMaxValueLen = ((PKEY_FULL_INFORMATION)KeyInfor)->MaxValueDataLen;
		}

		if (lpftLastWriteTime != NULL)
		{
			lpftLastWriteTime->dwLowDateTime = ((PKEY_FULL_INFORMATION)KeyInfor)->LastWriteTime.u.LowPart;
			lpftLastWriteTime->dwHighDateTime = ((PKEY_FULL_INFORMATION)KeyInfor)->LastWriteTime.u.HighPart;
		}
		if (lpClass != NULL)
		{
			if (((PKEY_FULL_INFORMATION)KeyInfor)->ClassLength > *lpcchClass)
			{
				return RtlNtStatusToDosError(ERROR_BUFFER_OVERFLOW);
			}
			memcpy(lpClass, ((PKEY_FULL_INFORMATION)KeyInfor)->Class, ((PKEY_FULL_INFORMATION)KeyInfor)->ClassLength);
			*lpcchClass = ((PKEY_FULL_INFORMATION)KeyInfor)->ClassLength / sizeof(CHAR);
		}

	}
	return RtlNtStatusToDosError(STATUS_SUCCESS);
}


LSTATUS RegEnumKeyExW_Stub(
	HKEY      hKey,
	DWORD     dwIndex,
	LPWSTR     lpName,
	LPDWORD   lpcchName,
	LPDWORD   lpReserved,
	LPWSTR     lpClass,
	LPDWORD   lpcchClass,
	PFILETIME lpftLastWriteTime
)
{
	pfnNtEnumerateKey EnumerateKey = (pfnNtEnumerateKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtEnumerateKey");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	if (lpName == NULL && (lpClass == NULL || lpcchClass == NULL))
		return RtlNtStatusToDosError(STATUS_INVALID_PARAMETER);

	NTSTATUS ntStatus;

	HANDLE KeyHandle = NULL;
	if (MapDefaultKey(&KeyHandle, hKey) == STATUS_SUCCESS && KeyHandle == NULL)
		return RtlNtStatusToDosError(STATUS_INVALID_PARAMETER);


	ULONG  Index = dwIndex;
	KEY_INFORMATION_CLASS KeyInformationClass = (lpClass != NULL ? KeyNodeInformation: KeyBasicInformation);
	PKEY_BASIC_INFORMATION BasicInformation = NULL;
	PKEY_NODE_INFORMATION  NodeInformation = NULL;
	ULONG Length = 0;
	ULONG  ResultLength = 0;
	if (KeyInformationClass == KeyBasicInformation)
	{
		Length = sizeof(KEY_BASIC_INFORMATION);
		BasicInformation = (PKEY_BASIC_INFORMATION)malloc(Length);
		ntStatus = EnumerateKey(KeyHandle, Index, KeyInformationClass, BasicInformation, Length, &ResultLength);
	}
	else if (KeyInformationClass == KeyNodeInformation)
	{
		Length = sizeof(KEY_NODE_INFORMATION);
		NodeInformation = (PKEY_NODE_INFORMATION)malloc(Length);
		ntStatus = EnumerateKey(KeyHandle, Index, KeyInformationClass, NodeInformation, Length, &ResultLength);
	}
	if (ntStatus == STATUS_BUFFER_OVERFLOW)
	{
		Length = ResultLength;
		if (BasicInformation != NULL)
		{
			free(BasicInformation);
			BasicInformation = (PKEY_BASIC_INFORMATION)malloc(Length);
			ntStatus = EnumerateKey(KeyHandle, Index, KeyInformationClass, BasicInformation, Length, &ResultLength);
		}
		else if (NodeInformation != NULL)
		{
			free(NodeInformation);
			NodeInformation = (PKEY_NODE_INFORMATION)malloc(Length);
			ntStatus = EnumerateKey(KeyHandle, Index, KeyInformationClass, NodeInformation, Length, &ResultLength);
		}
	}
	
	if (ntStatus == STATUS_SUCCESS)
	{
		if (KeyInformationClass == KeyBasicInformation && BasicInformation !=NULL)
		{
			if (*lpcchName > BasicInformation->NameLength && lpName != NULL)
			{
				memcpy(lpName, BasicInformation->Name, BasicInformation->NameLength);
				*lpcchName = BasicInformation->NameLength;
			}
		}
		else if (KeyInformationClass == KeyNodeInformation && NodeInformation != NULL)
		{
			if (*lpcchName > NodeInformation->NameLength && lpName != NULL)
			{
				memcpy(lpName, NodeInformation->Name, NodeInformation->NameLength);
				*lpcchName = (DWORD)NodeInformation->NameLength;
			}

			if (*lpcchClass > NodeInformation->ClassLength && lpClass != NULL)
			{
				memcpy(lpClass, (PBYTE)(NodeInformation + NodeInformation->ClassOffset), NodeInformation->ClassLength);
				*lpcchClass = NodeInformation->ClassLength;
			}

			if (lpftLastWriteTime != NULL)
			{
				*lpftLastWriteTime = *(PFILETIME)&NodeInformation->LastWriteTime;
			}

		}

	}
	//ntStatus = EnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, &ResultLength);
	//PVOID KeyInformation1 = NULL;
	//if (ntStatus == STATUS_BUFFER_OVERFLOW)
	//{
	//	KeyInformation1 = malloc(ResultLength);
	//	ntStatus = EnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, ResultLength, &ResultLength);
	//}

	//if (ntStatus == STATUS_SUCCESS)
	//{
	//	if (*lpcchName > KeyInformation->MaxNameLen && lpName != NULL)
	//	{
	//		memcpy(lpName,KeyInformation->)
	//	}
	//}
	return RtlNtStatusToDosError(ntStatus);
}

LSTATUS RegEnumKeyExA_Stub(
	HKEY      hKey,
	DWORD     dwIndex,
	LPSTR     lpName,
	LPDWORD   lpcchName,
	LPDWORD   lpReserved,
	LPSTR     lpClass,
	LPDWORD   lpcchClass,
	PFILETIME lpftLastWriteTime
)
{
	*lpcchName = *lpcchName * 2;
	PWCHAR wcName = (PWCHAR)malloc(*lpcchName);
	swprintf(wcName, L"%S", lpName);

	*lpcchClass = *lpcchClass * 2;
	PWCHAR wcClass = (PWCHAR)malloc(*lpcchClass);
	swprintf(wcClass, L"%S", lpClass);
	LSTATUS lStatus = RegEnumKeyExW_Stub(hKey, dwIndex, wcName, lpcchName, lpReserved, wcClass, lpcchClass, lpftLastWriteTime);
	if (lStatus == ERROR_SUCCESS)
	{
		wcstombs(lpName, wcName, *lpcchName);
		wcstombs(lpClass, wcClass, *lpcchClass);
	}
	return lStatus;
}

LSTATUS RegEnumKeyW_Stub(
	HKEY   hKey,
	DWORD  dwIndex,
	LPWSTR lpName,
	DWORD  cchName
)
{
	DWORD  dwReserved = 0;
	LPWSTR lpClass = NULL;
	DWORD dwClass = 0;
	PFILETIME ftLastWriteTime = NULL;
	DWORD dwTempcchName = cchName;   //cchName这个参数不返回
	LSTATUS lStatus = RegEnumKeyExW_Stub(hKey, dwIndex, lpName, &cchName, &dwReserved, lpClass, &dwClass, ftLastWriteTime);
	cchName = dwTempcchName;
	return lStatus;
}

LSTATUS RegEnumKeyA_Stub(
	HKEY  hKey,
	DWORD dwIndex,
	LPSTR lpName,
	DWORD cchName
)
{
	DWORD dwTempcchName = cchName;
	cchName = cchName * 2;
	PWCHAR wcName = (PWCHAR)malloc(cchName);
	DWORD  dwReserved = 0;
	LPWSTR lpClass = NULL;
	DWORD dwClass = 0;
	PFILETIME ftLastWriteTime = NULL;
	LSTATUS lStatus = RegEnumKeyExW_Stub(hKey, dwIndex, wcName, &cchName, &dwReserved, lpClass, &dwClass, ftLastWriteTime);
	if (lStatus == ERROR_SUCCESS)
	{
		wcstombs(lpName, wcName, cchName);
	}
	cchName = dwTempcchName;
	return lStatus;
}

DWORD WaitForSingleObjectEx_Stub(
	HANDLE hHandle,
	DWORD  dwMilliseconds,
	BOOL   bAlertable
)
{
	pfnNtWaitForSingleObject NtWaitForSingleObject = (pfnNtWaitForSingleObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "WaitForSingleObjectEx");
	NTSTATUS ntStatus = -1;
	LARGE_INTEGER timeout;
	timeout.QuadPart = -10000 * dwMilliseconds;
	ntStatus = NtWaitForSingleObject(hHandle, bAlertable, &timeout);
	return ntStatus;
}


//Process Optional

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
)
{

	if (lpApplicationName == NULL && lpCommandLine == NULL)
	{
		return FALSE;
	}

	WCHAR lpCommandLine_[MAX_PATH] = { 0 };
	if (lpApplicationName == NULL)
	{
		lpApplicationName = L"C:\\windows\\system32\\cmd.exe";
		swprintf(lpCommandLine_, L"%s %s", L"/c", lpCommandLine);    
	}
	else
	{
		wcscpy(lpCommandLine_, lpCommandLine);
	}
	WCHAR lpApplicationName_[MAX_PATH] = { 0 };
	swprintf(lpApplicationName_, L"%s%s", L"\\??\\", lpApplicationName);
	
	pfnBaseFormatObjectAttributes BaseFormatObjectAttributes = (pfnBaseFormatObjectAttributes)GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
		"BaseFormatObjectAttributes");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), 
		"RtlInitUnicodeString");
	pfnRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (pfnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlCreateProcessParametersEx");
	pfnRtlAllocateHeap RtlAllocateHeap = (pfnRtlAllocateHeap)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlAllocateHeap");
	pfnRtlFreeHeap RtlFreeHeap = (pfnRtlFreeHeap)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlFreeHeap");
	pfnRtlDestroyProcessParameters RtlDestroyProcessParameters = (pfnRtlDestroyProcessParameters)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlDestroyProcessParameters");

	pfnNtCreateUserProcess NtCreateUserProcess = (pfnNtCreateUserProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtCreateUserProcess");


	POBJECT_ATTRIBUTES ProcessObjectAttributes = NULL;
	POBJECT_ATTRIBUTES ThreadObjectAttributes = NULL;
	if (lpProcessAttributes != NULL)
	{
		BaseFormatObjectAttributes(ProcessObjectAttributes, lpProcessAttributes, NULL);
	}
	if (lpThreadAttributes != NULL)
	{
		BaseFormatObjectAttributes(ThreadObjectAttributes, lpThreadAttributes, NULL);
	}

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,v8,v9 = NULL;

	UNICODE_STRING NtImagePath = {0};
	RtlInitUnicodeString(&NtImagePath, (PWSTR)lpApplicationName_);

	UNICODE_STRING CommandLine = {0};
	RtlInitUnicodeString(&CommandLine, (PWSTR)lpCommandLine_);

	PUNICODE_STRING CurrentDirectory = NULL;
	if (lpCurrentDirectory)
	{
		CurrentDirectory = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
		CurrentDirectory->Length = wcslen(lpCurrentDirectory) * sizeof(WCHAR);
		CurrentDirectory->MaximumLength = (wcslen(lpCurrentDirectory)+1) * sizeof(WCHAR);
		RtlInitUnicodeString(CurrentDirectory, (PWSTR)lpCurrentDirectory);
	}
		

	PUNICODE_STRING WindowsTitle = NULL;
	if (lpStartupInfo->lpTitle)
	{
		WindowsTitle = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
		WindowsTitle->Length = wcslen(lpStartupInfo->lpTitle) * sizeof(WCHAR);
		WindowsTitle->MaximumLength = (wcslen(lpStartupInfo->lpTitle)+1) * sizeof(WCHAR);
		RtlInitUnicodeString(WindowsTitle, lpStartupInfo->lpTitle);
	}
	else
	{
		WindowsTitle = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
		WindowsTitle->Length = wcslen(lpApplicationName) * sizeof(WCHAR);
		WindowsTitle->MaximumLength = (wcslen(lpApplicationName) + 1) * sizeof(WCHAR);
		RtlInitUnicodeString(WindowsTitle, (PWSTR)lpApplicationName);
	}
	PUNICODE_STRING DesktopInfo = NULL;
	if (lpStartupInfo->lpDesktop)
	{
		DesktopInfo = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
		DesktopInfo->Length = wcslen(lpStartupInfo->lpDesktop) * sizeof(WCHAR);
		DesktopInfo->MaximumLength = (wcslen(lpStartupInfo->lpDesktop) + 1) * sizeof(WCHAR);
		RtlInitUnicodeString(DesktopInfo, lpStartupInfo->lpDesktop);
	}

	PUNICODE_STRING ShellInfo = NULL;
	if (lpStartupInfo->lpReserved)
	{
		ShellInfo = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
		ShellInfo->Length = wcslen(lpStartupInfo->lpReserved) * sizeof(WCHAR);
		ShellInfo->MaximumLength = (wcslen(lpStartupInfo->lpReserved) + 1) * sizeof(WCHAR);
		RtlInitUnicodeString(ShellInfo, lpStartupInfo->lpReserved);
	}
	//NTSTATUS ntStatus = RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, CurrentDirectory, &CommandLine, lpEnvironment, WindowsTitle, DesktopInfo, ShellInfo, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	NTSTATUS ntStatus = RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, &CommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	PPEB v10 = NtCurrentTeb()->ProcessEnvironmentBlock;

	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// Initialize the PS_ATTRIBUTE_LIST structure
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	// Create the process
	HANDLE hProcess, hThread = NULL;
	//NTSTATUS ntStaus = NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);
	ntStatus = NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, ProcessObjectAttributes, ThreadObjectAttributes, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);
	// Clean up
	RtlFreeHeap(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap, 0, AttributeList);
	RtlDestroyProcessParameters(ProcessParameters);
	return ntStatus == STATUS_SUCCESS;

}

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
)
{
	PWCHAR lpwApplicationName = NULL;
	PWCHAR lpwCommandLine = NULL;
	PWCHAR lpwCurrentDirectory = NULL;
	if (lpApplicationName != NULL)
	{
		lpwApplicationName =(PWCHAR)malloc(MAX_PATH * sizeof(WCHAR));
		swprintf(lpwApplicationName, L"%S", lpApplicationName);
	}

	if (lpCommandLine != NULL)
	{
		lpwCommandLine  = (PWCHAR)malloc(MAX_PATH * sizeof(WCHAR));
		swprintf(lpwCommandLine, L"%S", lpCommandLine);
	}
		
	if (lpCurrentDirectory != NULL)
	{
		lpwCurrentDirectory  = (PWCHAR)malloc(MAX_PATH * sizeof(WCHAR));
		swprintf(lpwCurrentDirectory, L"%S", lpCurrentDirectory);
	}
		

	return CreateProcessW_Stub(lpwApplicationName,
		lpwCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpwCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);
}

UINT WinExec_Stub(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
)
{
	DWORD uCmdShowa = 0;
	if ((uCmdShow & 0x80000000) == 0)
	{
		uCmdShowa = 0;
	}
	else
	{
		uCmdShowa = 0x80000;
	}
	STARTUPINFOW  StartupInformation;
	memset(&StartupInformation, 0, sizeof(StartupInformation));
	StartupInformation.dwFlags = 1;
	StartupInformation.wShowWindow = uCmdShow;
	StartupInformation.cb = 4 * (uCmdShowa != 0) + 68;
	PROCESS_INFORMATION ProcessInformation;
	memset(&ProcessInformation, 0, sizeof(ProcessInformation));
	BOOL bResult = CreateProcessA_Stub(0, (LPSTR)lpCmdLine, 0, 0, 0, uCmdShowa, 0, 0, &StartupInformation, &ProcessInformation);
	if (bResult == TRUE)
		return 33;
	return 0;  //error

}

HANDLE OpenProcess_Stub(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
)
{
	pfnNtOpenProcess NtOpenProcess = (pfnNtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
	pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

	CLIENT_ID ClientId;
	NTSTATUS ntStatus = -1;

	ClientId.UniqueThread = 0;
	ClientId.UniqueProcess = (HANDLE)(dwProcessId);

	HANDLE ProcessHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;


	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = 0;
	ObjectAttributes.ObjectName = 0;
	ObjectAttributes.Attributes = bInheritHandle ? 2 : 0;
	ObjectAttributes.SecurityDescriptor = 0;
	ObjectAttributes.SecurityQualityOfService = 0;

	ntStatus = NtOpenProcess(&ProcessHandle, dwDesiredAccess, &ObjectAttributes, &ClientId);
	if (ntStatus == STATUS_SUCCESS)
	{
		return ProcessHandle;
	}
	return 0;
}

BOOL TerminateProcess_Stub(
	HANDLE hProcess,
	UINT   uExitCode
)
{
	NTSTATUS ntStatus;
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetLastWin32Error");
	pfnNtTerminateProcess NtTerminateProcess = (pfnNtTerminateProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTerminateProcess");
	if (hProcess)
	{
		ntStatus = NtTerminateProcess(hProcess, uExitCode);
		if (ntStatus >= 0)
			return TRUE;
	}
	else
	{
		RtlSetLastWin32Error(6u);
	}
	return FALSE;
}


BOOL ReadProcessMemory_Stub(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesRead
)
{
	pfnNtReadVirtualMemory NtReadVirtualMemory = (pfnNtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	NTSTATUS ntStatus;
	ULONG NumberOfBytesRead = 0;
	ntStatus = NtReadVirtualMemory(hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, &NumberOfBytesRead);
	if (lpNumberOfBytesRead)
		*lpNumberOfBytesRead = NumberOfBytesRead;
	if (ntStatus >= 0)
		return TRUE;
	return FALSE;
}

BOOL WriteProcessMemory_Stub(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
)
{
	ULONG NumberOfBytesWritten = 0;
	pfnNtWriteVirtualMemory NtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	NTSTATUS ntStatus = NtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &NumberOfBytesWritten);
	if (NumberOfBytesWritten)
		*lpNumberOfBytesWritten = NumberOfBytesWritten;
	if (ntStatus >= 0)
		return TRUE;
	return FALSE;
}

BOOL GetExitCodeProcess_Stub(
	HANDLE  hProcess,
	LPDWORD lpExitCode
)
{
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationProcess");
	NTSTATUS ntStatus;
	BOOL bResult = FALSE;
	DWORD dwSizeOfProcessInformation = sizeof(PROCESS_BASIC_INFORMATION);
	PROCESS_BASIC_INFORMATION ProcessInformation = {0};
	ntStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessInformation, dwSizeOfProcessInformation, 0);
	if (ntStatus < 0)
	{
		bResult = FALSE;
	}
	else
	{
		*lpExitCode = ProcessInformation.ExitStatus;
		bResult = 1;
	}
	return bResult;
}

BOOL GetLogicalProcessorInformation_Stub(
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer,
	PDWORD                                ReturnedLength
)
{
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	pfnRtlGetCurrentProcessorNumberEx RtlGetCurrentProcessorNumberEx = (pfnRtlGetCurrentProcessorNumberEx)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlGetCurrentProcessorNumberEx");
	pfnNtQuerySystemInformationEx NtQuerySystemInformationEx = (pfnNtQuerySystemInformationEx)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"QuerySystemInformationEx");

	PROCESSOR_NUMBER v4 = { 0 };
	NTSTATUS ntStatus;

	if (!ReturnedLength)
	{
		RtlSetLastWin32Error(0x57u);
		return 0;
	}
	
	RtlGetCurrentProcessorNumberEx(&v4);
	ntStatus = NtQuerySystemInformationEx(SystemLogicalProcessorInformation, &v4, 2, Buffer, *ReturnedLength, ReturnedLength);
	if (ntStatus == 0xC0000004)
		ntStatus = 0xC0000023;
	if (ntStatus < 0)
	{
		RtlSetLastWin32Error(ntStatus);
		return FALSE;
	}
	return TRUE;
}

BOOL GetProcessAffinityMask_Stub(
	HANDLE     hProcess,
	PDWORD_PTR lpProcessAffinityMask,
	PDWORD_PTR lpSystemAffinityMask
)
{
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationProcess");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	BOOL bResult = FALSE;
	PROCESS_BASIC_INFORMATION ProcessInformation = { 0 };
	DWORD dwSizeOfProcessInformation = sizeof(PROCESS_BASIC_INFORMATION);
	SYSTEM_INFO SystemInfo;
	NTSTATUS ntStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessInformation, dwSizeOfProcessInformation, 0);
	if (ntStatus < 0)
	{
		RtlSetLastWin32Error(ntStatus);
		bResult = FALSE;
	}
	else
	{
		GetSystemInfo(&SystemInfo);
		*lpProcessAffinityMask = ProcessInformation.AffinityMask;
		*lpSystemAffinityMask = ProcessInformation.AffinityMask != 0 ? SystemInfo.dwActiveProcessorMask : 0;
		bResult = TRUE;
	}
	return bResult;
}

BOOL GetProcessHandleCount_Stub(HANDLE hProcess, PDWORD pdwHandleCount)
{
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationProcess");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");
	DWORD dwHandleCount = 0;
	NTSTATUS ntStatus = NtQueryInformationProcess(hProcess, ProcessHandleCount, &dwHandleCount, 4u, 0);
	BOOL bResult = FALSE;
	if (ntStatus >= 0)
	{
		*pdwHandleCount = dwHandleCount;
		bResult = TRUE;
	}
	else
	{
		RtlSetLastWin32Error(ntStatus);
		bResult = TRUE;
	}
	return bResult;
}


BOOL IsWow64Process_Stub(
	HANDLE hProcess,
	PBOOL  Wow64Process
)
{
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationProcess");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");
	NTSTATUS ntStatus = NtQueryInformationProcess(hProcess, ProcessWow64Information, &hProcess, sizeof(HANDLE), 0);
	if (ntStatus < 0)
		RtlSetLastWin32Error(ntStatus);
	else
		*Wow64Process = hProcess != 0;
	return ntStatus >= 0;
}

DWORD GetProcessId_Stub(
	HANDLE Process
)
{
	PROCESS_BASIC_INFORMATION ProcessInformation;
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationProcess");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	NTSTATUS ntStatus = NtQueryInformationProcess(Process, ProcessBasicInformation, &ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), 0);
	if (ntStatus >= 0)
		return (DWORD)ProcessInformation.UniqueProcessId;
	RtlSetLastWin32Error(ntStatus);
	return 0;
}


DWORD GetProcessVersion_Stub(
	DWORD ProcessId
)
{
	pfnNtCurrentTeb NtCurrentTeb = (pfnNtCurrentTeb)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtCurrentTeb");
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationProcess");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	HANDLE hProcess = NULL;
	if (!ProcessId || ProcessId == (DWORD)NtCurrentTeb()->ClientId.UniqueProcess)
	{
		hProcess = (HANDLE)-1;
	}
	else
	{
		hProcess = OpenProcess(0x1000u, 0, ProcessId);
		if (!hProcess)
		{
			hProcess = OpenProcess(0x400u, 0, ProcessId);
			if (!hProcess)
				return 0;
		}
	}
	
	SECTION_IMAGE_INFORMATION ImageInformation;
	NTSTATUS ntStatus = NtQueryInformationProcess(hProcess, ProcessImageInformation, &ImageInformation, 0x30u, 0);
	if (hProcess != (HANDLE)-1)
		CloseHandle(hProcess);
	if (ntStatus >= 0)
		return ImageInformation.u1.SubSystemVersion;
	RtlSetLastWin32Error(ntStatus);
	return 0;
}

/*
	Thread_Optional

*/

DWORD GetProcessIdOfThread_Stub(
	HANDLE Thread
)
{
	THREAD_BASIC_INFORMATION ThreadInformation;
	pfnNtQueryInformationThread NtQueryInformationThread = (pfnNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationThread");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	NTSTATUS ntStatus = NtQueryInformationThread(Thread, ThreadBasicInformation, &ThreadInformation, sizeof(THREAD_BASIC_INFORMATION), 0);
	if (ntStatus >= 0)
		return (DWORD)ThreadInformation.ClientId.UniqueProcess;
	RtlSetLastWin32Error(ntStatus);
	return 0;
}


//https://github.com/Arsense/WindowsCode/blob/master/NtCreateThreadEx().cpp
HANDLE CreateThread_Stub(LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId)
{
	NTSTATUS  ntStatus = -1;
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

	HANDLE hThread = NULL;

	ntStatus = NtCreateThreadEx(&hThread, 0x1FFFFF,
		NULL,
		GetCurrentProcess(),
		(PUSER_THREAD_START_ROUTINE)lpStartAddress,
		(PVOID)lpParameter,
		FALSE, NULL,
		(dwCreationFlags & 0x10000) == 0 ? dwStackSize : 0,
		(dwCreationFlags & 0x10000) != 0 ? dwStackSize : 0,
		NULL);
	return hThread;
}


HANDLE CreateRemoteThreadEx_Stub(
	HANDLE                       hProcess,
	LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	SIZE_T                       dwStackSize,
	LPTHREAD_START_ROUTINE       lpStartAddress,
	LPVOID                       lpParameter,
	DWORD                        dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD                      lpThreadId
)
{
	NTSTATUS  ntStatus = -1;
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	HANDLE hThread = NULL;
	ntStatus = NtCreateThreadEx(&hThread, 0x1FFFFF,
		NULL,
		hProcess,
		(PUSER_THREAD_START_ROUTINE)lpStartAddress,
		(PVOID)lpParameter,
		FALSE, NULL,
		(dwCreationFlags & 0x10000) == 0 ? dwStackSize : 0,
		(dwCreationFlags & 0x10000) != 0 ? dwStackSize : 0,
		NULL);
	return hThread;
}

BOOL GetExitCodeThread_Stub(
	HANDLE  hThread,
	LPDWORD lpExitCode
)
{
	THREAD_BASIC_INFORMATION ThreadInformation;
	pfnNtQueryInformationThread NtQueryInformationThread = (pfnNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationThread");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");


	BOOL bResult = FALSE;
	NTSTATUS ntStatus = NtQueryInformationThread(hThread, ThreadBasicInformation, &ThreadInformation, sizeof(THREAD_BASIC_INFORMATION), 0);
	if (ntStatus < 0)
	{
		bResult = FALSE;
	}
	else
	{
		*lpExitCode = ThreadInformation.ExitStatus;
		bResult = TRUE;
	}
	return bResult;
}


BOOL GetThreadContext_Stub(
	HANDLE    hThread,
	LPCONTEXT lpContext
)
{
	pfnNtGetContextThread NtGetContextThread = (pfnNtGetContextThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtGetContextThread");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");
	NTSTATUS ntStatus = NtGetContextThread(hThread, lpContext);
	if (ntStatus >= 0)
		return TRUE;
	RtlSetLastWin32Error(ntStatus);
	return TRUE;
}


HANDLE OpenThread_Stub(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
)
{
	pfnNtOpenThread NtOpenThread = (pfnNtOpenThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtGetContextThread");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");


	OBJECT_ATTRIBUTES ObjectAttributes = {0};
	CLIENT_ID ClientId = {0};
	HANDLE hThread = {0};
	ClientId.UniqueProcess = NULL;
	ClientId.UniqueThread = (HANDLE)dwThreadId;
	InitializeObjectAttributes(&ObjectAttributes, NULL, bInheritHandle ? 2 : 0, NULL, NULL);
	NTSTATUS ntStatus = NtOpenThread(&hThread, dwDesiredAccess, &ObjectAttributes, &ClientId);
	if (ntStatus > 0)
		return  hThread;
	RtlSetLastWin32Error(ntStatus);
	return  NULL;
}

DWORD ResumeThread_Stub(
	HANDLE hThread
)
{
	pfnNtResumeThread NtResumeThread = (pfnNtResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtGetContextThread");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	ULONG SuspendCount = 0;
	NTSTATUS ntStatus = NtResumeThread(hThread, &SuspendCount);
	if (ntStatus >= 0)
		return SuspendCount;
	RtlSetLastWin32Error(ntStatus);
	return -1;
}

BOOL SetThreadContext_Stub(
	HANDLE  hThread,
	CONTEXT *lpContext
)
{
	pfnNtSetContextThread NtSetContextThread = (pfnNtSetContextThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtSetContextThread");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	NTSTATUS ntStatus  = NtSetContextThread(hThread, lpContext);
	if  (ntStatus >= 0)
		return TRUE;
	RtlSetLastWin32Error(ntStatus);
	return FALSE;
}

EXECUTION_STATE SetThreadExecutionState_Stub(
	EXECUTION_STATE esFlags
)
{
	pfnNtSetThreadExecutionState NtSetThreadExecutionState = (pfnNtSetThreadExecutionState)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtSetThreadExecutionState");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");


	NTSTATUS ntStatus = STATUS_SUCCESS; 
	EXECUTION_STATE PreviousFlags = NULL;

	PreviousFlags = 0;
	ntStatus = NtSetThreadExecutionState(esFlags, &PreviousFlags);
	if (ntStatus >= 0)
		return PreviousFlags;
	RtlSetLastWin32Error(ntStatus);
	return NULL;
}

DWORD SuspendThreadStub_Stub(HANDLE hThread)
{
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");
	pfnNtSuspendThread NtSuspendThread = (pfnNtSuspendThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"pfnNtSuspendThread");

	ULONG PreviousSuspendCount = 0;
	NTSTATUS  ntStatus = NtSuspendThread(hThread, &PreviousSuspendCount);
	if (ntStatus >= 0)
		return PreviousSuspendCount;
	RtlSetLastWin32Error(ntStatus);
	return -1;
}

BOOL TerminateThread_Stub(HANDLE hThread, DWORD dwExitCode)
{

	pfnNtTerminateThread NtTerminateThread = (pfnNtTerminateThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtTerminateThread");
	pfnRtlSetLastWin32Error RtlSetLastWin32Error = (pfnRtlSetLastWin32Error)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"RtlSetLastWin32Error");

	if (hThread == NULL)
	{
		RtlSetLastWin32Error(6u);
		return FALSE;
	}
	NTSTATUS ntStatus = NtTerminateThread(hThread, dwExitCode);
	if (ntStatus >= 0)
		return TRUE;
	return TRUE;
}