#include <windows.h>
#include <stdio.h>
#include "SysWhisoers2Demo.h"



VOID OutPutSchedule(const CHAR* ScheduleName)
{
	printf("\t [=>] %s is  executing \r\n", ScheduleName);
}

VOID FileOptional_Demo()
{
	CHAR lpFileName[] = "D:\\123.txt";
	HANDLE hFile = CreateFileA_Stub(lpFileName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ, NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile != NULL)
	{
		printf("\t [*] CreateFileA Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] CreateFileA Failed to Execute \r\n");
		return;
	}


	DWORD lpNumber = 0;
	CHAR lpBuffer[] = "123456";
	if (WriteFile_Stub(hFile, lpBuffer, sizeof(lpBuffer), &lpNumber, NULL) == TRUE)
	{
		printf("\t [*] WriteFile Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] WriteFile Failed to Execute \r\n");
	}

	//lpNumber = 0;
	//memset(lpBuffer, 0, strlen((char*)lpBuffer));
	//if (ReadFile_Stub(hFile, lpBuffer, 2, &lpNumber, NULL) == TRUE)
	//{
	//	printf("\t [*] ReadFile Success to Execute  \r\n");
	//	printf("\t [*] Value is %s \r\n", (CHAR*)lpBuffer);
	//}
	//else
	//{
	//	printf("\t [!] ReadFile Failed to Execute \r\n");
	//}

	CloseHandle(hFile);
	if (DeleteFileA(lpFileName) == TRUE)
	{
		printf("\t [*] DeleteFile Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] DeleteFile Failed to Execute  \r\n");
	}
}




VOID RegOptional_Demo()
{
	HKEY hkResult;
	LSTATUS lStatus = RegCreateKeyA_Stub(HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\swyhdwuhd",&hkResult);
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegCreateKeyExA Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] RegCreateKeyExA Failed to Execute  %d\r\n", GetLastError());
	}

	lStatus = RegCloseKey_Stub(hkResult);
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegCloseKey Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] RegCloseKey Failed to Execute  %d\r\n", GetLastError());
	}


	hkResult = NULL;
	lStatus = RegOpenKeyW_Stub(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\swyhdwuhd", &hkResult);
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegOpenKeyW Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] RegOpenKeyW Failed to Execute  %d\r\n", GetLastError());
	}


	CHAR szModule[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szModule, MAX_PATH);
	lStatus = RegSetValueA_Stub(hkResult, "SelfRun", REG_SZ, szModule,strlen(szModule));
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegSetValueEx Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] RegSetValueEx Failed to Execute  %d\r\n", GetLastError());
	}

	CHAR lpBuffer[MAX_PATH] = {0};
	LONG dwReturn = MAX_PATH;
	lStatus = RegQueryValueA_Stub(hkResult, "SelfRun",lpBuffer,&dwReturn);
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegQueryValueExA Success to Execute :%ls \r\n", lpBuffer);
	}
	else
	{
		printf("\t [!] RegQueryValueExA Failed to Execute  %d\r\n", GetLastError());
	}

	CHAR lpBuffer1[MAX_PATH] = { 0 };
	DWORD dwReturn1 = MAX_PATH;
	lStatus = RegQueryValueExA_Stub(hkResult, "SelfRun", 0,NULL,(PBYTE)lpBuffer1, &dwReturn1);
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegQueryValueExA Success to Execute :%ls \r\n", lpBuffer1);
	}
	else
	{
		printf("\t [!] RegQueryValueExA Failed to Execute  %d\r\n", GetLastError());
	}

	WCHAR lpClass[MAX_PATH] = { 0 };
	DWORD lpcbClass = MAX_PATH;
	DWORD cSubKeys = 0, dwMaxSubKey = 0;
	lStatus = RegQueryInfoKeyW_Stub(hkResult, NULL, NULL,NULL, &cSubKeys, &dwMaxSubKey, NULL, NULL, NULL, NULL, NULL, NULL);
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegQueryInfoKeyW Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] RegQueryInfoKeyW Failed to Execute  %d\r\n", GetLastError());
	}

	for (DWORD i = 0; i < cSubKeys; i++)
	{
		CHAR szKeyName[MAX_PATH] = {0};
		CHAR szClass[MAX_PATH] = { 0 };
		DWORD dwKeyNameLength = MAX_PATH;
		DWORD dwKeyNameLength2 = MAX_PATH;
		lStatus = RegEnumKeyExA_Stub(hkResult, i, szKeyName, &dwKeyNameLength, NULL, szClass,&dwKeyNameLength2, NULL);
		if (lStatus == ERROR_SUCCESS)
		{
			printf("\t [*] RegEnumKeyExA Success to Execute :%s \r\n", szKeyName);
		}
		else
		{
			printf("\t [!] RegEnumKeyExA Failed to Execute  %d\r\n", GetLastError());
		}
		CHAR szKeyName3[MAX_PATH] = { 0 };
		DWORD dwKeyNameLength3 = MAX_PATH;
		lStatus = RegEnumKeyA_Stub(hkResult, i, szKeyName3, dwKeyNameLength3);
		if (lStatus == ERROR_SUCCESS)
		{
			printf("\t [*] RegEnumKeyA Success to Execute :%s \r\n", szKeyName3);
		}
		else
		{
			printf("\t [!] RegEnumKeyA Failed to Execute  %d\r\n", GetLastError());
		}

	}

	lStatus = RegDeleteValueA_Stub(hkResult, "SelfRun");
	if (lStatus == ERROR_SUCCESS)
	{
		printf("\t [*] RegDeleteValueA Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] RegDeleteValueA Failed to Execute  %d\r\n", GetLastError());
	}

	
}



VOID ProcessOptional_Demo()
{
	STARTUPINFOW si;
	PROCESS_INFORMATION info;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&info, 0, sizeof(info));
	WCHAR CommandLine[] = L"notepad.exe";
	WCHAR Application[] = L"C:\\windows\\system32\\cmd.exe";
	//TODO: ÉèÖÃ´°¿ÚÒþ²Ø
	if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &info) == TRUE)
	{
		printf("\t [*] CreateProcessA Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] CreateProcessA Failed to Execute \r\n");
	}

	//if (WinExec_Stub("notepad.exe", SW_HIDE) >= 33)
	//{
	//	printf("\t [*] WinExec Success to Execute  \r\n");
	//}
	//else
	//{
	//	printf("\t [!] WinExec Failed  to Execute  \r\n");
	//}

	HANDLE hProcess = OpenProcess_Stub(PROCESS_ALL_ACCESS, TRUE, info.dwProcessId);
	if (hProcess != NULL)
	{
		printf("\t [*] OpenProcess Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] OpenProcess Failed to Execute  \r\n");
	}

	DWORD dwPid = 0;
	dwPid = GetProcessId_Stub(hProcess);
	if (dwPid != 0)
	{
		printf("\t [*] GetProcessId Success to Execute Pid:%d \r\n",dwPid);
	}
	else
	{
		printf("\t [!] GetProcessId Failed to Execute  \r\n");
	}
	if (TerminateProcess_Stub(hProcess, -1) == TRUE)
	{
		printf("\t [*] TerminateProcess Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] TerminateProcess Failed to Execute  \r\n");
	}
}

VOID StartAddress()
{
	//MessageBoxA(NULL, "new thread", "new thread", MB_OK);
	printf("\t [*] new thread started \r\n");
	while (TRUE)
	{
		Sleep(1000);
	}
}

VOID ThreadOptional_Demo()
{
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;
	hThread = CreateThread_Stub(NULL, 0, (LPTHREAD_START_ROUTINE)StartAddress, 0, 0, &dwThreadId);
	if (hThread != NULL)
	{
		printf("\t [*] CreateThread Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] CreateThread Failed to Execute  \r\n");
	}

	CONTEXT context = { 0 };
	BOOL bResult = GetThreadContext_Stub(hThread, &context);
	if (bResult == TRUE)
	{
		printf("\t [*] GetThreadContext Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] GetThreadContext Failed to Execute  \r\n");
	}


	DWORD dwExitCode = 0;
	bResult = TerminateThread_Stub(hThread, dwExitCode);
	if (bResult > 0)
	{
		printf("\t [*] TerminateThread Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] TerminateThread Failed to Execute  \r\n");
	}

	bResult = GetExitCodeThread_Stub(hThread, &dwExitCode);
	if (bResult == TRUE)
	{
		printf("\t [*] GetExitCodeThread Success to Execute  \r\n");
	}
	else
	{
		printf("\t [!] GetExitCodeThread Failed to Execute  \r\n");
	}
}

int main()
{
	OutPutSchedule("File Optional");
	FileOptional_Demo();
	OutPutSchedule("Reg Optional");
	RegOptional_Demo();
	OutPutSchedule("Process Optional");
	ProcessOptional_Demo();
	OutPutSchedule("Thread Optional");
	ThreadOptional_Demo();
	getchar();
	return 0;
}