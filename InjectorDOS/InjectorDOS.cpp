#include <windows.h>
#include <iostream>
#include <filesystem>

#include <vector>
#include <tchar.h>
#include <tlhelp32.h>
#include <iostream>

#pragma comment(lib, "psapi.lib")

using namespace std;
using std::cout; using std::cin;
using std::endl; using std::string;


//wstring TargetName = L"WowClassicT.exe";
wstring TargetName = L"EarTrumpet.exe";
//wstring TargetName = L"WowClassic.exe";
//wstring TargetName = L"notepad.exe";
//const wstring DLL_NAME = L"CppInjection.dll";
//const wstring DLL_NAME = L"ColdHide64.dll";
wstring DLL_NAME = L"CppInjection.dll";
//wstring DLL_NAME = L"vehdebug-x86_64";
const char* DLL_NameChar = "a.dll";


std::wstring ExePath() {
	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	return std::wstring(buffer).substr(0, pos);
}


std::string ws2s(const std::wstring& wstr)
{
	int size_needed = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), int(wstr.length() + 1), 0, 0, 0, 0);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), int(wstr.length() + 1), &strTo[0], size_needed, 0, 0);
	return strTo;
}



std::string GetLastErrorAsString()
{
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::string message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}


int Inject(DWORD pid)
{
	std::cout << "Attempting to inject...";
	// place the dll in the build directory $(SolutionDir)bin
	auto path = ExePath() + L"\\" + DLL_NAME;
	LPCSTR dllPath = ws2s(path).c_str();

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	std::cout << GetLastErrorAsString();

	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(dllPath) + 1,
		MEM_COMMIT, PAGE_READWRITE);

	std::cout << GetLastErrorAsString();

	WriteProcessMemory(hProcess, pDllPath, (LPVOID)dllPath, strlen(dllPath) + 1, 0);

	std::cout << GetLastErrorAsString();

	HANDLE hLoadThread = CreateRemoteThread(hProcess, 0, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"),
			"LoadLibraryA"), pDllPath, 0, 0);

	std::cout << GetLastErrorAsString();

	WaitForSingleObject(hLoadThread, INFINITE);

	std::cout << GetLastErrorAsString();
	//VirtualFreeEx(hProcess, pDllPath, strlen(dllPath) + 1, MEM_RELEASE))
	if (!VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE))
	{
		std::cout << GetLastErrorAsString();
	}
	else
	{
		std::cout << "VirtualFree worked!";
	}

	//CloseHandle(hProcess);

	std::cout << "Injection finished!";
	return 0;
}


vector<DWORD> GetPIDs(wstring pName)
{
	vector<DWORD> pids;
	wstring targetProcessName = pName;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof entry;

	do
	{
		if (wstring(entry.szExeFile) == targetProcessName)
			pids.emplace_back(entry.th32ProcessID);

	} while (Process32NextW(snap, &entry));

	return pids;
}






void DisplayLastError(const char* operation, int err)
{
	std::cerr << "Error ";
	if (err) std::cerr << err << " ";
	std::cerr << operation << std::endl;
}

void DisplayLastError(const char* operation)
{
	DisplayLastError(operation, GetLastError());
}

bool CreateRemoteThreadInject(DWORD IDofproc)
{
	if (!IDofproc)
		return false;


	auto path = ExePath() + L"\\" + DLL_NAME;
	LPCSTR dll = ws2s(path).c_str();


	LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (!pLoadLibrary)
	{
		DisplayLastError("getting LoadLibrary pointer");
		return false;
	}

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, IDofproc);
	if (!hProcess)
	{
		DisplayLastError("opening the process");
		return false;
	}

	LPVOID pMemory = VirtualAllocEx(hProcess, NULL, strlen(dll) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pMemory)
	{
		DisplayLastError("allocating memory");
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, pMemory, dll, strlen(dll) + 1, NULL))
	{
		DisplayLastError("writing to allocated memory");
		VirtualFreeEx(hProcess, pMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pMemory, 0, NULL);
	if (!hThread)
	{
		DisplayLastError("creating remote thread");
		VirtualFreeEx(hProcess, pMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);

	DWORD dwExitCode = 0;
	GetExitCodeThread(hThread, &dwExitCode);

	CloseHandle(hThread);

	VirtualFreeEx(hProcess, pMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	if (!dwExitCode)
	{
		DisplayLastError("loading dll", 0);
		return false;
	}

	MessageBox(NULL, TEXT("Injected"), TEXT(""), MB_OK);
	return true;
}

bool Injectstuff(DWORD processId)
{
	std::cout << "Process ID: " << processId << std::endl;
	return CreateRemoteThreadInject(processId);
}





int main()
{

	DWORD target;

	std::cout << "Enter a PID to host : ";
	std::cin >> target;
	if (!Injectstuff(target))
	{
		std:cout << "Hosting at PID -> " << target << "Failed..." << std::endl;
		main();  /// Recursive code yikers boys
	}
	return 1;
		


	/*std::cout << "Attempting to inject to at all : notepad.exe";
	auto pids = GetPIDs(TargetName);

	for (auto p : pids)
	{
		if (Injectstuff(p))
			break;
	}			*/
}