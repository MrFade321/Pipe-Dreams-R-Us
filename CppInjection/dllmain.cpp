// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include "pch.h"
#include <thread>
#include <fstream>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <windows.h>
#include <processthreadsapi.h>
#include <string>
#include <vector>
#include <Psapi.h>
#include <TlHelp32.h>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <ntstatus.h>
#include <cstdint> // For byte
#include <iomanip>

using namespace std;
using namespace rapidjson;

///
//[in] LPCVOID lpBaseAddress,
//[out] LPVOID  lpBuffer,
//[in]  SIZE_T  nSize,
//[out] SIZE_T* lpNumberOfBytesRead
///

// Structure to represent parameters of ReadProcessMemory
struct ReadProcessMemoryParams {
    LPVOID baseAddress;    
    SIZE_T size;
};

struct ReturnReadProcessMemory {
    bool Sucesss;
    LPVOID  lpBuffer;
    SIZE_T lpNumberOfBytesRead;
};

typedef int NTSTATUS;


using NtReadVirtualMemoryFunc = NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);


NtReadVirtualMemoryFunc pNtReadVirtualMemory = NULL;


HANDLE hProcess = NULL;


bool DeserializeInput(const std::string& input, ReadProcessMemoryParams& params) {
    Document document;
    if (document.Parse(input.c_str()).HasParseError()) {
        std::cerr << "Error: Failed to parse JSON input from server." << std::endl;
        return false;
    }






    if (!document.HasMember("baseAddress") || !document.HasMember("size")) {
        std::cerr << "Error: JSON input is missing required fields." << std::endl;
        return false;
    }

    //params.processId = document["processId"].GetUint();
    

    // Deserialize input from client
    std::string baseAddressStr = document["baseAddress"].GetString(); // Get the base address as string
    // Convert the base address from string to uint64_t
    uint64_t baseAddress = std::stoull(baseAddressStr, nullptr, 16);
    params.baseAddress = reinterpret_cast<LPVOID>(baseAddress);


    params.size = document["size"].GetUint64();

    return true;
}



// Serialize the return of ReadProcessMemory to JSON
std::vector<uint8_t> SerializeReturn(const ReturnReadProcessMemory& result) {
    std::vector<uint8_t> byteArray(sizeof(long long) + sizeof(int));

    // Copy lpBuffer into byte array
    std::memcpy(byteArray.data(), &result.lpBuffer, sizeof(long long));

    // Copy bytesRead into byte array
    std::memcpy(byteArray.data() + sizeof(long long), &result.lpNumberOfBytesRead, sizeof(int));

    return byteArray;    
}





std::string MBFromW(LPCWSTR pwsz, UINT cp) {
    int cch = WideCharToMultiByte(cp, 0, pwsz, -1, 0, 0, NULL, NULL);

    char* psz = new char[cch];

    WideCharToMultiByte(cp, 0, pwsz, -1, psz, cch, NULL, NULL);

    std::string st(psz);
    delete[] psz;

    return st;
}


HMODULE GetModule()
{
    HMODULE hMods[1024];
    HANDLE pHandle = GetCurrentProcess();
    DWORD cbNeeded;
    unsigned int i;

    if (EnumProcessModules(pHandle, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(pHandle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                std::wstring wstrModName = szModName;
                //you will need to change this to the name of the exe of the foreign process
                wstring wstrModContain = L"WowClassic.exe";
                if (wstrModName.find(wstrModContain) != string::npos)
                {
                    CloseHandle(pHandle);
                    return hMods[i];
                }
            }
        }
    }
    return nullptr;
}






HINSTANCE DllHandle;



DWORD __stdcall EjectThread(LPVOID lpParameter) {
    Sleep(100);
    FreeLibraryAndExitThread(DllHandle, 0);
    return 0;
}

void shutdown(FILE* fp, std::string reason) {

  
    std::cout << reason << std::endl;
    Sleep(1000);
    if (fp != nullptr)
        fclose(fp);
    FreeConsole();
    CreateThread(0, 0, EjectThread, 0, 0, 0);
    return;
}


void TestWoWHandle()
{

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot failed" << std::endl;
        return;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process, and exit if unsuccessful.
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Error: Process32First failed" << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }

    // Iterate through processes to find the one named "WowClassic.exe".
    do {
        if (_wcsicmp(pe32.szExeFile, L"WowClassic.exe") == 0) {
            std::cout << "Found WowClassic.exe with PID: " << pe32.th32ProcessID << std::endl;
            // You can get the handle to the process using OpenProcess function here
             hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                std::cout << "Opened handle to process successfully." << std::endl;
                // Use hProcess as needed
            }
            else {
                std::cerr << "Error: OpenProcess failed" << std::endl;
            }
            // Use hProcess as needed
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    // Close the handle to the process snapshot.
    CloseHandle(hProcessSnap);

}



ReturnReadProcessMemory ReadProcessMemory(LPVOID BaseAddress, SIZE_T size)
{
    ReturnReadProcessMemory result;


    // Define the address in the target process where the string is located
   // LPVOID address = Parms.baseAddress; // Replace this with the target address

    // Define a buffer to store the read string
    //const size_t bufferSize = size;
    unsigned char* buffer = new unsigned char[size]; // Dynamically allocate memory

    // Read the string from the target process's memory
    SIZE_T bytesRead = 0;


    std::cout << "BaseAddress: 0x" << std::hex << reinterpret_cast<uintptr_t>(BaseAddress) << std::endl;

    NTSTATUS Readresult = pNtReadVirtualMemory(hProcess, BaseAddress, buffer, size, &bytesRead);

    if (Readresult != 0x00000000) {
        std::cout << "Error: Failed to read process memory.  NTResult : " << Readresult <<  "Last Error code : " << GetLastError() << std::endl;    
        delete[] buffer;
        return ReturnReadProcessMemory();
    }
    else
    {

        std::cout << "Buffer Contents (hex): ";
        for (SIZE_T i = 0; i < bytesRead; ++i) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buffer[i]) << " ";
        }
        std::cout << std::endl;


        // Debug: Print buffer contents as an integer
        int intValue = *reinterpret_cast<int*>(buffer);
        std::cout << "Buffer Contents (int): " << intValue << std::endl;

        // Debug: Print buffer contents as a byte
        std::cout << "Buffer Contents (byte): " << static_cast<int>(buffer[0]) << std::endl;

        // Debug: Print buffer contents as a string
        std::string strValue(reinterpret_cast<char*>(buffer), bytesRead);
        std::cout << "Buffer Contents (string): " << strValue << std::endl;


        result.Sucesss = true;
        std::vector<unsigned char> byteVector(buffer, buffer + bytesRead);
        result.lpBuffer = reinterpret_cast<LPVOID>(byteVector.data());
        result.lpNumberOfBytesRead = bytesRead;
        return result;
    }        
}







DWORD Test(LPVOID hInstance)
{
    //std::thread(Test, hModule).detach();

    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout); //sets cout to be used with our newly created console


    HMODULE Module = GetModule();

   


    HMODULE hNtdll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtdll == NULL) {
        std::cerr << "Failed to load ntdll.dll\n";
      //  return 1;
    }

    // Get address of NtReadVirtualMemory
     pNtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemoryFunc>(
        GetProcAddress(hNtdll, "NtReadVirtualMemory")
        );
    if (pNtReadVirtualMemory == NULL) {
        std::cerr << "Failed to get address of NtReadVirtualMemory\n";
      //  return 1;
    }


    TestWoWHandle();

    // Define the name of the pipe
    LPCWSTR pipeName = L"\\\\.\\pipe\\MyNamedPipe";

    // Create the named pipe
    HANDLE hPipe = CreateNamedPipe(
        pipeName,                   // Pipe name
        PIPE_ACCESS_DUPLEX,         // Pipe open mode
        PIPE_TYPE_MESSAGE |         // Message type pipe
        PIPE_READMODE_MESSAGE |     // Message-read mode
        PIPE_WAIT,                  // Blocking mode
        PIPE_UNLIMITED_INSTANCES,   // Max. instances
        12,                       // Output buffer size
        12,                       // Input buffer size
        0,                          // Default timeout
        NULL                        // Security attributes
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Failed to create named pipe. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Named pipe server created successfully. Waiting for clients..." << std::endl;

    // Wait for a client to connect
    if (!ConnectNamedPipe(hPipe, NULL)) {
        std::cerr << "Error: Failed to connect to named pipe. Error code: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return 1;
    }


    while (true)
    {

       /* std::cout << "Client connected. Ready to receive data." << std::endl;*/

        // Read data from the pipe
        std::vector<uint8_t> byteArray(12);
        DWORD bytesRead;
        if (!ReadFile(hPipe, byteArray.data(), sizeof(byteArray), &bytesRead, NULL)) {
            std::cout << "Error: Failed to read data from server. Error code: " << GetLastError() << std::endl;
            //CloseHandle(hPipe);
           
        }


        if (byteArray.size() < sizeof(long long) + sizeof(int))
        {
            std::cout << "Insufficient data received\n";
         
        }

        // Read IntPtr (BaseAddress)
        long long baseAddress;
        std::memcpy(&baseAddress, byteArray.data(), sizeof(long long));
        //std::cout << "BaseAddress: " << baseAddress << std::endl;

        // Read int (Size)
        int size;
        std::memcpy(&size, byteArray.data() + sizeof(long long), sizeof(int));
       // std::cout << "Size: " << size << std::endl;


        //std::cout << "RPM Base -> " << std::hex << reinterpret_cast<uint64_t>(params.baseAddress) << std::endl;

        //std::cout << "RPM Size -> " << params.size << std::endl;


       ReturnReadProcessMemory Response = ReadProcessMemory((LPVOID)baseAddress,size);




       std::vector<uint8_t> RbyteArray = SerializeReturn(Response);

        DWORD bytesWritten;
        if (!WriteFile(hPipe, RbyteArray.data(), RbyteArray.size(), &bytesWritten, NULL)) {
            std::cout << "Failed to reponse to pipe client." << std::endl;
            throw std::runtime_error("Failed to send data to client.");
        }

       //  Flush the pipe to ensure that all data is sent
        //FlushFileBuffers(hPipe);
        //std::cout << "Result sent to client." << std::endl;


        // Now you have the parameters and can proceed with ReadProcessMemory

       // Now you can read data from the pipe and process it        
       // Sleep(1);
    }


    // Close the pipe handle when done
    CloseHandle(hPipe);



    //CallInGame();
 
    bool NoClip = false;
    while (true) {
        Sleep(80);
        if (GetAsyncKeyState(VK_NUMPAD0) & 1) {
            break;
        }
    }


    shutdown(fp, "Byby");
    return 0;
}






BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DllHandle = hModule;       
        std::thread(Test, hModule).detach();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
