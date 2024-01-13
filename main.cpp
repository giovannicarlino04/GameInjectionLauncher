#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <Shlwapi.h>

// Function to redirect cout and cerr to a log file
void redirectLogToFile(const std::string& filename) {
    // Save the original cout and cerr buffers
    std::streambuf* coutBuf = std::cout.rdbuf();
    std::streambuf* cerrBuf = std::cerr.rdbuf();

    // Open the log file
    std::ofstream logFile(filename);

    // Redirect cout and cerr to the log file
    std::cout.rdbuf(logFile.rdbuf());
    std::cerr.rdbuf(logFile.rdbuf());
}

// Function to inject a DLL into a process
bool InjectDLL(DWORD processId, const std::string& dllPath) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == nullptr) {
        std::cerr << "Error: Failed to open the target process." << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);

    if (remoteMemory == nullptr) {
        std::cerr << "Error: Failed to allocate memory in the target process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path to the allocated memory
    WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), dllPath.size() + 1, nullptr);

    // Get the address of LoadLibraryA in kernel32.dll
    LPVOID loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    if (loadLibraryAddress == nullptr) {
        std::cerr << "Error: Failed to get the address of LoadLibraryA." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress),
                                        remoteMemory, 0, nullptr);

    if (hThread == nullptr) {
        std::cerr << "Error: Failed to create a remote thread." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up resources
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

// Function to parse an INI file and retrieve configuration data
bool ReadConfig(const std::string& iniPath, std::string& processName, std::string& dllPath) {
    char buffer[MAX_PATH];

    GetPrivateProfileString("Config", "ProcessName", "", buffer, sizeof(buffer), iniPath.c_str());
    processName = buffer;

    GetPrivateProfileString("Config", "DllPath", "", buffer, sizeof(buffer), iniPath.c_str());
    dllPath = buffer;

    return !processName.empty() && !dllPath.empty();
}

int main() {
    // Example INI file path
    std::string iniPath = "GIL.ini";

    // Read configuration from the INI file
    std::string processName, dllPath;

    if (!ReadConfig(iniPath, processName, dllPath)) {
        std::cerr << "Error: Failed to read configuration from the INI file." << std::endl;
        return 1;
    }

    // Example target process name
    const char* targetProcessName = processName.c_str();

    // Example DLL path
    const std::string injectDllPath = dllPath;

    // Get the process ID of the target process
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_stricmp(processEntry.szExeFile, targetProcessName) == 0) {
                processId = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);

    if (processId == 0) {
        std::cerr << "Error: Target process not found." << std::endl;
        return 1;
    }

    // Inject the DLL into the target process
    if (InjectDLL(processId, injectDllPath)) {
        std::cout << "DLL injected successfully!" << std::endl;
    } else {
        std::cerr << "Error: DLL injection failed." << std::endl;
        return 1;
    }

    return 0;
}
