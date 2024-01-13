#include <windows.h>
#include <tlHelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <Shlwapi.h>


std::ofstream logFile;  // Declare logFile in the global scope


// Function to redirect cout and cerr to a log file
void redirectLogToFile() {
    logFile.open("GIL.log");  // Open the log file
    if (!logFile.is_open()) {
        std::cerr << "Error: Failed to open the log file." << std::endl;
        return;
    }

    // Redirect cout and cerr to the log file
    std::cout.rdbuf(logFile.rdbuf());
    std::cerr.rdbuf(logFile.rdbuf());

    logFile << "Log file opened successfully." << std::endl;
    logFile << std::flush;  // Flush the log buffer
}

// Function to inject a DLL into a process
bool InjectDLL(DWORD processId, const std::string& dllPath) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == nullptr) {
        logFile << "Error: Failed to open the target process." << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);

    if (remoteMemory == nullptr) {
        logFile << "Error: Failed to allocate memory in the target process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path to the allocated memory
    WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), dllPath.size() + 1, nullptr);

    // Get the address of LoadLibraryA in kernel32.dll
    LPVOID loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    if (loadLibraryAddress == nullptr) {
        logFile << "Error: Failed to get the address of LoadLibraryA." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress),
                                        remoteMemory, 0, nullptr);

    if (hThread == nullptr) {
        logFile << "Error: Failed to create a remote thread." << std::endl;
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


bool LaunchProcess(const std::string& processPath) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(STARTUPINFOA));
    si.cb = sizeof(STARTUPINFOA);

    if (!CreateProcessA(nullptr, const_cast<char*>(processPath.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        logFile << "Error: Failed to launch the process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// Function to parse an INI file and retrieve configuration data
bool ReadConfig(const std::string& iniPath, std::string& processName, std::string& dllPath) {
    char buffer[MAX_PATH];

    if (GetPrivateProfileStringA("Config", "ProcessName", "", buffer, sizeof(buffer), iniPath.c_str()) == 0) {
        logFile << "Error: Failed to read 'ProcessName' from the INI file. Section or key not found." << std::endl;
        return false;
    }
    processName = buffer;

    if (GetPrivateProfileStringA("Config", "DllPath", "", buffer, sizeof(buffer), iniPath.c_str()) == 0) {
        logFile << "Error: Failed to read 'DllPath' from the INI file. Section or key not found." << std::endl;
        return false;
    }
    dllPath = buffer;

    return !processName.empty() && !dllPath.empty();
}

int main() {
	
	char buffer[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, buffer);
	std::string iniPath = std::string(buffer) + "\\GIL.ini";

    redirectLogToFile();

    std::string processName, dllPath;

    if (!ReadConfig(iniPath, processName, dllPath)) {
        logFile << "Error: Failed to read configuration from the INI file." << std::endl;
        return 1;
    }

    const char* targetProcessName = processName.c_str();
    const std::string injectDllPath = dllPath;

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
        logFile << "Target process not found. Launching..." << std::endl;
        if (!LaunchProcess(targetProcessName)) {
            logFile << "Error: Failed to launch the target process." << std::endl;
            return 1;
        }

        // Wait for the process to start
        Sleep(5000);

        // Retrieve the process ID again
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
            logFile << "Error: Unable to find or launch the target process." << std::endl;
            return 1;
        }
    }

    // Inject the DLL into the target process
    if (InjectDLL(processId, injectDllPath)) {
        logFile << "DLL injected successfully!" << std::endl;
    } else {
        logFile << "Error: DLL injection failed." << std::endl;
        return 1;
    }

    return 0;
}