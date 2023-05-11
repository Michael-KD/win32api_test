#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#pragma comment (lib, "ntdll")

char ok[] = "(+)";
char er[] = "(-)";
char in[] = "(*)";

typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
        OUT PHANDLE hThread,
        IN ACCESS_MASK DesiredAccess,
        IN PVOID ObjectAttributes,
        IN HANDLE ProcessHandle,
        IN PVOID lpStartAddress,
        IN PVOID lpParameter,
        IN ULONG Flags,
        IN SIZE_T StackZeroBits,
        IN SIZE_T SizeOfStackCommit,
        IN SIZE_T SizeOfStackReserve,
        OUT PVOID lpBytesBuffer
    );

LPVOID rBuffer;
HANDLE hThread;
HANDLE hProcess;

wchar_t dllPath[] = L"C:\\Users\\micha\\OneDrive\\Desktop\\win32\\win32api_test\\dllExample.dll";
//C:\\Users\\micha\\Desktop\\Code\\win32api_test\\dllExample.dll

int dllSize = sizeof(dllPath) + 1; // account for null-terminator

int main(int argc, char* argv[]) {

    if (argv[1] == NULL) {
        printf("%s usage: ntdllinjection.exe <pid>\n", er);
        return EXIT_FAILURE;
    }

    DWORD PID = atoi(argv[1]);
    hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE, //null?
        PID
    );

    if (!hProcess) {
        printf("%s couldn't create a handle to process (%d), error = %ld\n", er, PID, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s created a handle to process (%d)\n", ok, PID);
    printf("%s DLL path: '%S'\n", ok, dllPath);

    HMODULE hKernel32 = GetModuleHandleW(L"Kernel32");

    if (!hKernel32) {
        printf("%s couldn't get handle to Kernel32, error = %ld\n", er, GetLastError());
        CloseHandle(hProcess);
        printf("%s closed handle to process\n", in);
        return EXIT_FAILURE;
    }

    printf("%s got handle to Kernel32: 0x%p\n", ok, hKernel32);

    LPTHREAD_START_ROUTINE loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    pNtCreateThreadEx threadCreate = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");

    printf("%s got address of LoadLibraryW: 0x%p\n", ok, loadLib);
    printf("%s got address of NtCreateThreadEx: 0x%p\n", ok, threadCreate);

    if (!threadCreate) {
        printf("%s couldn't get address of NtCreateThreadEx, error = %ld\n", er, GetLastError());
        CloseHandle(hProcess);
        printf("%s closed handle to process\n", in);
        return EXIT_FAILURE;
    }

    rBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        dllSize,
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_EXECUTE_READWRITE
    );

    printf("%s allocated %d-bytes to process memory\n", ok, dllSize);

    WriteProcessMemory(
        hProcess,
        rBuffer,
        dllPath,
        dllSize,
        NULL
    );

    printf("%s wrote to process memory\n", ok);

    threadCreate(
        &hThread,
        0x1FFFFF,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE) loadLib,
        rBuffer,
        FALSE,
        FALSE, //null?
        FALSE, //null?
        FALSE, //null?
        NULL
    );

    printf("%s used custom NTDLL function (threadCreate) to create a thread\n", ok);

    if (hThread == NULL) {
        printf("%s couldn't create thread\n", er);
        CloseHandle(hProcess);
        printf("%s closed handle to process\n", in);
        return EXIT_FAILURE;
    }

    else {
        printf("%s injected with custom function (threadCreate) NtCreateThreadEx directly from NTDLL!\n", ok);
    }

    WaitForSingleObject(hThread, INFINITE);

    printf("%s closing handle to thread\n", in);
    CloseHandle(hThread);
    printf("%s closing handle to process", in);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;

}