#include <windows.h>
#include <stdio.h>

int main(void) {
    
STARTUPINFO si = { 0 };
PROCESS_INFORMATION pi= { 0 };

    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))     
    {
        printf("(-) failed to create process, error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    DWORD TID = pi.dwThreadId;
    DWORD PID = pi.dwProcessId;
    HANDLE hThread = pi.hThread;
    HANDLE hProcess = pi.hProcess;

    printf("(+) got handle to process\n");
    printf("(+) process started! pid: %ld\n", PID);
    printf("\t(+) pid: %ld, handle: 0x%x\n", PID, hProcess);
    printf("\t(+) tid: %ld, handle: 0x%x\n\r", TID, hThread);    
    
    WaitForSingleObject(hProcess, INFINITE);
    printf("(+) finished! exiting...");

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}