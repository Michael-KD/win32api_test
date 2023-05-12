#include <windows.h>

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD nReason,
    LPVOID lpvReserved
) {

    switch (nReason) {

    case DLL_PROCESS_ATTACH:
        MessageBoxW(NULL, L"test, dll process attach", L"this is a box", MB_OK); // 0x00000000L
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
        
    }
    
    return TRUE;
}