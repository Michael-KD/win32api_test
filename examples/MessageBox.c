#include <windows.h>

int main(void) {
    MessageBoxW(
        NULL,
        L"My first message box!!",
        L"Yippie!!",
        MB_ICONEXCLAMATION | MB_OKCANCEL
    );

    return EXIT_SUCCESS;
}