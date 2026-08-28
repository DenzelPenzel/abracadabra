#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#ifdef VMP_SDK_IMPORT_THUNK
// Omit only dllimport so MSVC emits calls through import-library thunks.
extern "C" {
void __stdcall VMProtectBeginMutation(const char *);
void __stdcall VMProtectEnd(void);
bool __stdcall VMProtectIsProtected(void);
const char *__stdcall VMProtectDecryptStringA(const char *);
const wchar_t *__stdcall VMProtectDecryptStringW(const wchar_t *);
bool __stdcall VMProtectFreeString(const void *);
}
#else
#include "sdk.h"
#endif

#ifdef VMP_SDK_REGISTER_TRANSFER
extern "C" int sdk_register_protected_region(int value);
#define protected_region sdk_register_protected_region
#elif defined(VMP_SDK_STATIC_MARKER)
extern "C" int sdk_static_protected_region(int value);
#define protected_region sdk_static_protected_region
#else
__declspec(noinline) static int protected_region(int value) {
    VMProtectBeginMutation("direct-sdk-slice");

    const char *ansi = VMProtectDecryptStringA("ansi");
    const wchar_t *wide = VMProtectDecryptStringW(L"wide");
    int result = value + VMProtectIsProtected();
    result += ansi[0] == 'a';
    result += wide[0] == L'w';
    (void)VMProtectFreeString(ansi);
    (void)VMProtectFreeString(wide);

    if (value == 13) {
        RaiseException(0xE0421001u, 0, 0, NULL);
    }
    if (value == 9) {
        return result + 900;
    }
    if ((value & 1) != 0) {
        result *= 3;
        VMProtectEnd();
        return result ^ 0x55;
    }

    result -= 2;
    VMProtectEnd();
    return result ^ 0xAA;
}
#endif

int main(int argc, char **argv) {
    int value = argc > 1 ? atoi(argv[1]) : 0;
    __try {
        int result = protected_region(value);
        printf("result=%d unwound=false\n", result);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("code=%08lx unwound=true\n", GetExceptionCode());
    }
    return 0;
}
