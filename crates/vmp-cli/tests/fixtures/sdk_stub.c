#define __unix__ 1
#include "sdk.h"
#undef __unix__

#pragma comment(linker, "/export:VMProtectBeginMutation")
#pragma comment(linker, "/export:VMProtectEnd")
#pragma comment(linker, "/export:VMProtectIsProtected")
#pragma comment(linker, "/export:VMProtectDecryptStringA")
#pragma comment(linker, "/export:VMProtectDecryptStringW")
#pragma comment(linker, "/export:VMProtectFreeString")

#ifdef __cplusplus
extern "C" {
#endif

void VMP_API VMProtectBeginMutation(const char *name) {
    (void)name;
}

void VMP_API VMProtectEnd(void) {
}

bool VMP_API VMProtectIsProtected(void) {
    return true;
}

const char *VMP_API VMProtectDecryptStringA(const char *value) {
    return value;
}

const VMP_WCHAR *VMP_API VMProtectDecryptStringW(const VMP_WCHAR *value) {
    return value;
}

bool VMP_API VMProtectFreeString(const void *value) {
    (void)value;
    return false;
}

#ifdef __cplusplus
}
#endif
