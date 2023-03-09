#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <dsgetdc.h>
//#include "beacon.h"

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
WINBASEAPI int __cdecl MSVCRT$printf(const char * __restrict__ _Format,...);

char* TestGlobalString = "This is a global string";
int testvalue = 0;

int test(void){
    MSVCRT$printf("Test String from `test`\n");
    testvalue = 1;
    return 0;
}

int test2(void){
    MSVCRT$printf("Test String from `test2`\n");
    return 0;
}

int go(char * args, unsigned long alen) {
    DWORD dwRet;
    PDOMAIN_CONTROLLER_INFO pdcInfo;
    // BeaconPrintf(1, "This GlobalString \"%s\"\n", TestGlobalString);
    MSVCRT$printf("This GlobalString \"%s\"\n", TestGlobalString);
    MSVCRT$printf("Test Value: %d\n", testvalue);
    (void)test();
    MSVCRT$printf("Test ValueBack: %d\n", testvalue);
    (void)test2();
    dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);

    if (ERROR_SUCCESS == dwRet) {
        MSVCRT$printf("%s", pdcInfo->DomainName);
    } else {
        MSVCRT$printf("Failed");
    }

    NETAPI32$NetApiBufferFree(pdcInfo);
}