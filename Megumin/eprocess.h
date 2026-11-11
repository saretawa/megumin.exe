#pragma once
#include <windows.h>

// PS_PROTECTION lives at _EPROCESS + Protection offset
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;  // 0 = None, 1 = Light, 2 = Full
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

// Protection types
#define PS_PROTECTED_TYPE_NONE      0
#define PS_PROTECTED_TYPE_LIGHT     1
#define PS_PROTECTED_TYPE_FULL      2

// Signer levels
#define PS_PROTECTED_SIGNER_NONE        0
#define PS_PROTECTED_SIGNER_AUTHENTICODE 1
#define PS_PROTECTED_SIGNER_CODEGEN     2
#define PS_PROTECTED_SIGNER_ANTIMALWARE 3
#define PS_PROTECTED_SIGNER_LSA         4
#define PS_PROTECTED_SIGNER_WINDOWS     5
#define PS_PROTECTED_SIGNER_WINTCB      6
#define PS_PROTECTED_SIGNER_WINSYSTEM   7

// EPROCESS.Protection offset per OS build
// Key: build number from RtlGetVersion
// You MUST verify these on your target use WinDbg:
//   dt nt!_EPROCESS Protection
typedef struct _EPROCESS_OFFSETS {
    DWORD build_min;
    DWORD build_max;
    DWORD protection_offset;
} EPROCESS_OFFSETS;

// Known offsets - extend as needed
static const EPROCESS_OFFSETS g_offsets[] = {
    // Windows 10 1507 - 1607
    { 10240, 14393, 0x6B2 },
    // Windows 10 1703 - 1709
    { 15063, 16299, 0x6C2 },
    // Windows 10 1803
    { 17134, 17134, 0x6CA },
    // Windows 10 1809 / Server 2019
    { 17763, 17763, 0x6CA },
    // Windows 10 1903 - 1909
    { 18362, 18363, 0x6CA },
    // Windows 10 20H1 through 22H2
    { 19041, 19045, 0x87A },
    // Windows Server 2022
    { 20348, 20348, 0x87A },
    // Windows 11 21H2
    { 22000, 22000, 0x87A },
    // Windows 11 22H2 - 23H2
    { 22621, 22631, 0x87A },
    // Windows 11 24H2 - TODO: verify with WinDbg
    // { 26100, 26100, 0x??? },
};

#define OFFSET_TABLE_SIZE (sizeof(g_offsets) / sizeof(g_offsets[0]))

// Resolve EPROCESS.Protection offset for current build
DWORD get_protection_offset(void);

// Find EPROCESS base address for a given PID
ULONG_PTR find_eprocess(DWORD pid);

// Print current protection info
void print_protection(PS_PROTECTION prot);