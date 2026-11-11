#include <stdio.h>
#include "eprocess.h"
#include "ntdefs.h"

// ── Resolve EPROCESS.Protection offset for current OS build ─────

DWORD get_protection_offset(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    pRtlGetVersion RtlGetVersion =
        (pRtlGetVersion)(void*)GetProcAddress(ntdll, "RtlGetVersion");
    if (!RtlGetVersion) return 0;

    RTL_OSVERSIONINFOW vi = { 0 };
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (!NT_SUCCESS(RtlGetVersion(&vi))) return 0;

    DWORD build = vi.dwBuildNumber;
    printf("[*] OS Build: %lu\n", build);

    for (DWORD i = 0; i < OFFSET_TABLE_SIZE; i++) {
        if (build >= g_offsets[i].build_min &&
            build <= g_offsets[i].build_max) {
            printf("[+] EPROCESS.Protection offset: 0x%lX\n",
                g_offsets[i].protection_offset);
            return g_offsets[i].protection_offset;
        }
    }

    printf("[-] Unknown build %lu - offset not in table!\n", build);
    printf("    Use WinDbg: dt nt!_EPROCESS Protection\n");
    printf("    Then add the offset to g_offsets[] in eprocess.h\n");
    return 0;
}

// ── Find EPROCESS address for a PID ─────────────────────────────
//
// Open a handle to the target PID, then query
// SystemExtendedHandleInformation (class 64) to find our handle's
// Object pointer, which IS the EPROCESS address.

ULONG_PTR find_eprocess(DWORD pid) {
    // Open a handle to the target process
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 0;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)(void*)GetProcAddress(ntdll,
            "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        CloseHandle(hProc);
        return 0;
    }

    DWORD my_pid = GetCurrentProcessId();
    ULONG_PTR eprocess = 0;

    // SystemExtendedHandleInformation = 64
    ULONG buf_size = 4 * 1024 * 1024;
    PVOID buf = NULL;
    NTSTATUS status;
    do {
        buf = malloc(buf_size);
        if (!buf) { CloseHandle(hProc); return 0; }

        status = NtQuerySystemInformation(64, buf, buf_size, NULL);
        if (status == (NTSTATUS)0xC0000004) {
            free(buf);
            buf_size *= 2;
        }
    } while (status == (NTSTATUS)0xC0000004);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtQuerySystemInformation(64) failed: 0x%lX\n", status);
        free(buf);
        CloseHandle(hProc);
        return 0;
    }

    // SYSTEM_HANDLE_INFORMATION_EX:
    //   ULONG_PTR NumberOfHandles;
    //   ULONG_PTR Reserved;
    //   SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[];
    //
    // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX:
    //   PVOID Object;               // +0x00
    //   ULONG_PTR UniqueProcessId;  // +0x08
    //   ULONG_PTR HandleValue;      // +0x10
    //   ULONG GrantedAccess;        // +0x18
    //   USHORT CreatorBackTraceIndex;
    //   USHORT ObjectTypeIndex;
    //   ULONG HandleAttributes;
    //   ULONG Reserved;
    // Total size: 0x28 per entry

    ULONG_PTR num_handles = *(ULONG_PTR*)buf;
    BYTE* base = (BYTE*)buf + 2 * sizeof(ULONG_PTR);

    for (ULONG_PTR i = 0; i < num_handles; i++) {
        BYTE* entry = base + i * 0x28;

        ULONG_PTR entry_pid = *(ULONG_PTR*)(entry + 0x08);
        ULONG_PTR entry_handle = *(ULONG_PTR*)(entry + 0x10);
        PVOID     entry_object = *(PVOID*)(entry + 0x00);

        if (entry_pid == my_pid &&
            entry_handle == (ULONG_PTR)hProc) {
            eprocess = (ULONG_PTR)entry_object;
            break;
        }
    }

    free(buf);
    CloseHandle(hProc);

    if (eprocess) {
        printf("[+] EPROCESS for PID %lu: 0x%llX\n",
            pid, (unsigned long long)eprocess);
    }
    else {
        printf("[-] Could not find EPROCESS for PID %lu\n", pid);
    }

    return eprocess;
}

// ── Pretty-print protection info ────────────────────────────────

void print_protection(PS_PROTECTION prot) {
    const char* type_str[] = { "None", "Light (PPL)", "Full (PP)" };
    const char* signer_str[] = {
        "None", "Authenticode", "CodeGen", "Antimalware",
        "Lsa", "Windows", "WinTcb", "WinSystem"
    };

    printf("  Protection.Level  = 0x%02X\n", prot.Level);
    printf("  Protection.Type   = %s (%u)\n",
        prot.Type < 3 ? type_str[prot.Type] : "?", prot.Type);
    printf("  Protection.Signer = %s (%u)\n",
        prot.Signer < 8 ? signer_str[prot.Signer] : "?", prot.Signer);
}