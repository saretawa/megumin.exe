#pragma once
#include <windows.h>
#include <winternl.h>

// NT internals we need not in standard headers

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NtQuerySystemInformation classes not in public headers
#define SystemExtendedHandleInformation 64

// Function pointers for NT APIs resolved at runtime
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pRtlGetVersion)(
    PRTL_OSVERSIONINFOW lpVersionInformation
    );

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
    );