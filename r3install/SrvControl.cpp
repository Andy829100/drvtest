#include <windows.h>
#include <iostream>
#include <strsafe.h>
#include "SrvControl.h"

bool InstallDriver(LPCWSTR lpszSrvName, LPCWSTR lpszFilePath, LPCWSTR lpszAltitude)
{
    if (NULL == lpszSrvName || NULL == lpszFilePath)
        return false;

    WCHAR szDriverImagePath[MAX_PATH] = { 0 };
    if (GetFullPathNameW(lpszFilePath, MAX_PATH, szDriverImagePath, NULL) == 0 || szDriverImagePath[0] == L'\0')
        StringCchCopyW(szDriverImagePath, MAX_PATH, lpszFilePath);

    //打开服务控制管理器
    SC_HANDLE  hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == hServiceMgr)
    {
        printf("OpenSCManagerW fail,errcode= %d \n", GetLastError());
        return false;
    }

    //创建驱动所对应的服务
    SC_HANDLE hService = CreateServiceW(hServiceMgr,
        lpszSrvName,                 // 驱动程序的在注册表中的名字
        lpszSrvName,                // 注册表驱动程序的DisplayName 值
        SERVICE_ALL_ACCESS,         // 加载驱动程序的访问权限
        SERVICE_KERNEL_DRIVER/*SERVICE_FILE_SYSTEM_DRIVER*/, // 表示加载的服务是文件系统驱动程序
        SERVICE_DEMAND_START,       // 注册表驱动程序的Start 值
        SERVICE_ERROR_IGNORE,       // 注册表驱动程序的ErrorControl 值
        szDriverImagePath,          // 注册表驱动程序的ImagePath 值
        NULL/*L"FSFilter Activity Monitor"*/,// 注册表驱动程序的Group 值
        NULL,
        NULL/*L"FltMgr"*/,                   // 注册表驱动程序的DependOnService 值
        NULL,
        NULL);

    if (NULL == hService)
    {
        CloseServiceHandle(hServiceMgr);

        // ERROR_IO_PENDING
        if (GetLastError() == ERROR_SERVICE_EXISTS)
        {
            //服务已经存在，返回成功
            printf("CreateServiceW ,Srv existed ,success \n");
            return true;
        }
        else
        {
            printf("CreateServiceW fail,errcode= %d \n", GetLastError());
            return false;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hServiceMgr);

    if (lpszAltitude != NULL)
    {
        // 写注册表
    // System\\CurrentControlSet\\Services\\DriverName\\Instances子健 
        HKEY    hKey;
        DWORD   dwData;
        WCHAR   szTempStr[MAX_PATH];
        wcscpy_s(szTempStr, L"SYSTEM\\CurrentControlSet\\Services\\");
        wcscat_s(szTempStr, lpszSrvName);
        wcscat_s(szTempStr, L"\\Instances");
        if (ERROR_SUCCESS != RegCreateKeyExW(HKEY_LOCAL_MACHINE, szTempStr, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData))
        {
            printf("Reg API fail,errcode= %d\n", GetLastError());
            return false;
        }

        // 注册表驱动程序的DefaultInstance 值 
        wcscpy_s(szTempStr, lpszSrvName);
        wcscat_s(szTempStr, L" Instance");
        if (ERROR_SUCCESS != RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)wcslen(szTempStr) * sizeof(wchar_t)))
        {
            printf("Reg API fail,errcode= %d\n", GetLastError());
            return false;
        }

        RegFlushKey(hKey);//刷新注册表
        RegCloseKey(hKey);

        // System\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance子健
        wcscpy_s(szTempStr, L"SYSTEM\\CurrentControlSet\\Services\\");
        wcscat_s(szTempStr, lpszSrvName);
        wcscat_s(szTempStr, L"\\Instances\\");
        wcscat_s(szTempStr, lpszSrvName);
        wcscat_s(szTempStr, L" Instance");
        if (ERROR_SUCCESS != RegCreateKeyExW(HKEY_LOCAL_MACHINE, szTempStr, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData))
        {
            printf("Reg API fail,errcode= %d\n", GetLastError());
            return false;
        }

        // 注册表驱动程序的Altitude 值
        wcscpy_s(szTempStr, lpszAltitude);
        if (ERROR_SUCCESS != RegSetValueExW(hKey, L"Altitude", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)wcslen(szTempStr) * sizeof(wchar_t)))
        {
            printf("Reg API fail,errcode= %d\n", GetLastError());
            return false;
        }

        // 注册表驱动程序的Flags 值
        dwData = 0x0;
        if (ERROR_SUCCESS != RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (CONST BYTE*) & dwData, sizeof(DWORD)))
        {
            printf("Reg API fail,errcode= %d\n", GetLastError());
            return false;
        }

        RegFlushKey(hKey);//刷新注册表
        RegCloseKey(hKey);
    }

    return true;
}

bool StartDriver(LPCWSTR lpszSrvName)
{
    if (nullptr == lpszSrvName)
        return false;

    SC_HANDLE schManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (nullptr == schManager)
    {
        printf("OpenSCManagerW fail, GetLastError()=%u \n", GetLastError());
        return false;
    }
    SC_HANDLE schService = OpenServiceW(schManager, lpszSrvName, SERVICE_ALL_ACCESS);
    if (nullptr == schService)
    {
        printf("OpenServiceW fail, GetLastError()=%u \n", GetLastError());
        CloseServiceHandle(schManager);
        return false;
    }

    bool bRet = false;
    if (StartServiceW(schService, 0, NULL))
        bRet = true;
    else
    {
        printf("StartServiceW, GetLastError()=%u \n", GetLastError());
        if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
            bRet = true;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);
    return bRet;
}

bool StopDriver(LPCWSTR lpszSrvName)
{
    SC_HANDLE schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schManager)
    {
        printf("OpenSCManager fail, errcode= %d\n", GetLastError());
        return false;
    }
    SC_HANDLE schService = OpenService(schManager, lpszSrvName, SERVICE_ALL_ACCESS);
    if (NULL == schService)
    {
        printf("OpenService fail, errcode= %d\n", GetLastError());
        CloseServiceHandle(schManager);
        return false;
    }

    SERVICE_STATUS svcStatus;
    if (!ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus) && (svcStatus.dwCurrentState != SERVICE_STOPPED))
    {
        printf("ControlService fail, errcode= %d\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        return false;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);
    return true;
}

bool DeleteDriver(LPCWSTR lpszSrvName)
{
    SC_HANDLE schManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schManager)
    {
        printf("OpenSCManagerW fail, errcode= %d\n", GetLastError());
        return false;
    }
    SC_HANDLE schService = OpenServiceW(schManager, lpszSrvName, SERVICE_ALL_ACCESS);
    if (NULL == schService)
    {
        printf("OpenServiceW fail, errcode= %d\n", GetLastError());
        CloseServiceHandle(schManager);
        return false;
    }

    SERVICE_STATUS svcStatus;
    ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus);
    if (!DeleteService(schService))
    {
        printf("DeleteService fail, errcode= %d\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        return false;
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);

    return true;
}