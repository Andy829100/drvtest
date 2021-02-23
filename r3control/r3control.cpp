// r3control.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include "../include/common.h"
int main()
{
	BOOL bRet = FALSE;
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	do
	{
		printf("will open device\n");
		getchar();
		hDevice = CreateFileW(R3_SYM_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
		if (INVALID_HANDLE_VALUE == hDevice)
		{
			printf("Failed to CreateFileW device:  errcode= 0x%x\n", GetLastError());
			break;
		}

		printf("will send SEND_CMD\n");
		getchar();
		DWORD length = 0;
		bRet = DeviceIoControl(hDevice, SEND_CMD, nullptr, 0, NULL, 0, &length, NULL);
		if (!bRet)
		{
			printf("Failed to DeviceIoControl:  errcode= 0x%x\n", GetLastError());
			break;
		}

		printf("will send SEND_CMD2, stop test thread\n");
		getchar();
		bRet = DeviceIoControl(hDevice, SEND_CMD2, nullptr, 0, NULL, 0, &length, NULL);
		if (!bRet)
		{
			printf("Failed to DeviceIoControl SEND_CMD2:  errcode= 0x%x\n", GetLastError());
			break;
		}

		printf("will exit\n");
		getchar();

	} while (0);
		
	if (INVALID_HANDLE_VALUE != hDevice)
		CloseHandle(hDevice);

	return 0;
}