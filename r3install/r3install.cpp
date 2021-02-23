// r3install.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>
#include "SrvControl.h"

#define DRIVER_NAME     L"drvtest"
#define DRIVER_PATH     L".\\drvtest.sys"
#define DRIVER_ALTITUDE	L"370060"

int main()
{
    std::cout << "Hello World!\n";

    printf("Print any key to install driver\n");
    getchar();

    //启动一次服务以便判断需不需要安装驱动
    bool bRet = StartDriver(DRIVER_NAME);
    if (bRet == false)
    {
        bRet = InstallDriver(DRIVER_NAME, DRIVER_PATH/*, DRIVER_ALTITUDE*/);
        if (bRet == false)
        {
            printf("Driver install failed\n");
            return -1;
        }

        //启动驱动调用这个函数
        bRet = StartDriver(DRIVER_NAME);
        if (bRet == false)
        {
            printf("StartDriver failed\n");
            return -1;
        }
    }
    else
    {
        printf("Driver is already exist. Now driver start succeed\n");
    }

    printf("Print any key to stop driver\n");
    getchar();

    //停止驱动调用这个
    if (StopDriver(DRIVER_NAME))
        printf("StopDriver Success\n");
    else
        printf("StopDriver fail\n");

    //删除服务调用这个
    if (DeleteDriver(DRIVER_NAME))
        printf("DeleteDriver Success\n");
    else
        printf("DeleteDriver fail\n");
    getchar();
}