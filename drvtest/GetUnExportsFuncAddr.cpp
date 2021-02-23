#include "GetUnExportsFuncAddr.h"
#include "string.h"

typedef __int64 (*FuncPsUpdateActiveProcessAffinity)();
void test()
{
	//	KeQueryActiveProcessorCountEx	//	找到 KeNumberProcessors
	//	KeQueryActiveProcessorAffinity  //	找到 KeActiveProcessors
	//	KeStartDynamicProcessor			//	找到 PsUpdateActiveProcessAffinity

	PUCHAR pAddr = nullptr;
	PUCHAR pAddr2 = nullptr;
	PUCHAR pFuncAddr = nullptr;
	UNICODE_STRING FuncName;

	RtlInitUnicodeString(&FuncName, L"KeQueryActiveProcessorCountEx");
	pAddr = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);
	dprint("KeQueryActiveProcessorCountEx addr=0x%p \r\n", pAddr);

	RtlInitUnicodeString(&FuncName, L"KeQueryActiveProcessorAffinity");
	pAddr2 = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);
	dprint("KeQueryActiveProcessorAffinity addr=0x%p \r\n", pAddr2);

	RtlInitUnicodeString(&FuncName, L"KeStartDynamicProcessor");
	pFuncAddr = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);
	dprint("KeStartDynamicProcessor addr=0x%p \r\n", pFuncAddr);

	// 搜索硬编码
	//ULONG_PTR addr = 0;
	//ULONG code1 = 0xac2b0300, code2 = 0x8bc3eb05;
	//ULONG_PTR i = 0;
	//for (i = (ULONG_PTR)pFuncAddr;; i++)
	//{
	//	if (MmIsAddressValid((PULONG)i))
	//	{  //蓝屏原因：搜索到之后就应该退出,少句代码return address
	//		if ((*(PULONG)i == code1) && (*(PULONG)(i + 4) == code2))
	//		{
	//			addr = (ULONG_PTR)i;
	//			dprint("[GetPspTerminateProcess] address :0x%x\n", addr);  //打印地址
	//			break;
	//		}
	//	}
	//}


    UNICODE_STRING usFunc = { 0 };
    /*nt!KeStartDynamicProcessor:
      fffff800`1d93d740 48895c2408      mov     qword ptr[rsp + 8], rbx
      fffff800`1d93d745 4889742410      mov     qword ptr[rsp + 10h], rsi
      ......
      fffff800`1d93d7c2 e8a1a4b4ff      call    nt!PnpInitializeProcessor(fffff800`1d487c68)
      fffff800`1d93d7c7 e8ac2b0300      call    nt!PsUpdateActiveProcessAffinity(fffff800`1d970378)

      fffff800`1d93d7cc 8bc3            mov     eax, ebx
      fffff800`1d93d7ce eb05            jmp     nt!KeStartDynamicProcessor + 0x95 (fffff800`1d93d7d5)  Branch

      fffff800`1d93d7d0 b8010000c0      mov     eax, 0C0000001h

      fffff800`1d93d7d5 488b5c2430      mov     rbx, qword ptr[rsp + 30h]
      fffff800`1d93d7da 488b742438      mov     rsi, qword ptr[rsp + 38h]
      fffff800`1d93d7df 4883c420        add     rsp, 20h
      fffff800`1d93d7e3 5f              pop     rdi
      fffff800`1d93d7e4 c3              ret*/
#if 1
    UCHAR shellcode[10] =
        "\xe8\xac\x2b\x03\x00"
        "\x8b\xc3"
        "\xeb\x05";
#else

    /*nt!PsUpdateActiveProcessAffinity:
    fffff803`3aee2378 48895c2408      mov     qword ptr[rsp + 8], rbx
    fffff803`3aee237d 4889742410      mov     qword ptr[rsp + 10h], rsi
    fffff803`3aee2382 57              push    rdi*/

        UCHAR shellcode[12] =
        "\x48\x89\x5c\x24\x08"
        "\x48\x89\x74\x24\x10";
        "\x57";

#endif
#if 1
    KdBreakPoint();

    if (pFuncAddr == NULL || !MmIsAddressValid(pFuncAddr))
        return;

    int sun_shift[MAXNUM];
    SundayPre(sun_shift, shellcode, 9);
    PCUCHAR p = SundaySearch(pFuncAddr, 0x100, shellcode, 9, sun_shift);
    
    __try
    {
        PCUCHAR p2 = (p + 5) + *(PULONG)(p + 1);
        FuncPsUpdateActiveProcessAffinity func = (FuncPsUpdateActiveProcessAffinity)p2;
        _int64 nRet = func();
        dprint("PsUpdateActiveProcessAffinity ,func= 0x%p ,nRet=%I64d \r\n", func, nRet);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        dprint("PsUpdateActiveProcessAffinity ,func= 0x%p\r\n", pFuncAddr);
    }
    //HalRequestSoftwareInterrupt

#else
    PVOID p = GetUndocumentFunctionAddress(NULL, (PUCHAR)pFuncAddr, shellcode, 9, 0x300, 0x60, 0, FALSE);
    if (p != NULL)
    {
        DbgPrint("CallFrom:0x%p -- CallPoint:0x%p\n", p, GetCallPoint(p));
    }
    else
        DbgBreakPoint();
#endif

}


#pragma warning(disable : 4047)

PVOID GetCallPoint(PVOID pCallPoint)
{
    ULONG dwOffset = 0;
    ULONG_PTR returnAddress = 0;
    LARGE_INTEGER returnAddressTemp = { 0 };
    PUCHAR pFunAddress = NULL;

    if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))
        return NULL;

    pFunAddress = (PUCHAR)pCallPoint;
    // 函数偏移
    RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 1), sizeof(ULONG));

    // JMP向上跳转
    if ((dwOffset & 0x10000000) == 0x10000000)
    {
        dwOffset = dwOffset + 5 + (ULONG)(ULONG_PTR)pFunAddress;
        returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;
        returnAddressTemp.LowPart = dwOffset;
        returnAddress = returnAddressTemp.QuadPart;
        return (PVOID)returnAddress;
    }

    returnAddress = (ULONG_PTR)dwOffset + 5 + (ULONG_PTR)pFunAddress;
    return (PVOID)returnAddress;

}

PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, IN PUCHAR pStartAddress,\
            IN UCHAR* pFeatureCode, IN ULONG FeatureCodeNum, ULONG SerSize, \
            UCHAR SegCode, ULONG AddNum, BOOLEAN ByName)
{
    UNREFERENCED_PARAMETER(SegCode);
    ULONG dwIndex = 0;
    PUCHAR pFunAddress = NULL;
    ULONG dwCodeNum = 0;

    if (pFeatureCode == NULL)
        return NULL;

    if (FeatureCodeNum >= 15)
        return NULL;

    if (SerSize > 0x1024)
        return NULL;

    if (ByName)
    {
        if (pFunName == NULL || !MmIsAddressValid(pFunName->Buffer))
            return NULL;

        pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName);
        if (pFunAddress == NULL)
            return NULL;
    }
    else
    {
        if (pStartAddress == NULL || !MmIsAddressValid(pStartAddress))
            return NULL;

        pFunAddress = pStartAddress;
    }

    for (dwIndex = 0; dwIndex < SerSize; dwIndex++)
    {
        __try
        {
            if (pFunAddress[dwIndex] == pFeatureCode[dwCodeNum] /*|| pFeatureCode[dwCodeNum] == SegCode*/)
            {
                dwCodeNum++;

                if (dwCodeNum == FeatureCodeNum)
                    return pFunAddress + dwIndex - dwCodeNum + 1 + AddNum;

                continue;
            }

            dwCodeNum = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    return 0;
}
