/*++
	参考: https://blog.csdn.net/weixin_44286745/article/details/104298132
	win10x64 ssdt获取，windbg下：dqs KeServiceDescriptorTable
	author： 
--*/

#include "ssdt.h"
#include<ntifs.h>
#include<ntddk.h>
#include <intrin.h>
#pragma intrinsic(__readmsr)

PSYSTEM_SERVICE_TABLE gSt = nullptr;
ULONG64 SSDT_GetPfnAddr(ULONG dwIndex)
{
    if (gSt == nullptr)
        return 0;

    PULONG lpBase = gSt->ServiceTableBase;
   // ULONG dwCount = gSt->NumberOfServices;
    ULONG64 lpAddr = NULL;
    ULONG dwOffset = lpBase[dwIndex];

    // SAR这个指令, 以及右移4位, 决定了0xF0000000这个值。
    if (dwOffset & 0x80000000)
        dwOffset = (dwOffset >> 4) | 0xF0000000;
    else
        dwOffset >>= 4;

    lpAddr = (ULONG64)((PUCHAR)lpBase + (LONG)dwOffset);

    return lpAddr;
}

ULONGLONG GetKeServiceDescriptorTable()
{
	if (gSt != nullptr)
		return (ULONGLONG)gSt;

	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);//0x16A000是取的一个偏移量
	PUCHAR EndSearchAddress = StartSearchAddress + 0x200;//通常搜索范围在500字节就够了
	PUCHAR i = NULL;
	UCHAR a = 0, b = 0, c = 0;//a,b,c用来存储特征字节
	ULONG Temp = 0;
	ULONGLONG addr = 0;

	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		//使用MmIsAddressValid()函数检查地址是否有页面错误，但是微软并不建议使用此函数
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			a = *i;
			b = *(i + 1);
			c = *(i + 2);
			//对比特征值
			//fffff804`2f678184 4c8d15f5663900  lea     r10,[nt!KeServiceDescriptorTable (fffff804`2fa0e880)]
			//fffff804`2f67818b 4c8d1deee73700  lea     r11, [nt!KeServiceDescriptorTableShadow(fffff804`2f9f6980)]

			//nt!KiSystemServiceRepeat:
			//fffff803`68a0a2a4 4c8d15d5e52700  lea     r10, [nt!KeServiceDescriptorTable(fffff803`68c88880)]
			//fffff803`68a0a2ab 4c8d1d4eb22600  lea     r11, [nt!KeServiceDescriptorTableShadow(fffff803`68c75500)]
			//fffff803`68a0a2b2 f7437840000000  test    dword ptr[rbx + 78h], 40h
			//fffff803`68a0a2b9 7413            je      nt!KiSystemServiceRepeat + 0x2a (fffff803`68a0a2ce)  Branch

			if (a == 0x4c && b == 0x8d && c == 0x15)
			{
				memcpy(&Temp, i + 3, 4);
				addr = (ULONGLONG)Temp + (ULONGLONG)i + 7;
				dprint(" KeServiceDescriptorTable addr：0x%p \r\n", addr);
				return addr;
			}
		}
	}
	return  0;
}

KIRQL CloseProtect()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	ULONG_PTR cr0 = __readcr0();

	cr0 &= 0xfffffffffffeffff;
	_disable();
	__writecr0(cr0);

	return irql;
}

VOID OpenProtect(KIRQL irql)
{

	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
	_enable();

	KeLowerIrql(irql);
}

/*
要改写的指令长度网上一些方法是用LDE这个反编译引擎计算，但有时候这并不靠谱，比如我在HOOK NtOpenProcess的时候
发现需要改写的字节数为20，但LDE只算出了16，导致跳回原函数的地址与实际我们需要的地址差4个字节
这里的 原函数 是用来储存原API函数被修改掉的函数的指令及，后面需要调用它跳回原API函数
*/
VOID StartHook(UINT64 hookaddr, UINT64 newaddr, USHORT modifylen, PVOID* orifunc)
{
	UCHAR jmpnew[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	UCHAR jmpori[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	memcpy(jmpnew + 6, &newaddr, 8);

	/*
	下面的数值14是跳转指令的总长度 假设该指令地址为0x410000
	0x410000 jmp qword ptr [0x410006]
	0x410006 xxxxxxxx
	其中0x410006中储存代理函数的地址
	*/
	UINT64 jmporiaddr = hookaddr + modifylen;
	memcpy(jmpori + 6, &jmporiaddr, 8);
	*orifunc = ExAllocatePool(NonPagedPool, modifylen + 14);
	RtlFillMemory(*orifunc, modifylen + 14, 0x90);

	KIRQL irql = CloseProtect();
	memcpy(*orifunc, (PVOID)hookaddr, modifylen);
	memcpy((PCHAR)(*orifunc) + modifylen, jmpori, 14);

	KIRQL dpc_irql = KeRaiseIrqlToDpcLevel();
	RtlFillMemory((void*)hookaddr, modifylen, 0x90);
	memcpy((PVOID)hookaddr, &jmpnew, 14);
	KeLowerIrql(dpc_irql);
	OpenProtect(irql);
}

VOID StopHook(UINT64 hookaddr, USHORT modifylen, PVOID originfunc)
{
	KIRQL irql = CloseProtect();
	memcpy((PVOID)hookaddr, originfunc, modifylen);
	OpenProtect(irql);
	ExFreePool(originfunc);
}


PVOID S_OpenProcess;
PVOID S_ReadVritualMemory;

//要HOOK的函数原型声明，win x64系统的API函数调用约定为__fastcall
typedef NTSTATUS(__fastcall* pMyOpenProcess)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess,\
	IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId OPTIONAL);
typedef NTSTATUS(__fastcall* pMyReadVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress,\
	OUT PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL);


NTSTATUS MyOpenProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId OPTIONAL)
{
	PEPROCESS process = 0;
	if (STATUS_SUCCESS == PsLookupProcessByProcessId(ClientId->UniqueProcess, &process))
	{
		if (strcmp(PsGetProcessImageFileName(process), "instdrv.exe") == 0)
		{
			//KdBreakPoint();
			KdPrint(("受保护进程：%s", PsGetProcessImageFileName(process)));
			return STATUS_PNP_INVALID_ID;
		}
	}

	return ((pMyOpenProcess)S_OpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS MyReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS    status;
	PEPROCESS   process;

	//KdBreakPoint();

	status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		(PVOID*)&process,
		NULL);
	if (NT_SUCCESS(status))
	{
		KdPrint((PsGetProcessImageFileName(process)));
	}
	return ((pMyReadVirtualMemory)S_ReadVritualMemory)(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
}
void Test_SsdtHook()
{
	KdBreakPoint();
	gSt = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable();

	{
		UINT64 a = SSDT_GetPfnAddr(38);
		UNICODE_STRING FuncName;

		RtlInitUnicodeString(&FuncName, L"NtOpenProcess");
		PUCHAR pAddr = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);
		dprint("NtOpenProcess addr=0x%p, a=0x%p \r\n", pAddr, a);

	}


	//调用例子：inlinehook NtOpenProcess实现防止“NewTzmTool.exe”的进程被OpenProcess
	//	inlinehook NtReadVirtualMemory，有程序调用ReadProcessMemory时显示被读取得程序的名字

	StartHook(SSDT_GetPfnAddr(63), (UINT64)&MyReadVirtualMemory, 17, &S_ReadVritualMemory);
	StartHook(SSDT_GetPfnAddr(38), (UINT64)&MyOpenProcess, 20, &S_OpenProcess);

	{
		UINT64 a = SSDT_GetPfnAddr(38);
		UNICODE_STRING FuncName;

		RtlInitUnicodeString(&FuncName, L"NtOpenProcess");
		PUCHAR pAddr = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);
		dprint("NtOpenProcess2 addr=0x%p, a=0x%p \r\n", pAddr,a);
	}
	//卸载
	//
}
void Test_UnSsdtHook()
{
	StopHook(SSDT_GetPfnAddr(63), 17, S_ReadVritualMemory);
	StopHook(SSDT_GetPfnAddr(38), 20, S_OpenProcess);
}