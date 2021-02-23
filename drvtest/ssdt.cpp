/*++
	�ο�: https://blog.csdn.net/weixin_44286745/article/details/104298132
	win10x64 ssdt��ȡ��windbg�£�dqs KeServiceDescriptorTable
	author�� 
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

    // SAR���ָ��, �Լ�����4λ, ������0xF0000000���ֵ��
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

	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);//0x16A000��ȡ��һ��ƫ����
	PUCHAR EndSearchAddress = StartSearchAddress + 0x200;//ͨ��������Χ��500�ֽھ͹���
	PUCHAR i = NULL;
	UCHAR a = 0, b = 0, c = 0;//a,b,c�����洢�����ֽ�
	ULONG Temp = 0;
	ULONGLONG addr = 0;

	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		//ʹ��MmIsAddressValid()��������ַ�Ƿ���ҳ����󣬵���΢��������ʹ�ô˺���
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			a = *i;
			b = *(i + 1);
			c = *(i + 2);
			//�Ա�����ֵ
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
				dprint(" KeServiceDescriptorTable addr��0x%p \r\n", addr);
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
Ҫ��д��ָ�������һЩ��������LDE���������������㣬����ʱ���Ⲣ�����ף���������HOOK NtOpenProcess��ʱ��
������Ҫ��д���ֽ���Ϊ20����LDEֻ�����16����������ԭ�����ĵ�ַ��ʵ��������Ҫ�ĵ�ַ��4���ֽ�
����� ԭ���� ����������ԭAPI�������޸ĵ��ĺ�����ָ���������Ҫ����������ԭAPI����
*/
VOID StartHook(UINT64 hookaddr, UINT64 newaddr, USHORT modifylen, PVOID* orifunc)
{
	UCHAR jmpnew[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	UCHAR jmpori[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	memcpy(jmpnew + 6, &newaddr, 8);

	/*
	�������ֵ14����תָ����ܳ��� �����ָ���ַΪ0x410000
	0x410000 jmp qword ptr [0x410006]
	0x410006 xxxxxxxx
	����0x410006�д���������ĵ�ַ
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

//ҪHOOK�ĺ���ԭ��������win x64ϵͳ��API��������Լ��Ϊ__fastcall
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
			KdPrint(("�ܱ������̣�%s", PsGetProcessImageFileName(process)));
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


	//�������ӣ�inlinehook NtOpenProcessʵ�ַ�ֹ��NewTzmTool.exe���Ľ��̱�OpenProcess
	//	inlinehook NtReadVirtualMemory���г������ReadProcessMemoryʱ��ʾ����ȡ�ó��������

	StartHook(SSDT_GetPfnAddr(63), (UINT64)&MyReadVirtualMemory, 17, &S_ReadVritualMemory);
	StartHook(SSDT_GetPfnAddr(38), (UINT64)&MyOpenProcess, 20, &S_OpenProcess);

	{
		UINT64 a = SSDT_GetPfnAddr(38);
		UNICODE_STRING FuncName;

		RtlInitUnicodeString(&FuncName, L"NtOpenProcess");
		PUCHAR pAddr = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);
		dprint("NtOpenProcess2 addr=0x%p, a=0x%p \r\n", pAddr,a);
	}
	//ж��
	//
}
void Test_UnSsdtHook()
{
	StopHook(SSDT_GetPfnAddr(63), 17, S_ReadVritualMemory);
	StopHook(SSDT_GetPfnAddr(38), 20, S_OpenProcess);
}