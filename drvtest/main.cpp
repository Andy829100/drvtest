/*++
	�����Ǹ����Գ������ڸ�������һЩ���ܽӿ�

--*/

#include "pch.h"
#include "util.h"
#include "GetUnExportsFuncAddr.h"
#include "ssdt.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, DispatchDefault)
#pragma alloc_text(PAGE, DispatchDevIoCtrl)
#pragma alloc_text(PAGE, CreateTestThread)
#pragma alloc_text(PAGE, TestThreadProc)
#pragma alloc_text(PAGE, CreateDevice)
#pragma alloc_text(PAGE, ObRegisterProcessCB)
#pragma alloc_text(PAGE, ObUnRegisterProcessCB)
#pragma alloc_text(PAGE, preOBProcessCall)

#endif

// A pool tag for this module
static const ULONG gnMemPoolTag = 'TSET';

// void* ���͵ı�����ObRegisterCallbacks�����ĵڶ���������
PVOID gOBHandle = nullptr;

// global variable
PETHREAD gpThreadObj = NULL;
bool gbStopped = false;

void test2()
{

	/*while (1)
	{
		v12 = PsGetNextProcess(v11);
		v13 = v12;
		if (!v12)
			break;
		
		v11 = v13;
	}*/

}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	// UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;

	// KdBreakPoint();
	dprint("Start DriverEntry(): regpath= %wZ\n", RegistryPath);

	if (*InitSafeBootMode == 0) {
		dprint("��ǰ��ȫģʽ�����˳�(*InitSafeBootMode == %u)\n", (ULONG)*InitSafeBootMode);
		return STATUS_UNSUCCESSFUL;
	}

	// ��ʼ����־
#ifndef DISABLE_WRITE_LOG_FILE
	status = LogInitialization(kLogPutLevelDebug, L"\\??\\c:\\drvtest.txt");
	if (!NT_SUCCESS(status))
	{
		dprint("%s", "LogInitialization fail\n");
		return status;
	}
#endif

	//IRP_MJ_MAXIMUM_FUNCTION
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchDefault;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchDefault;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = DispatchDefault;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDevIoCtrl;
	DriverObject->DriverUnload = DriverUnload;

	// ��ȡ��ǰϵͳ�汾
	RTL_OSVERSIONINFOW osver;
	RtlZeroMemory(&osver, sizeof(osver));
	osver.dwOSVersionInfoSize = sizeof(osver);
	status = RtlGetVersion(&osver);
	ASSERT(NT_SUCCESS(status));
	if (!NT_SUCCESS(status))
	{
		dprint("RtlGetVersion fail= 0x%x\n", status);
		return status;
	}

	dprint("RtlGetVersion: dwMajor=%u,dwMinor=%u,dwBuildnum=%u,dwPlatID=%u,szCSDV=%ws\n", \
		osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber, osver.dwPlatformId, osver.szCSDVersion);

	// ���������߳�
	/*status = CreateTestThread();
	ASSERT(NT_SUCCESS(status));
	if (!NT_SUCCESS(status))
	{
		dprint("CreateTestThread fail= 0x%x\n", status);
		return status;
	}*/

	// �����豸�ͷ�������
	status = CreateDevice(DriverObject, R0_DEVICE_NAME, R0_SYM_NAME);
	ASSERT(NT_SUCCESS(status));
	if (!NT_SUCCESS(status))
	{
		dprint("CreateDevice fail= 0x%x\n", status);
		return status;
	}

	status = IoRegisterShutdownNotification(DriverObject->DeviceObject);
	if (!NT_SUCCESS(status))
	{
		dprint("IoRegisterShutdownNotification fail= 0x%x\n", status);
		return status;
	}


	// ��̷�ʽ�ƹ�ǩ�����
	BypassCheckSign(DriverObject);

#if 0
	// ���̱���
	status = ObRegisterProcessCB();
	if (!NT_SUCCESS(status))
	{
		LOG_ERROR("ObRegisterProcessCB fail, status= 0x%x", status);
		return status;
	}
#endif 

	// ������ж�� CPU
	// test();

	// ����WIN10 64λ SSDT INLINE HOOK
	Test_SsdtHook();

	dprint("DriverEntry end\n");
	return status;
}

OB_PREOP_CALLBACK_STATUS preOBProcessCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext );
	UNREFERENCED_PARAMETER(pOperationInformation);
	/*
	UNREFERENCED_PARAMETER(RegistrationContext);
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	PUCHAR szProcName = PsGetProcessImageFileName((PEPROCESS)pOperationInformation->Object);
	//if (IsProtectProc((ULONG)(ULONG_PTR)pid, szProcName))
	if (0);
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				LOG_INFO("���б����Ľ��̣���ֹ��ֹ[%s][pid=%u][OriginalDesiredAccess=0x%x]", \
					szProcName, (ULONG)(ULONG_PTR)pid, pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess);

				//Terminate the process, such as by calling the user-mode TerminateProcess routine..
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			//if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			//{
			//	LOG_INFO("preCall: PROCESS_VM_OPERATION");
			//	//Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
			//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			//}
			//if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			//{
			//	LOG_INFO("preCall: PROCESS_VM_READ");
			//	//Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
			//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			//}
			//if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			//{
			//	LOG_INFO("preCall: PROCESS_VM_WRITE");
			//	//Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
			//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			//}
		}
	}
	*/
	return OB_PREOP_SUCCESS;
}

NTSTATUS ObRegisterProcessCB()
{
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	memset(&opReg, 0, sizeof(opReg)); //��ʼ���ṹ�����

	//������ע������ṹ��ĳ�Ա�ֶε�����
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preOBProcessCall; //������ע��һ���ص�����ָ��

	obReg.OperationRegistration = &opReg; //ע����һ�����

	return ObRegisterCallbacks(&obReg, &gOBHandle); //������ע��ص�����
}

VOID ObUnRegisterProcessCB()
{
	if (gOBHandle)
	{
		ObUnRegisterCallbacks(gOBHandle);
		gOBHandle = nullptr;
	}
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	dprint("DriveUnLoad start\n");
	// KdBreakPoint();

	PDEVICE_OBJECT pNextObj = pDriverObj->DeviceObject;
	while (pNextObj != NULL)
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pNextObj->DeviceExtension;
		IoDeleteSymbolicLink(&pDevExt->ustrSymlinkName);
		pNextObj = pNextObj->NextDevice;
		IoUnregisterShutdownNotification(pDevExt->pDevice);
		IoDeleteDevice(pDevExt->pDevice);
	}
#if 0
	ObUnRegisterProcessCB();
#endif

	// ж�� SSDT INLINE HOOK
	Test_UnSsdtHook();

#ifndef DISABLE_WRITE_LOG_FILE
	LogTermination();
#endif
	dprint("DriveUnLoad end\n");
}

NTSTATUS  DispatchDefault(
	struct _DEVICE_OBJECT* DeviceObject,
	struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);
	dprint("DispatchDefault: 0x%p, %u ,%u\n", DeviceObject, pStack->MajorFunction, pStack->MinorFunction);

	PAGED_CODE();

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS  DispatchDevIoCtrl(
	struct _DEVICE_OBJECT* DeviceObject,
	struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIroStack = IoGetCurrentIrpStackLocation(Irp);

	//�õ�IOCTL�� 
	ULONG code = pIroStack->Parameters.DeviceIoControl.IoControlCode;

	PAGED_CODE();

	// �õ����뻺�����Ĵ�С 
	// ULONG cbin = stack->Parameters.DeviceIoControl.InputBufferLength;
	// �õ�����������Ĵ�С 
	// ULONG cbout = stack->Parameters.DeviceIoControl.OutputBufferLength;

	// 1����������ʽ
	// Irp->AssociatedIrp.SystemBuffer

	// 2��ֱ��ģʽ
	// Irp->MdlAddress
	// MmGetSystemAddressForMdlSafe(Irp->MdlAddress,NormalPagePriority);

	// 3���Բ���ģʽ
	// ����
	//pIroStack->Parameters.DeviceIoControl.OutputBufferLength;
	//pIroStack->Parameters.DeviceIoControl.Type3InputBuffer;
	// ���
	//Irp->UserBuffer;
	
	switch (code)
	{
	case SEND_CMD:
	{
		DbgPrint("����deviceiocontrol��SEND_CMD\r\n");
		break;
	}
	case SEND_CMD2:
	{
		DbgPrint("����deviceiocontrol��SEND_CMD2\r\n");
		gbStopped = true;
		break;
	}
	default:
		status = STATUS_INVALID_VARIANT;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject, PCWSTR pDevName, PCWSTR pSymName)
{
	dprint("%ws: driverobject= 0x%p, devname->%ws,symname->%ws\n",__FUNCTIONW__, pDriverObject, pDevName, pSymName);
	PAGED_CODE();

	NTSTATUS status;
	PDEVICE_OBJECT pDevObj = nullptr;
	PDEVICE_EXTENSION pDevExt = nullptr;

	UNICODE_STRING ustrDevName, ustrSymName;
	RtlInitUnicodeString(&ustrDevName, pDevName);
	RtlInitUnicodeString(&ustrSymName, pSymName);

	ULONG nDevSize = sizeof(DEVICE_EXTENSION);
	status = IoCreateDevice(pDriverObject,
		nDevSize,
		&ustrDevName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE, /*�Ƿ��ռ�豸*/
		&pDevObj);
	if (!NT_SUCCESS(status))
	{
		dprint("IoCreateDevice Error[0x%X]\n", status);
		return status;
	}
	pDevObj->Flags |= DO_BUFFERED_IO; //DO_DIRECT_IO;// 

	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->pDevice = pDevObj;

	dprint("CreateDevice: pDevObj= %p, DriverObject->dev= %p\n", pDevObj, pDriverObject->DeviceObject);

	// TODO : ִ��ʧ��
	RtlCopyUnicodeString(&pDevExt->ustrDeviceName, &ustrDevName);
	RtlCopyUnicodeString(&pDevExt->ustrSymlinkName, &ustrSymName);
	
	status = IoCreateSymbolicLink(&ustrSymName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteSymbolicLink(&ustrSymName);
		status = IoCreateSymbolicLink(&ustrSymName, &ustrDevName);
		if (!NT_SUCCESS(status))
		{
			dprint("IoCreateSymbolicLink Error[0x%X]\n", status);
			IoDeleteDevice(pDevObj);
			return status;
		}
	}

	// ��������豸�Ѿ�������
	pDevObj->Flags &= ~DO_DEVICE_INITIALIZING;
	return status;
}
VOID TestThreadProc(IN PVOID context)
{
	UNREFERENCED_PARAMETER(context);
	dprint("TestThreadProc Start, PID = %u\n", HandleToULong(PsGetCurrentThreadId()));

	/*PEPROCESS EProcess;
	PsLookupProcessByProcessId(ProcessId, &EProcess);*/

	PEPROCESS pCurrentProcess = NULL;
	PEPROCESS pFirstProcess = NULL;

	char* ProcessName;
	ULONG PID;
	LARGE_INTEGER inteval;
	inteval.QuadPart = -10000 * 1000 * 10;  // 10 ��

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	do
	{
		if (gbStopped)
		{
			break;
		}

		pCurrentProcess = IoGetCurrentProcess();
		pFirstProcess = pCurrentProcess;

		//  ����ϵͳwin7 64λ �� ���̽ṹƫ��  ���£�
		//  +0x2e0 ImageFileName		//������ ƫ��
		//  +0x188 ActiveProcessLinks	//����������һ�� ���̽ṹ  ƫ��
		//  +0x1f0 DebugPort			//��˵�еĵ��Զ˿� ƫ��

		//  ����ϵͳwin7 32λ �� ���̽ṹƫ��  ���£�
		//  +0x16c ImageFileName		//������ ƫ��
		//  +0x0b8 ActiveProcessLinks	//����������һ�� ���̽ṹ  ƫ��
		//  +0x0ec DebugPort			//��˵�еĵ��Զ˿� ƫ��

		//����ϵͳxp sp3 ��Ľ��̽ṹƫ��  ����
		//  +0x174 ImageFileName		//������ ƫ��
		//  +0x088 ActiveProcessLinks	//����������һ�� ���̽ṹ  ƫ��
		//  +0x0bc DebugPort			//��˵�еĵ��Զ˿� ƫ��

		//������ActiveProcessLinks ��������ַ��������ÿһ�����̵Ľ��̽ṹPEPROCES �壬Ҳ���ǽ��̽ṹ�Ļ�ַ��
		//Ȼ������ ���̽ṹ�Ļ�ַ+ƫ��������ʽ��ȡ�ṹ���ڲ��ĸ��ֱ��������������ImageFileName   �����̵��Զ˿� DebugPort  ��
		//��Ȼ���ﻹ��һ��С�ջ񣬾������ݽ��̽ṹ������ȡ���̵�pidֵ���� �ں˺���PsGetProcessId��ȡPID.

#ifdef _WIN64
		// win7 64
		ULONG uOffsetImageFileName = 0x2e0;
		ULONG uOffsetActiveProcessLinks = 0x188;
		ULONG uOffsetDebugPort = 0x1f0;

#else
		// win7 32
		ULONG uOffsetImageFileName = 0x16c;
		ULONG uOffsetActiveProcessLinks = 0x0b8;
		ULONG uOffsetDebugPort = 0x0ec;
#endif

		PUCHAR ptr = (PUCHAR)((ULONG_PTR)pCurrentProcess + uOffsetImageFileName);
		while (RtlCompareMemory("mytest.exe", ptr, 10) != 10)
		{
			pCurrentProcess = (PEPROCESS)(*(PULONG_PTR)((ULONG_PTR)pCurrentProcess + uOffsetActiveProcessLinks) - uOffsetActiveProcessLinks);
			//�жϵ�һ�����̽ṹ��һ���໥������һ���һ�������������жϵ������һ�����̽ṹ��ʱ���˵����һ�ν��̱�������ˡ�
			if (pCurrentProcess == pFirstProcess)
			{
				dprint("������������������˳������������\n");
				goto END;
			}
			ptr = (PUCHAR)((ULONG_PTR)pCurrentProcess + uOffsetImageFileName);
		}

		//����������ȼ���� debug�˿ڱ������ڴ��ַ��Ȼ����ǿ��ת��Ϊ�������ڴ��ַ����ν��ָ�롣
		//Ȼ���޸��ڴ��ַ�ϵ���ֵ���޸�Ϊ0���ɡ�

		*(PULONG_PTR)((ULONG_PTR)pCurrentProcess + uOffsetDebugPort) = 0;//debug�˿����㣨���Ĵ������һ�䣬��OD�ϵ�û��Ӧ���򱨴�

		//��������ǻ�ȡ���������������ڽ��̽ṹ�е�ƫ����Ϊ+ 0x16C 
		ProcessName = (char*)((ULONG_PTR)pCurrentProcess + uOffsetImageFileName);
		//�������о� ��Ѷ��debug�˿���0�ķ�������������ż���ڲ��ĵ����ϵ�ʱ���ֻ����Ի�ȡ����PID������

		PID = (ULONG)(ULONG_PTR)PsGetProcessId(pCurrentProcess);//PsGetProcessId�������ݽ��̽ṹ���ȡ����PID��ֵ

		dprint("Debug�˿�����ɹ����������Ľ�����Ϊ: %s  ����PIDΪ:%d\n", ProcessName, PID);

	END:
		KeDelayExecutionThread(KernelMode, FALSE, &inteval);
	} while (true);

	PsTerminateSystemThread(STATUS_SUCCESS);
}
NTSTATUS  CreateTestThread()
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjAddr = { 0 };
	HANDLE hThread = nullptr;

	InitializeObjectAttributes(&ObjAddr, NULL, OBJ_KERNEL_HANDLE, 0, NULL);

	/// ����һ���߳�
	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &ObjAddr, \
		NULL, NULL, TestThreadProc, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, \
		KernelMode, (PVOID*)&gpThreadObj, NULL);
	ZwClose(hThread);

	if (!NT_SUCCESS(status))
	{
		// gbStopped = TRUE;
		dprint("ObReferenceObjectByHandle failed\n");
		return status;
	}
	return status;

}