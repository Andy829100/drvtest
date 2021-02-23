/*++
	本例是个测试程序，用于辅助测试一些功能接口

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

// void* 类型的变量，ObRegisterCallbacks函数的第二个参数。
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
		dprint("当前安全模式，将退出(*InitSafeBootMode == %u)\n", (ULONG)*InitSafeBootMode);
		return STATUS_UNSUCCESSFUL;
	}

	// 初始化日志
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

	// 获取当前系统版本
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

	// 创建测试线程
	/*status = CreateTestThread();
	ASSERT(NT_SUCCESS(status));
	if (!NT_SUCCESS(status))
	{
		dprint("CreateTestThread fail= 0x%x\n", status);
		return status;
	}*/

	// 创建设备和符号链接
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


	// 编程方式绕过签名检查
	BypassCheckSign(DriverObject);

#if 0
	// 进程保护
	status = ObRegisterProcessCB();
	if (!NT_SUCCESS(status))
	{
		LOG_ERROR("ObRegisterProcessCB fail, status= 0x%x", status);
		return status;
	}
#endif 

	// 测试热卸载 CPU
	// test();

	// 测试WIN10 64位 SSDT INLINE HOOK
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
				LOG_INFO("命中保护的进程，禁止终止[%s][pid=%u][OriginalDesiredAccess=0x%x]", \
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
	memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量

	//下面请注意这个结构体的成员字段的设置
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preOBProcessCall; //在这里注册一个回调函数指针

	obReg.OperationRegistration = &opReg; //注意这一条语句

	return ObRegisterCallbacks(&obReg, &gOBHandle); //在这里注册回调函数
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

	// 卸载 SSDT INLINE HOOK
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

	//得到IOCTL码 
	ULONG code = pIroStack->Parameters.DeviceIoControl.IoControlCode;

	PAGED_CODE();

	// 得到输入缓冲区的大小 
	// ULONG cbin = stack->Parameters.DeviceIoControl.InputBufferLength;
	// 得到输出缓冲区的大小 
	// ULONG cbout = stack->Parameters.DeviceIoControl.OutputBufferLength;

	// 1、缓冲区方式
	// Irp->AssociatedIrp.SystemBuffer

	// 2、直接模式
	// Irp->MdlAddress
	// MmGetSystemAddressForMdlSafe(Irp->MdlAddress,NormalPagePriority);

	// 3、皆不是模式
	// 输入
	//pIroStack->Parameters.DeviceIoControl.OutputBufferLength;
	//pIroStack->Parameters.DeviceIoControl.Type3InputBuffer;
	// 输出
	//Irp->UserBuffer;
	
	switch (code)
	{
	case SEND_CMD:
	{
		DbgPrint("进入deviceiocontrol，SEND_CMD\r\n");
		break;
	}
	case SEND_CMD2:
	{
		DbgPrint("进入deviceiocontrol，SEND_CMD2\r\n");
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
		FALSE, /*是否独占设备*/
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

	// TODO : 执行失败
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

	// 设置这个设备已经启动。
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
	inteval.QuadPart = -10000 * 1000 * 10;  // 10 秒

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	do
	{
		if (gbStopped)
		{
			break;
		}

		pCurrentProcess = IoGetCurrentProcess();
		pFirstProcess = pCurrentProcess;

		//  操作系统win7 64位 版 进程结构偏移  如下：
		//  +0x2e0 ImageFileName		//进程名 偏移
		//  +0x188 ActiveProcessLinks	//进程链，下一个 进程结构  偏移
		//  +0x1f0 DebugPort			//传说中的调试端口 偏移

		//  操作系统win7 32位 版 进程结构偏移  如下：
		//  +0x16c ImageFileName		//进程名 偏移
		//  +0x0b8 ActiveProcessLinks	//进程链，下一个 进程结构  偏移
		//  +0x0ec DebugPort			//传说中的调试端口 偏移

		//操作系统xp sp3 版的进程结构偏移  如下
		//  +0x174 ImageFileName		//进程名 偏移
		//  +0x088 ActiveProcessLinks	//进程链，下一个 进程结构  偏移
		//  +0x0bc DebugPort			//传说中的调试端口 偏移

		//先依据ActiveProcessLinks 进程链地址来遍历出每一个进程的进程结构PEPROCES 体，也就是进程结构的基址。
		//然后依据 进程结构的基址+偏移量的形式获取结构体内部的各种变量，比如进程名ImageFileName   、进程调试端口 DebugPort  。
		//当然这里还有一个小收获，就是依据进程结构体来获取进程的pid值，用 内核函数PsGetProcessId获取PID.

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
			//判断第一个进程结构是一个相互紧挨在一起的一个”手链“。判断到起初第一个进程结构的时候就说明，一次进程遍历完成了。
			if (pCurrentProcess == pFirstProcess)
			{
				dprint("进程链表遍历结束，退出进程链表遍历\n");
				goto END;
			}
			ptr = (PUCHAR)((ULONG_PTR)pCurrentProcess + uOffsetImageFileName);
		}

		//以下这句是先计算出 debug端口变量的内存地址，然后将其强制转化为真正的内存地址即所谓的指针。
		//然后修改内存地址上的数值，修改为0即可。

		*(PULONG_PTR)((ULONG_PTR)pCurrentProcess + uOffsetDebugPort) = 0;//debug端口清零（核心代码就这一句，让OD断点没反应，或报错）

		//以下这句是获取进程名，进程名在进程结构中的偏移量为+ 0x16C 
		ProcessName = (char*)((ULONG_PTR)pCurrentProcess + uOffsetImageFileName);
		//本来是研究 腾讯的debug端口清0的反调试器技术。偶尔在查阅的资料的时候发现还可以获取进程PID，哈哈

		PID = (ULONG)(ULONG_PTR)PsGetProcessId(pCurrentProcess);//PsGetProcessId函数依据进程结构体获取进程PID数值

		dprint("Debug端口清零成功！被保护的进程名为: %s  进程PID为:%d\n", ProcessName, PID);

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

	/// 创建一个线程
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