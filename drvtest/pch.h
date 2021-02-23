#ifndef __PCH_H__
#define __PCH_H__
#include<ntifs.h>
#include "log.h"
#include "../include/common.h"

#define DISABLE_WRITE_LOG_FILE 1

#ifdef DBG
#define dprint(Format,...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FMG: " Format, __VA_ARGS__); 
#else
#define dbprint
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif
#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

EXTERN_C_START
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);
NTSTATUS  DispatchDefault(struct _DEVICE_OBJECT* DeviceObject, struct _IRP* Irp);
NTSTATUS  DispatchDevIoCtrl(struct _DEVICE_OBJECT* DeviceObject, struct _IRP* Irp);
NTSTATUS  CreateTestThread();
VOID TestThreadProc(IN PVOID context);
NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject, PCWSTR pDevName, PCWSTR pSymName);
NTSTATUS ObRegisterProcessCB();
VOID ObUnRegisterProcessCB();
OB_PREOP_CALLBACK_STATUS preOBProcessCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);

//用到的内核函数，该函数使用前需要声明
PCHAR PsGetProcessImageFileName(PEPROCESS Process);


// 导出变量
extern POBJECT_TYPE* IoDriverObjectType;

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;
extern PULONG_PTR InitSafeBootMode;


EXTERN_C_END




















#endif
