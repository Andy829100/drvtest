#ifndef __SSDT_H__
#define __SSDT_H__
#include "pch.h"




typedef struct _SYSTEM_SERVICE_TABLE {
	PULONG  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;


ULONG64 SSDT_GetPfnAddr(ULONG dwIndex);
ULONGLONG GetKeServiceDescriptorTable();
KIRQL CloseProtect();
VOID OpenProtect(KIRQL irql);

void Test_SsdtHook();
void Test_UnSsdtHook();
#endif