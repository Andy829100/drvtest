#ifndef __UTIL_H__
#define __UTIL_H__ 


// 进程打开权限
#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020 


typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONG64 Bitmap[20];
}KAFFINITY_EX, * PKAFFINITY_EX;


#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)

// 相当于 Sleep()，单位毫秒
VOID MySleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;		//设备名称
	UNICODE_STRING ustrSymlinkName;		//符号链接名称

}DEVICE_EXTENSION, * PDEVICE_EXTENSION;

// 编程方式绕过签名检查
BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject)
{
#ifdef _WIN64
	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG64 __Undefined1;
		ULONG64 __Undefined2;
		ULONG64 __Undefined3;
		ULONG64 NonPagedDebugInfo;
		ULONG64 DllBase;
		ULONG64 EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
		USHORT  LoadCount;
		USHORT  __Undefined5;
		ULONG64 __Undefined6;
		ULONG   CheckSum;
		ULONG   __padding1;
		ULONG   TimeDateStamp;
		ULONG   __padding2;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	//	typedef struct _LDR_DATA_TABLE_ENTRY {
	//		// 这个成员把系统所有加载(可能是停止没被卸载)已经读取到内存中 我们关系第一个，
	//		// 我们要遍历链表 双链表 不管中间哪个节点都可以遍历整个链表 本驱动的驱动对象就是一个节点
	//		LIST_ENTRY InLoadOrderLinks;
	//
	//		// 系统已经启动 没有被初始化 没有调用DriverEntry这个历程的时候 通过这个链表进程串接起来
	//		LIST_ENTRY InMemoryOrderLinks;
	//
	//		// 已经调用DriverEntry这个函数的所有驱动程序
	//		LIST_ENTRY InInitializationOrderLinks;
	//
	//		PVOID DllBase;
	//
	//		// 驱动的进入点 DriverEntry
	//		PVOID EntryPoint;
	//		ULONG SizeOfImage;
	//		UNICODE_STRING FullDllName; // 驱动的满路径
	//		UNICODE_STRING BaseDllName; // 不带路径的驱动名字
	//		ULONG Flags;
	//		USHORT LoadCount;
	//		USHORT TlsIndex;
	//		union {
	//			LIST_ENTRY HashLinks;
	//			struct s1{
	//				PVOID SectionPointer;
	//				ULONG CheckSum;
	//				};
	//			};
	//		union {
	//			struct s2{
	//				ULONG TimeDateStamp;
	//			};
	//			struct s3{
	//				PVOID LoadedImports;
	//			};
	//		};
	//} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#else
	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG unknown1;
		ULONG unknown2;
		ULONG unknown3;
		ULONG unknown4;
		ULONG unknown5;
		ULONG unknown6;
		ULONG unknown7;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#endif

	PLDR_DATA_TABLE_ENTRY pLdrData = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	pLdrData->Flags = pLdrData->Flags | 0x20;

	return TRUE;
}

_inline PMDL MyMdlAllocate(PVOID buf, ULONG length)
{
	PMDL pmdl = IoAllocateMdl(buf, length, FALSE, FALSE, NULL);
	if (pmdl == NULL)
		return NULL;
	MmBuildMdlForNonPagedPool(pmdl);
	return pmdl;
}
_inline PMDL MyMdlMemoryAllocate(ULONG length, ULONG tag)
{
	PMDL mdl;
	void* buffer = ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (buffer == nullptr)
		return NULL;
	mdl = MyMdlAllocate(buffer, length);
	if (mdl == NULL)
	{
		ExFreePool(buffer);
		return NULL;
	}
	return mdl;
}
_inline void MyMdlMemoryFree(PMDL mdl)
{
	void* buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
	IoFreeMdl(mdl);
	ExFreePool(buffer);
}







#endif

