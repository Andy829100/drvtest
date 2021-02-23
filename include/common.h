#ifndef __COMMON_H__
#define __COMMON_H__

// device name
#define DEVICE_SHORT_NAME	L"drvtest"
#define R0_DEVICE_NAME			(L"\\Device\\" DEVICE_SHORT_NAME)

// sym name
#define SYM_SHORT_NAME			L"drvsym"
#define R0_SYM_NAME				(L"\\??\\" SYM_SHORT_NAME)
#define R3_SYM_NAME				(L"\\\\.\\" SYM_SHORT_NAME)



#define FMG_CTL_CODE(x) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + x, METHOD_NEITHER, FILE_ANY_ACCESS)

// ¿ØÖÆÃüÁî1
#define SEND_CMD FMG_CTL_CODE(0)

// ¿ØÖÆÃüÁî2
#define SEND_CMD2 FMG_CTL_CODE(1)

// ¿ØÖÆÃüÁî3
#define SEND_CMD3 FMG_CTL_CODE(2)










#endif
