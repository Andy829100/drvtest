#ifndef __GETUNEXPORTSFUNADDR_H__
#define __GETUNEXPORTSFUNADDR_H__

#include "pch.h"



void test();


/*
获取Call的地址
考虑了向上跳的问题
参数：e8 开始的地址
*/
PVOID GetCallPoint(PVOID pCallPoint);

/*
获取未导出函数所在地址(没有计算call 和跳转) 得到的地址需要计算偏移
支持模糊搜索 可用分隔符代替未知
存在问题：内存重叠时出现问题(见例子)
实际此函数为特征码搜索函数
参数：
PUNICODE_STRING pFunName : 函数名称(需要是导出函数)
PUCHAR pStartAddress: 开始搜索的地址
UCHAR* pFeatureCode: 特征码 不能超过15个
ULONG FeatureCodeNum: 特征码个数
ULONG SerSize: 搜索范围大小 不能超过0x1024
UCHAR SegCode: 分割符 用于支持模糊搜索
ULONG AddNum: 默认返回特征码开始的地址 可利用这个数值进行调整
BOOLEAN ByName: 是否是通过函数名搜索
返回： 失败返回NULL 成功返回搜索到的地址
*/

PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, IN PUCHAR pStartAddress, IN UCHAR* pFeatureCode, IN ULONG FeatureCodeNum, ULONG SerSize, UCHAR SegCode, ULONG AddNum, BOOLEAN ByName);

#endif // __GETUNEXPORTSFUNADDR_H__

/*
使用例子：
例子：
nt!NtOpenProcess:
fffff800`041b62ec 4883ec38        sub     rsp,38h
fffff800`041b62f0 65488b042588010000 mov   rax,qword ptr gs:[188h]
fffff800`041b62f9 448a90f6010000  mov     r10b,byte ptr [rax+1F6h]
fffff800`041b6300 4488542428      mov     byte ptr [rsp+28h],r10b
fffff800`041b6305 4488542420      mov     byte ptr [rsp+20h],r10b <--如果使用44 ?? ?? ?? ?? e8 做特征码 会失败 原因是前面出现了44 并且特征码长度大于了此段代码 类似于内存重叠
fffff800`041b630a e851fcffff      call    nt!PsOpenProcess (fffff800`041b5f60) <-- 使用e8开头做特征码就不会存在此问题
fffff800`041b630f 4883c438        add     rsp,38h
fffff800`041b6313 c3              ret
UCHAR shellcode[11] =
"\xe8\x60\x60\x60\x60"
"\x48\x60\x60\x60"
"\xc3";
PVOID p = GetUndocumentFunctionAddress(NULL, (PUCHAR)0xfffff800041b62ec, shellcode, 10, 0x300, 0x60, 0, FALSE);
if (p != NULL)
{
    DbgPrint("CallFrom:0x%p -- CallPoint:0x%p\n", p, GetCallPoint(p));
}
*/