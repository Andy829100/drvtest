#ifndef __GETUNEXPORTSFUNADDR_H__
#define __GETUNEXPORTSFUNADDR_H__

#include "pch.h"



void test();


/*
��ȡCall�ĵ�ַ
������������������
������e8 ��ʼ�ĵ�ַ
*/
PVOID GetCallPoint(PVOID pCallPoint);

/*
��ȡδ�����������ڵ�ַ(û�м���call ����ת) �õ��ĵ�ַ��Ҫ����ƫ��
֧��ģ������ ���÷ָ�������δ֪
�������⣺�ڴ��ص�ʱ��������(������)
ʵ�ʴ˺���Ϊ��������������
������
PUNICODE_STRING pFunName : ��������(��Ҫ�ǵ�������)
PUCHAR pStartAddress: ��ʼ�����ĵ�ַ
UCHAR* pFeatureCode: ������ ���ܳ���15��
ULONG FeatureCodeNum: ���������
ULONG SerSize: ������Χ��С ���ܳ���0x1024
UCHAR SegCode: �ָ�� ����֧��ģ������
ULONG AddNum: Ĭ�Ϸ��������뿪ʼ�ĵ�ַ �����������ֵ���е���
BOOLEAN ByName: �Ƿ���ͨ������������
���أ� ʧ�ܷ���NULL �ɹ������������ĵ�ַ
*/

PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, IN PUCHAR pStartAddress, IN UCHAR* pFeatureCode, IN ULONG FeatureCodeNum, ULONG SerSize, UCHAR SegCode, ULONG AddNum, BOOLEAN ByName);

#endif // __GETUNEXPORTSFUNADDR_H__

/*
ʹ�����ӣ�
���ӣ�
nt!NtOpenProcess:
fffff800`041b62ec 4883ec38        sub     rsp,38h
fffff800`041b62f0 65488b042588010000 mov   rax,qword ptr gs:[188h]
fffff800`041b62f9 448a90f6010000  mov     r10b,byte ptr [rax+1F6h]
fffff800`041b6300 4488542428      mov     byte ptr [rsp+28h],r10b
fffff800`041b6305 4488542420      mov     byte ptr [rsp+20h],r10b <--���ʹ��44 ?? ?? ?? ?? e8 �������� ��ʧ�� ԭ����ǰ�������44 ���������볤�ȴ����˴˶δ��� �������ڴ��ص�
fffff800`041b630a e851fcffff      call    nt!PsOpenProcess (fffff800`041b5f60) <-- ʹ��e8��ͷ��������Ͳ�����ڴ�����
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