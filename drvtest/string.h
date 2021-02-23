#pragma once
#include "ntddk.h"

// �����ַ������Χ 0 - 255
static const int MAXNUM = 256;
/*
	׼������
Param��
	@sun_shift �ַ�ʧ��ʱ���Ƶľ���
	@p	��Ҫƥ����ַ���
	@lenP	��Ҫƥ����ַ����ĳ���

*/
void SundayPre(int sun_shift[], PCUCHAR p, int lenP)
{
	int i;
	for (i = 0; i < MAXNUM; ++i)
	{
		sun_shift[i] = lenP + 1;
	}
	for (i = 0; i < lenP; ++i)
	{
		sun_shift[p[i]] = lenP - i;
	}
}
PCUCHAR SundaySearch(PCUCHAR T, int lenT, PCUCHAR p, int lenP, int shift[])
{
	int j, pos = 0;
	__try
	{
		while (pos <= lenT - lenP)
		{
			j = 0;
			while (T[pos + j] == p[j] && j < lenP)
				j++;
			if (j >= lenP)
			{
				return &T[pos]; // ƥ��ɹ�
			}
			else
			{
				pos += shift[T[pos + lenP]];
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return nullptr;
	}
	return nullptr;
}

