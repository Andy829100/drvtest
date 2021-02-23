#pragma once
#include "ntddk.h"

// 单个字符的最大范围 0 - 255
static const int MAXNUM = 256;
/*
	准备数组
Param：
	@sun_shift 字符失配时右移的距离
	@p	需要匹配的字符串
	@lenP	需要匹配的字符串的长度

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
				return &T[pos]; // 匹配成功
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

