#pragma once
#ifndef __SRVCONTROL_H__
#define __SRVCONTROL_H__

bool InstallDriver(LPCWSTR lpszSrvName, LPCWSTR lpszFilePath, LPCWSTR lpszAltitude = NULL);
bool StartDriver(LPCWSTR lpszSrvName);
bool StopDriver(LPCWSTR lpszSrvName);
bool DeleteDriver(LPCWSTR lpszSrvName);


#endif
