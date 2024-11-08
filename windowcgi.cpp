/* -------------------------------------------------------------------------
//	文件名		：	windowcgi.cpp
//	创建者		：	magictong
//	创建时间	：	2016/11/16 21:24:48
//	功能描述	：	
//
//	$Id: $
// -----------------------------------------------------------------------*/

#include "stdafx.h"
#include "windowcgi.h"

#include <atlconv.h>
// -------------------------------------------------------------------------

CWinCGI::CWinCGI()
 : hStdInRead(NULL)
 , hStdInWrite(NULL)
 , hStdOutRead(NULL)
 , hStdOutWrite(NULL)
{
	 memset(&siStartInfo, 0, sizeof(siStartInfo));
	 memset(&piProcInfo, 0, sizeof(piProcInfo));
}

CWinCGI::~CWinCGI()
{
	__Reset();
}

void CWinCGI::__Reset()
{
	if (hStdInRead)
	{
		CloseHandle(hStdInRead);
		hStdInRead = NULL;
	}

	if (hStdInWrite)
	{
		CloseHandle(hStdInWrite);
		hStdInWrite = NULL;
	}

	if (hStdOutRead)
	{
		CloseHandle(hStdOutRead);
		hStdOutRead = NULL;
	}

	if (hStdOutWrite)
	{
		CloseHandle(hStdOutWrite);
		hStdOutWrite = NULL;
	}

	if (piProcInfo.hProcess)
	{
		CloseHandle(piProcInfo.hProcess);
		piProcInfo.hProcess = NULL;
	}

	if (piProcInfo.hThread)
	{
		CloseHandle(piProcInfo.hThread);
		piProcInfo.hThread = NULL;
	}
}

BOOL CWinCGI::Exec(const char* path, const char* query_string)
{
	BOOL bRet = FALSE;

	do 
	{
		if (!path)
			break;

		__Reset(); // 复位（释放资源）

		SECURITY_ATTRIBUTES saAttr = {sizeof(SECURITY_ATTRIBUTES), 0, TRUE};
		if (!CreatePipe(&hStdInRead, &hStdInWrite, &saAttr, 0))
			break;

		if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0))
			break;

		ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
		siStartInfo.cb = sizeof(STARTUPINFO);
		GetStartupInfo(&siStartInfo);
		siStartInfo.dwFlags |= STARTF_USESHOWWINDOW;
		siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
		siStartInfo.hStdOutput = hStdOutWrite;
		//siStartInfo.hStdError  =  hStdErrWrite;
		siStartInfo.hStdInput  = hStdInRead;
		siStartInfo.wShowWindow = SW_HIDE;

		WCHAR szCmd[1024] = {0};
		USES_CONVERSION;
		if (_stricmp(path, "htdocs/cgipy") == 0 && query_string)
		{
			swprintf_s(szCmd, _countof(szCmd) - 1, L"\"python.exe\"  htdocs\\cgi\\%s",  A2W(query_string));
			//wcsncpy_s(szCmd, _countof(szCmd) - 1, L"\"python.exe\"  htdocs\\cgi\\p.py", -1);
		}
		else if (_stricmp(path, "htdocs/cgibat") == 0 && query_string)
		{
			swprintf_s(szCmd, _countof(szCmd) - 1, L"\"cmd.exe\"  /c htdocs\\cgi\\%s",  A2W(query_string));
			//wcsncpy_s(szCmd, _countof(szCmd) - 1, L"\"cmd.exe\" /c ", -1);
		}
		else if (_stricmp(path, "htdocs/cgipost") == 0)
		{
			swprintf_s(szCmd, _countof(szCmd) - 1, L"\"python.exe\"  htdocs\\cgi\\%s",  L"cgipost.py");
		}
		else
		{
			break;
		}

		if (!CreateProcess(NULL, szCmd, NULL, NULL, TRUE , CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &siStartInfo, &piProcInfo))
			break;

		bRet =TRUE;
	} while (0);

	return bRet;
}

DWORD CWinCGI::Wait()
{
	return WaitForSingleObject(piProcInfo.hProcess, 5000);
}

BOOL CWinCGI::Write(PBYTE in_buffer, DWORD dwSize)
{
	if (!in_buffer || 0 == dwSize)
	{
		return FALSE;
	}

	DWORD process_exit_code = 0;
	GetExitCodeProcess(piProcInfo.hProcess, &process_exit_code);
	if (process_exit_code != STILL_ACTIVE)
		return FALSE;

	DWORD dwWritten = 0;
	BOOL bSuccess = FALSE;
	return WriteFile(hStdInWrite, in_buffer, dwSize, &dwWritten, NULL);
}

// 读出stdout  
BOOL CWinCGI::Read(PBYTE out_buffer, DWORD dwSize)  
{
	DWORD dwRead = 0;
	return ReadFile(hStdOutRead, out_buffer, dwSize, &dwRead, NULL);
}
// -------------------------------------------------------------------------
// $Log: $