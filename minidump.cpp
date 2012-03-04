#include <windows.h>
#include <dbghelp.h>
#include <tchar.h>
#include "minidump.h"

#define MINIDUMP_FILE _T("elc.dmp")

static const PTCHAR imageNames[] = {
	_T("elc.exe"),
	_T("elc-vc.exe"),
	_T("wrap_oal.dll"),
	_T("OpenAL32.dll")
};
static const int numImageNames = sizeof(imageNames) / sizeof(imageNames[0]);


BOOL minidump_createcrashdump(LPCTSTR lpFileName,EXCEPTION_POINTERS * pExPtrs);
BOOL minidump_dumpminidump(HANDLE hFile, EXCEPTION_POINTERS * pExPtrs);
LONG minidump_launcherrorreporter(LPCTSTR pszDumpFile);

// minidump callback function
BOOL CALLBACK minidump_minidumpcallback(
	PVOID                            pParam,
	const PMINIDUMP_CALLBACK_INPUT   pInput,
	PMINIDUMP_CALLBACK_OUTPUT        pOutput
);

BOOL minidump_isdatasectionneeded(PWCHAR pModuleName);

// The typedef for the MiniDumpWriteDump function.
typedef BOOL
(WINAPI * PFNMINIDUMPWRITEDUMP)(
    IN HANDLE hProcess,
    IN DWORD ProcessId,
    IN HANDLE hFile,
    IN MINIDUMP_TYPE DumpType,
    IN CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, OPTIONAL
    IN CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, OPTIONAL
    IN CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam OPTIONAL);

// DBGHELP.DLL name.
const TCHAR * k_DBGHELPDLLNAME = _T("DBGHELP.DLL");

// The function name for MiniDumpWriteDump.
const char * k_MINIDUMPWRITEDUMP = "MiniDumpWriteDump";

LONG __stdcall
minidump_crashhandler (EXCEPTION_POINTERS * pExPtrs)
{
	LONG lReturnVal = EXCEPTION_CONTINUE_SEARCH;

	// If the exception is an EXCEPTION_STACK_OVERFLOW, there isn't much
	// you can do because the stack is blown. If you try to do anything,
	// the odds are great that you'll just double-fault and bomb right
	// out of your exception filter. I take the safe route and make some
	// calls to OutputDebugString here. I still might double-fault, but
	// because OutputDebugString does very little on the stack (something like 8-16 bytes),
	// it's worth a shot. You can have your users download Mark Russinovich's
	// DebugView (www.sysinternals.com) so they can at least tell you
	// what they see.
	// The only problem is that I can't even be sure there's enough
	// room on the stack to convert the instruction pointer.
	// Fortunately, EXCEPTION_STACK_OVERFLOW doesn't happen very often.
	__try
	{
		// I'm doing the logging work here in case the blown stack kills the crash handler.
		if (FALSE == IsBadReadPtr(pExPtrs, sizeof( EXCEPTION_POINTERS))
				&& EXCEPTION_STACK_OVERFLOW == pExPtrs->ExceptionRecord->ExceptionCode)
		{
			OutputDebugString(_T("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"));
			OutputDebugString(_T("EXCEPTION_STACK_OVERFLOW occurred\n"));
			OutputDebugString(_T("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"));
		}

		// GetTempPath function retrieves the path of the directory
		// designated for temporary files.The returned string ends
		// with a backslash, for example, C:\TEMP\.
		TCHAR szDumpFile[MAX_PATH];
		DWORD nRet = GetTempPath(MAX_PATH, szDumpFile);
		if (nRet != 0)
			lstrcat(szDumpFile, MINIDUMP_FILE);
		else
			lstrcpy(szDumpFile, MINIDUMP_FILE);

		if (minidump_createcrashdump(szDumpFile,pExPtrs))
		{

			lReturnVal = minidump_launcherrorreporter(szDumpFile);
		}
		else
		{
			// CreateCrashDump() function failed - let
			// the standard crash dialog appear
			lReturnVal = EXCEPTION_CONTINUE_SEARCH;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// let the standard crash dialog appear
		lReturnVal = EXCEPTION_CONTINUE_SEARCH;
	}
	return (lReturnVal);
}

extern "C" void
minidump_setcrashhandler()
{
	// This function enables an application to supersede the top-level exception
	// handler of each thread and process.
	SetUnhandledExceptionFilter(&minidump_crashhandler);
}

BOOL
minidump_dumpminidump(HANDLE hFile, EXCEPTION_POINTERS * pExPtrs)
{
	BOOL bRet = FALSE;
	HINSTANCE hInstDBGHELP = NULL;
	PFNMINIDUMPWRITEDUMP pfnMDWD = NULL;
	MINIDUMP_EXCEPTION_INFORMATION eInfo;
	eInfo.ThreadId = GetCurrentThreadId();
	eInfo.ExceptionPointers = pExPtrs;
	eInfo.ClientPointers = FALSE;

	// This structure contains a pointer to an optional callback function
	// that can be used by the MiniDumpWriteDump function.
	MINIDUMP_CALLBACK_INFORMATION mci;
	mci.CallbackRoutine     = (MINIDUMP_CALLBACK_ROUTINE)minidump_minidumpcallback;
	mci.CallbackParam       = 0;

	// MiniDumpNormal : Capture stack traces for all existing threads in a process.

	// MiniDumpWithDataSegs : Include the data sections from all loaded modules.
	// This results in the inclusion of global variables.

	// MiniDumpWithHandleData : Include high-level information about the operating system
	// handles that are active when the minidump is made.

	// MiniDumpWithIndirectlyReferencedMemory : Include pages with data referenced
	// by locals or other stack memory.

	// MiniDumpScanMemory : Stack and backing store memory should be scanned for pointer
	// references to modules in the module list.

	// Type of information that will be written to the minidump file.
	MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpNormal
					| MiniDumpWithIndirectlyReferencedMemory
					| MiniDumpScanMemory
					| MiniDumpWithDataSegs
					);

	// Load DBGHELP.DLL
	hInstDBGHELP = LoadLibrary (k_DBGHELPDLLNAME);
	if ( NULL != hInstDBGHELP )
	{
		// Get MiniDumpWriteDump function.
		pfnMDWD = (PFNMINIDUMPWRITEDUMP)GetProcAddress (hInstDBGHELP,k_MINIDUMPWRITEDUMP) ;
		if ( NULL != pfnMDWD )
		{
			// Write minidump to the file.
			// If the function succeeds, the return value is TRUE;
			// otherwise, the return value is FALSE
			bRet = pfnMDWD(GetCurrentProcess(),
			    GetCurrentProcessId(),
			    hFile,
			    mdt,
			    pExPtrs ? &eInfo : NULL,
			    NULL,
			    &mci
			    );
		}
		else
		{
			// error
			;
		}

		// Unload DBGHELP.DLL
		FreeLibrary(hInstDBGHELP);
	}

	return bRet;
}


BOOL
minidump_createcrashdump(LPCTSTR lpFileName, EXCEPTION_POINTERS * pExPtrs)
{
	BOOL bRet = FALSE;
	if (IsBadStringPtr(lpFileName,MAX_PATH))
		return bRet;
	// Create the file
	HANDLE hMiniDumpFile = CreateFile(
		lpFileName,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hMiniDumpFile != INVALID_HANDLE_VALUE)
	{
		// Write minidump to the file.
		// If the function succeeds, the return value is TRUE;
		// otherwise, the return value is FALSE
		bRet = minidump_dumpminidump(hMiniDumpFile, pExPtrs);

		// Close file
		CloseHandle(hMiniDumpFile);
	}
	return bRet;
}

BOOL CALLBACK
minidump_minidumpcallback(
	PVOID                            pParam,
	const PMINIDUMP_CALLBACK_INPUT   pInput,
	PMINIDUMP_CALLBACK_OUTPUT        pOutput
)
{
	BOOL bRet = FALSE;

	// Check parameters
	if (pInput == 0)
		return FALSE;
	if (pOutput == 0)
		return FALSE;

	// Process the callbacks
	switch (pInput->CallbackType)
	{
		case IncludeModuleCallback:
		{
			// Include the module into the dump
			bRet = TRUE;
		}
		break;
		case IncludeThreadCallback:
		{
			// Include the thread into the dump
			bRet = TRUE;
		}
		break;
		case ModuleCallback:
		{
			// Does the module have ModuleReferencedByMemory flag set ?
			if (!(pOutput->ModuleWriteFlags & ModuleReferencedByMemory))
			{
				// No, it does not - exclude it
				pOutput->ModuleWriteFlags &= (~ModuleWriteModule);

				// Are data sections available for this module ?
				if (pOutput->ModuleWriteFlags & ModuleWriteDataSeg)
				{
					// Yes, they are. We don't need them, so exclude data sections for this module.
					pOutput->ModuleWriteFlags &= (~ModuleWriteDataSeg);
				}
			}
			else // ModuleReferencedByMemory flag is set for this module
			{
				// Are data sections available for this module ?
				if (pOutput->ModuleWriteFlags & ModuleWriteDataSeg)
				{
					// Yes, they are. but do we need them?
					if (!minidump_isdatasectionneeded(pInput->Module.FullPath))
					{
						// No, we don't need them. So exclude data sections for this module.
						pOutput->ModuleWriteFlags &= (~ModuleWriteDataSeg);
					}
				}
			}
			bRet = TRUE;
		}
		break;
		case ThreadCallback:
		{
			// Include all thread information into the minidump
			bRet = TRUE;
		}
		break;
		case ThreadExCallback:
		{
			// Include this information
			bRet = TRUE;
		}
		break;
	}
	return bRet;
}

static const TCHAR *
minidump_getfilepart(LPCTSTR source)
{
	LPCTSTR result = _tcsrchr(source, _T('\\'));
	if (result)
		result++;
	else
		result = (TCHAR *)source;
	return result;
}

BOOL
minidump_isdatasectionneeded(PWCHAR pModuleName)
{
	// Check parameters
	if (pModuleName == 0)
		return false;

#ifdef _UNICODE
	TCHAR *szModuleFullPath = pModuleName;
#else
	TCHAR szModuleFullPath[2 * _MAX_PATH];
	WideCharToMultiByte( CP_ACP, 0, pModuleName, -1,
		(LPSTR) szModuleFullPath, 2 * _MAX_PATH, NULL, NULL );
#endif
	// Extract the module name
	LPCTSTR pszFileName = minidump_getfilepart(szModuleFullPath);
	if (pszFileName == NULL)
		return false;

	// Compare the name with the list of known names and decide
	for (int i = 0; i < numImageNames; ++i)
	{
		if (lstrcmpi (pszFileName, imageNames[i]) == 0)
		{
			// File is one of ours, include data sections
			return true;
		}
	}

	 // Don't include data sections
	return false;
}

// lstrrchr
static TCHAR *
lstrrchr(LPCTSTR string, int ch)
{
	TCHAR *start = (TCHAR *)string;

	while (*string++)                       /* find end of string */
		;
											/* search towards front */
	while (--string != start && *string != (TCHAR) ch)
		;

	if (*string == (TCHAR) ch)                /* char found ? */
		return (TCHAR *)string;

	return NULL;
}
// Launch ErrorReporter Application
LONG minidump_launcherrorreporter(LPCTSTR pszDumpFile)
{
	LONG lReturnVal = EXCEPTION_CONTINUE_SEARCH;
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCommandLine[MAX_PATH];
	TCHAR szCrashReportExe[MAX_PATH];

	ZeroMemory(szModuleName, sizeof(szModuleName));
	if (GetModuleFileName(0, szModuleName, _countof(szModuleName) - sizeof(TCHAR)) <= 0)
		lstrcpy(szModuleName, _T("Unknown"));

	TCHAR *pszFilePart = lstrrchr(szModuleName, _T('\\'));
	if (pszFilePart)
		pszFilePart++;
	else
		pszFilePart = (TCHAR *)szModuleName;

	lstrcpy(pszFilePart, "ErrorReporter.exe");
	ZeroMemory(szCrashReportExe, sizeof(szCrashReportExe));
	lstrcpy(szCrashReportExe, szModuleName);

	// Append dump file name wrapped with quotes
	lstrcat(szCommandLine, _T(" \""));
	if (FALSE == IsBadStringPtr(pszDumpFile, MAX_PATH))
		lstrcat(szCommandLine, pszDumpFile);
	else
		lstrcat(szCommandLine, MINIDUMP_FILE);
	lstrcat(szCommandLine, _T("\""));

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	if (CreateProcess(
		szCrashReportExe,		// name of executable module
		szCommandLine,			// command line string
		NULL,					// process attributes
		NULL,					// thread attributes
		FALSE,					// handle inheritance option
		0,						// creation flags
		NULL,					// new environment block
		NULL,					// current directory name
		&si,					// startup information
		&pi))					// process information
	{
		// CrashReport.exe was successfully started, so
		// suppress the standard crash dialog
		lReturnVal =  EXCEPTION_EXECUTE_HANDLER;
	}
	else
	{
		// CrashReport.exe was not started - let
		// the standard crash dialog appear
		lReturnVal = EXCEPTION_CONTINUE_SEARCH;
	}
	return lReturnVal;
}
