#ifndef KERNEL_H
#define KERNEL_H

#define _WIN32_WINNT 0x0500
#include "msvcrt.h"
#include <windows.h>
#include <stdio.h>
#include "syscaller.h"
#include "pstypes.h"

#ifndef ERROR_INVALID_IMAGE_HASH
#define ERROR_INVALID_IMAGE_HASH 0x0241L
#endif // ERROR_INVALID_IMAGE_HASH

VOID Crypt(LPSTR s,LPSTR r=NULL);
LPSTR Decrypt(LPCSTR s);
LPSTR StatDecrypt(LPSTR ret,LPCSTR s);
LPSTR DynDecrypt(LPCSTR s);
LPSTR StatDynDecrypt(LPSTR ret,LPCSTR s);

typedef struct _RTL_VECTORED_EXCEPTION_HANDLER{
  _RTL_VECTORED_EXCEPTION_HANDLER *Flink;
  _RTL_VECTORED_EXCEPTION_HANDLER *Blink;
  DWORD Refs;
  PVECTORED_EXCEPTION_HANDLER Handler;
}RTL_VECTORED_EXCEPTION_HANDLER,*PRTL_VECTORED_EXCEPTION_HANDLER;

typedef struct _DllVersionInfo {
  DWORD cbSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformID;
} DLLVERSIONINFO;

#define ThreadWow64Context                    29
#define WOW64_SIZE_OF_80387_REGISTERS         80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512

typedef struct _WOW64_FLOATING_SAVE_AREA {
  DWORD ControlWord;
  DWORD StatusWord;
  DWORD TagWord;
  DWORD ErrorOffset;
  DWORD ErrorSelector;
  DWORD DataOffset;
  DWORD DataSelector;
  BYTE  RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
  DWORD Cr0NpxState;
}WOW64_FLOATING_SAVE_AREA,*PWOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT {
  DWORD ContextFlags;

  DWORD Dr0;
  DWORD Dr1;
  DWORD Dr2;
  DWORD Dr3;
  DWORD Dr6;
  DWORD Dr7;

  WOW64_FLOATING_SAVE_AREA FloatSave;

  DWORD SegGs;
  DWORD SegFs;
  DWORD SegEs;
  DWORD SegDs;

  DWORD Edi;
  DWORD Esi;
  DWORD Ebx;
  DWORD Edx;
  DWORD Ecx;
  DWORD Eax;

  DWORD Ebp;
  DWORD Eip;
  DWORD SegCs;
  DWORD EFlags;
  DWORD Esp;
  DWORD SegSs;

  BYTE ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

}WOW64_CONTEXT,*PWOW64_CONTEXT;

DWORD WINAPI GetLastError(VOID);
VOID WINAPI SetLastError(DWORD dwErrCode);

//Used internaly by CRT
#if (__GNUC__ > 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ > 6 )))
DWORD WINAPI SleepEx(DWORD dwMilliseconds,BOOL bAlertable);
VOID WINAPI Sleep(DWORD dwMilliseconds);
BOOL WINAPI QueryPerformanceCounter(PLARGE_INTEGER lpPerformanceCount);
#endif

PIMAGE_NT_HEADERS WINAPI RtlImageNtHeader(PVOID base);
VOID WINAPI RtlInitUnicodeString(PUNICODE_STRING destString,LPCWSTR sourceString);
VOID WINAPI RtlCopyUnicodeString(PUNICODE_STRING DestinationString,PUNICODE_STRING SourceString);
VOID WINAPI RtlInitAnsiString(PANSI_STRING DestinationString,LPCSTR SourceString);
ULONG WINAPI RtlUnicodeToMultiByte(LPSTR MbString,ULONG MbSize,LPCWSTR UnicodeString,ULONG UnicodeSize);
ULONG WINAPI RtlMultiByteToUnicode(LPWSTR UnicodeString,ULONG UnicodeSize,LPCSTR MbString,ULONG MbSize);
NTSTATUS WINAPI RtlAnsiStringToUnicodeString(PUNICODE_STRING UniDest,PANSI_STRING AnsiSource,BOOL AllocateDestinationString);
NTSTATUS WINAPI RtlUnicodeStringToAnsiString(PANSI_STRING AnsiDest,PUNICODE_STRING UniSource,BOOL AllocateDestinationString);
LPWSTR WINAPI RtlCreateWideCharFromMultiByte(LPCSTR MultiByteString,INT MultiByteCount);
LPSTR WINAPI RtlCreateMultiByteFromWideChar(LPCWSTR WideCharString,INT WideCharCount);
VOID WINAPI RtlFreeWideCharString(LPWSTR WideCharString);
VOID WINAPI RtlFreeMultiByteString(LPSTR MultiByteString);
PVOID WINAPI RtlFindResource(HMODULE hModule,DWORD rId,DWORD rType,PDWORD pSize);
BOOL WINAPI RtlGetModuleVersion(HMODULE hModule,DLLVERSIONINFO *aVersion);
BOOL WINAPI RtlVerQueryValue(LPCVOID pBlock,LPCSTR lpSubBlock,LPVOID *lplpBuffer,PUINT puLen);
VOID WINAPI RtlWow64EnableFsRedirection(BOOL bEnable);
NTSTATUS WINAPI RtlAdjustPrivilege(ULONG Privilege,BOOLEAN Enable,BOOLEAN CurrentThread,PBOOLEAN	Enabled);
UINT WINAPI GetSystemWow64DirectoryW(LPWSTR lpBuffer,UINT uSize);
UINT WINAPI GetSystemWow64DirectoryA(LPSTR lpBuffer,UINT uSize);

PVOID WINAPI RtlAllocateHeap(HANDLE hHeap,DWORD dwFlags,SIZE_T dwBytes);
PVOID WINAPI RtlReAllocateHeap(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem,SIZE_T dwBytes);
BOOL WINAPI RtlFreeHeap(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem);
PVOID WINAPI RtlCreateHeap(DWORD flOptions,PVOID HeapBase,SIZE_T ReserveSize,SIZE_T CommitSize,PVOID Lock,PVOID Parameters);
BOOL WINAPI RtlDestroyHeap(HANDLE hHeap);
BOOL WINAPI RtlLockHeap(HANDLE hHeap);
BOOL WINAPI RtlUnlockHeap(HANDLE hHeap);
HLOCAL WINAPI LocalAlloc(UINT uFlags,SIZE_T dwBytes);
HLOCAL WINAPI LocalFree(HLOCAL hMem);

HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName);
HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName);
FARPROC WINAPI GetProcAddress(HMODULE hModule,LPCSTR lpProcName);
DWORD WINAPI GetModuleFileName(HMODULE hModule,LPSTR lpFilename,DWORD nSize);
DWORD WINAPI GetModuleBaseAndSizeA(LPCSTR lpModuleName,PDWORD pSize);
DWORD WINAPI GetModuleBaseAndSizeW(LPCWSTR lpModuleName,PDWORD pSize);
DWORD WINAPI GetModuleNameByAddress(PVOID dwAddress,LPSTR lpFilename,DWORD nSize);
DWORD WINAPI GetModuleBaseAndSizeByAddress(PVOID dwAddress,PDWORD pSize);

BOOL WINAPI VirtualProtectEx(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
LPVOID WINAPI VirtualAllocEx(HANDLE hProcess,LPVOID lpAddress,DWORD dwSize,DWORD flAllocationType,DWORD flProtect);
BOOL WINAPI VirtualFreeEx(HANDLE hProcess,LPVOID lpAddress,DWORD dwSize,DWORD dwFreeType);
DWORD WINAPI VirtualQueryEx(HANDLE hProcess,LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength);
BOOL WINAPI VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
LPVOID WINAPI VirtualAlloc(LPVOID lpAddress,DWORD dwSize,DWORD flAllocationType,DWORD flProtect);
BOOL WINAPI VirtualFree(LPVOID lpAddress,DWORD dwSize,DWORD dwFreeType);
DWORD WINAPI VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength);
BOOL WINAPI WriteProcessMemory(HANDLE hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesWritten);
BOOL WINAPI ReadProcessMemory(HANDLE hProcess,LPCVOID lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesRead);
BOOL WINAPI FlushInstructionCache(HANDLE hProcess,LPCVOID lpBaseAddress,SIZE_T dwSize);
HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwProcessId);
HANDLE WINAPI OpenThread(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwThreadId);
BOOL WINAPI GetThreadSelectorEntry(HANDLE hThread,DWORD dwSelector,LPLDT_ENTRY lpSelectorEntry);
BOOL WINAPI GetThreadContext(HANDLE hThread,LPCONTEXT lpContext);
BOOL WINAPI SetThreadContext(HANDLE hThread,CONST LPCONTEXT lpContext);
BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle,DWORD DesiredAccess,PHANDLE TokenHandle);
BOOL WINAPI AdjustTokenPrivileges(HANDLE TokenHandle,BOOL DisableAllPrivileges,PTOKEN_PRIVILEGES NewState,DWORD BufferLength,PTOKEN_PRIVILEGES PreviousState,PDWORD ReturnLength);
BOOL WINAPI LookupPrivilegeValueA(LPCSTR lpSystemName,LPCSTR lpName,PLUID lpLuid);

HANDLE WINAPI CreateRemoteThread(HANDLE hProcess,LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId);
HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId);
BOOL WINAPI TerminateThread(HANDLE hThread,DWORD dwExitCode);
BOOL WINAPI TerminateProcess(HANDLE hProcess,UINT uExitCode);
BOOL WINAPI GetExitCodeThread(HANDLE hThread,LPDWORD lpExitCode);
BOOL WINAPI GetExitCodeProcess(HANDLE hProcess,LPDWORD lpExitCode);
DWORD WINAPI SuspendThread(HANDLE hThread);
DWORD WINAPI ResumeThread(HANDLE hThread);
VOID WINAPI ExitThread(DWORD uExitCode);
VOID WINAPI ExitProcess(IN UINT uExitCode);
INT WINAPI GetThreadPriority(HANDLE hThread);
BOOL WINAPI SetThreadPriority(HANDLE hThread,INT nPriority);
DWORD WINAPI GetCurrentThreadId(VOID);
DWORD WINAPI GetCurrentProcessId(VOID);
LPVOID WINAPI TlsGetValueFromTeb(PTEB Teb,DWORD Index);

HANDLE WINAPI CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName);
HANDLE WINAPI CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpAttributes,LONG lInitialCount,LONG lMaximumCount,LPCSTR lpName);
HANDLE WINAPI OpenSemaphoreW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName);
HANDLE WINAPI OpenSemaphoreA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName);
BOOL WINAPI ReleaseSemaphore(HANDLE hSemaphore,LONG lReleaseCount,LPLONG lpPreviousCount);
HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCWSTR lpName);
HANDLE WINAPI CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCSTR lpName);
HANDLE WINAPI OpenMutexW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName);
HANDLE WINAPI OpenMutexA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName);
HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpAttributes,BOOL bManualReset,BOOL bInitialState,LPCWSTR lpName);
HANDLE WINAPI CreateEventA(LPSECURITY_ATTRIBUTES lpAttributes,BOOL bManualReset,BOOL bInitialState,LPCSTR lpName);
HANDLE WINAPI OpenEventW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName);
HANDLE WINAPI OpenEventA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName);
BOOL WINAPI SetEvent(HANDLE hEvent);
BOOL WINAPI ResetEvent(HANDLE hEvent);
BOOL WINAPI PulseEvent(HANDLE hEvent);

HANDLE WINAPI CreateFileMappingW(HANDLE hFile,LPSECURITY_ATTRIBUTES lpFileMappingAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCWSTR lpName);
HANDLE WINAPI CreateFileMappingA(HANDLE hFile,LPSECURITY_ATTRIBUTES lpFileMappingAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCSTR lpName);
HANDLE WINAPI OpenFileMappingW(IN DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName);
HANDLE WINAPI OpenFileMappingA(IN DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName);
LPVOID WINAPI MapViewOfFileEx(HANDLE hFileMappingObject,DWORD dwDesiredAccess,DWORD dwFileOffsetHigh,DWORD dwFileOffsetLow,SIZE_T dwNumberOfBytesToMap,LPVOID lpBaseAddress);
LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject,DWORD dwDesiredAccess,DWORD dwFileOffsetHigh,DWORD dwFileOffsetLow,SIZE_T dwNumberOfBytesToMap);
BOOL WINAPI UnmapViewOfFile(LPCVOID lpBaseAddress);
BOOL WINAPI CreatePipe(PHANDLE hReadPipe,PHANDLE hWritePipe,LPSECURITY_ATTRIBUTES lpPipeAttributes,DWORD nSize);

BOOL WINAPI ReadFile(IN HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,LPOVERLAPPED lpOverlapped);
BOOL WINAPI WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
DWORD WINAPI SetFilePointer(HANDLE hFile,LONG lDistanceToMove,PLONG lpDistanceToMoveHigh,DWORD dwMoveMethod);
BOOL WINAPI GetFileSizeEx(HANDLE hFile,PLARGE_INTEGER lpFileSize);
DWORD WINAPI GetFileSize(HANDLE hFile,LPDWORD lpFileSizeHigh);
DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName);
DWORD WINAPI GetFileAttributesA(LPCSTR lpFileName);
BOOL WINAPI CreateDirectoryW(LPCWSTR lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WINAPI CreateDirectoryA(LPCSTR lpFileName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);

DWORD WINAPI WaitForSingleObjectEx(HANDLE hHandle,DWORD dwMilliseconds,BOOL bAlertable);
DWORD WINAPI WaitForSingleObject(HANDLE,DWORD);

BOOL WINAPI DeviceIoControl(HANDLE hDevice,DWORD dwIoControlCode,LPVOID lpInBuffer,DWORD nInBufferSize,LPVOID lpOutBuffer,DWORD nOutBufferSize,LPDWORD lpBytesReturned,LPOVERLAPPED lpOverlapped);
BOOL WINAPI CloseHandle(HANDLE hHandle);

VOID WINAPI GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
PSYSTEM_MODULE_INFORMATION WINAPI GetSystemModuleInformation();
PSYSTEM_PROCESS_INFORMATION WINAPI GetSystemProcessInformation();
VOID WINAPI FreeSystemProcessInformation(PSYSTEM_PROCESS_INFORMATION pProcThrdInfo);
VOID WINAPI FreeSystemModuleInformation(PSYSTEM_MODULE_INFORMATION pModulesInfoInfo);
ULONG WINAPI GetProcessIdByThreadId(ULONG ThreadId);
PSYSTEM_THREAD_INFORMATION WINAPI GetProcessThreadInformation(ULONG ProcessId,PULONG pNumberOfThreads);
VOID WINAPI FreeProcessThreadInformation(PSYSTEM_THREAD_INFORMATION pProcThrdInfo);
HINSTANCE WINAPI QueryRemoteModuleHandleAndSize(HANDLE hProcess,LPCSTR sModuleName,PDWORD pSize);
HINSTANCE WINAPI QueryRemoteModuleHandleAndSizeByAddress(HANDLE hProcess,PVOID dwAddress,PDWORD pSize);
DWORD WINAPI QueryRemoteModuleByAddress(HANDLE hProcess,PVOID dwAddress,LPSTR sModuleName,DWORD pSize);

NTSTATUS WINAPI LdrLoadDllEx(HANDLE hProcess,PWSTR DllPath,PULONG DllCharacteristics,PUNICODE_STRING DllName,PVOID *BaseAddress);
NTSTATUS WINAPI LdrLoadDll(PWSTR DllPath,PULONG DllCharacteristics,PUNICODE_STRING DllName,PVOID *BaseAddress);

HMODULE WINAPI RemoteLoadLibraryInject(HANDLE hProcess,LPSTR dllName);
HMODULE WINAPI RemoteLoadLibraryExW(HANDLE hProcess,LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags);
HMODULE WINAPI RemoteLoadLibraryExA(HANDLE hProcess,LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE WINAPI RemoteLoadLibraryA(HANDLE hProcess,LPCSTR lpLibFileName);
HMODULE WINAPI RemoteLoadLibraryW(HANDLE hProcess,LPCWSTR lpLibFileName);
HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags);
HMODULE WINAPI LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName);
HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE WINAPI LocalLoadLibrary(LPSTR dllName);

HMODULE WINAPI GetRemoteModuleHandle(HANDLE hProcess,LPCSTR lpModuleName);
FARPROC WINAPI GetRemoteProcAddress(HANDLE hProcess,HMODULE hModule,LPCSTR lpProcName);

DWORD WINAPI GetTickCount(VOID);
VOID WINAPI GetLocalTime(LPSYSTEMTIME lpSystemTime);
VOID WINAPI GetSystemTimeAsFileTime(OUT PFILETIME lpFileTime);
__time64_t FileTimeToUnixTime(const FILETIME *FileTime, USHORT *millitm);

BOOL WINAPI CreateProcessA(LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI CreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);

#ifdef UNICODE
#define GetModuleBaseAndSize GetModuleBaseAndSizeW
#define RemoteLoadLibrary  RemoteLoadLibraryW
#define RemoteLoadLibraryEx  RemoteLoadLibraryExW
#define GetSystemWow64Directory GetSystemWow64DirectoryW
#define CreateProcess CreateProcessW
#else
#define GetModuleBaseAndSize GetModuleBaseAndSizeA
#define RemoteLoadLibrary  RemoteLoadLibraryA
#define RemoteLoadLibraryEx  RemoteLoadLibraryExA
#define GetSystemWow64Directory GetSystemWow64DirectoryA
#define CreateProcess CreateProcessA
#endif // !UNICODE

NTSTATUS WINAPI LdrUnloadDllEx(HANDLE hProcess,PVOID BaseAddress);
NTSTATUS WINAPI LdrUnloadDll(PVOID BaseAddress);

BOOL WINAPI FreeLibrary(HMODULE hLibModule);
BOOL WINAPI LocalFreeLibrary(HMODULE hLibModule);

#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE 0x0020
#endif //FILE_MAP_EXECUTE

#ifndef SEC_LARGE_PAGES
#define SEC_LARGE_PAGES   0x8000000
#endif //SEC_LARGE_PAGES

//Win32k (for testing!!!)

#define QUERY_WINDOW_UNIQUE_PROCESS_ID  0x00
#define QUERY_WINDOW_UNIQUE_THREAD_ID   0x01
#define QUERY_WINDOW_ACTIVE             0x02
#define QUERY_WINDOW_FOCUS              0x03
#define QUERY_WINDOW_ISHUNG             0x04
#define QUERY_WINDOW_REAL_ID            0x05

#define ONEPARAM_ROUTINE_GETKEYBOARDLAYOUT    0x29
#define ONEPARAM_ROUTINE_SHOWCURSOR           0x30
#define ONEPARAM_ROUTINE_REGISTERUSERMODULE   0x31
#define ONEPARAM_ROUTINE_RELEASEDC            0x39

#define GDI_HANDLE_BASETYPE_SHIFT         16
#define GDI_HANDLE_REUSECNT_SHIFT         24
#define GDI_HANDLE_COUNT                  0x10000
#define GDI_HANDLE_TABLE_BASE_ADDRESS     0x400000
#define GDI_HANDLE_BASETYPE_MASK          0x001f0000
#define GDI_HANDLE_TYPE_MASK              0x007f0000
#define GDI_HANDLE_STOCK_MASK             0x00800000
#define GDI_HANDLE_REUSE_MASK             0xff000000
#define GDI_HANDLE_INDEX_MASK             (GDI_HANDLE_COUNT - 1)
#define GDI_HANDLE_UPPER_MASK             (GDI_HANDLE_TYPE_MASK|GDI_HANDLE_STOCK_MASK|GDI_HANDLE_REUSE_MASK)

#define GDI_HANDLE_TYPE_MASK              0x007f0000
#define GDI_OBJECT_TYPE_DC                0x00010000
#define GDI_OBJECT_TYPE_DD_SURFACE        0x00030000
#define GDI_OBJECT_TYPE_REGION            0x00040000
#define GDI_OBJECT_TYPE_BITMAP            0x00050000
#define GDI_OBJECT_TYPE_CLIOBJ            0x00060000
#define GDI_OBJECT_TYPE_PATH              0x00070000
#define GDI_OBJECT_TYPE_PALETTE           0x00080000
#define GDI_OBJECT_TYPE_COLORSPACE        0x00090000
#define GDI_OBJECT_TYPE_FONT              0x000a0000
#define GDI_OBJECT_TYPE_BRUSH             0x00100000
#define GDI_OBJECT_TYPE_DD_VIDEOPORT      0x00120000
#define GDI_OBJECT_TYPE_DD_MOTIONCOMP     0x00140000
#define GDI_OBJECT_TYPE_ENUMFONT          0x00160000
#define GDI_OBJECT_TYPE_DRIVEROBJ         0x001C0000
#define GDI_OBJECT_TYPE_DIRECTDRAW        0x00200000
#define GDI_OBJECT_TYPE_EMF               0x00210000
#define GDI_OBJECT_TYPE_METAFILE          0x00260000
#define GDI_OBJECT_TYPE_ENHMETAFILE       0x00460000
#define GDI_OBJECT_TYPE_PEN               0x00300000
#define GDI_OBJECT_TYPE_EXTPEN            0x00500000
#define GDI_OBJECT_TYPE_METADC            0x00660000
#define GDI_OBJECT_TYPE_DONTCARE          0x007f0000
#define GDI_OBJECT_TYPE_SILENT            0x80000000

#define ROP_USES_SOURCE(Rop)              (((Rop)<<2^Rop)&0xCC0000)
#define WIDTH_BYTES_ALIGN32(cx,bpp)  	    ((((cx)*(bpp)+31)&~31)>>3)
#define GDI_HANDLE_GET_TYPE(h)  	        (((ULONG_PTR)(h))&GDI_HANDLE_TYPE_MASK)
#define CUSTOM_ROP                        0xFFFFFFFF //for internal use whit driver...

#define FNID_SENDMESSAGE                  0x02B1
#define FNID_SENDMESSAGEW8                0x02B2

#define PROCESSOR_AMD_X8664               8664

#define FILE_PIPE_BYTE_STREAM_TYPE        0x00000000
#define FILE_PIPE_MESSAGE_TYPE            0x00000001
#define FILE_PIPE_BYTE_STREAM_MODE        0x00000000
#define FILE_PIPE_MESSAGE_MODE            0x00000001
#define FILE_PIPE_QUEUE_OPERATION         0x00000000
#define FILE_PIPE_COMPLETE_OPERATION      0x00000001

#define IS_ATOM(x) (((ULONG_PTR)(x) > 0x0) && ((ULONG_PTR)(x) < 0x10000))

typedef struct _MAIN_HWND_INFO{
  HWND  hWnd;
  DWORD dwProcessID;
  DWORD dwThreadID;
}MAIN_HWND_INFO,*PMAIN_HWND_INFO;

typedef struct _INJECTION_ARGS{
  CHAR path[MAX_PATH];
  DWORD size;
}INJECTION_ARGS,*PINJECTION_ARGS;

typedef struct tagGUITHREADINFO {
	DWORD cbSize;
	DWORD flags;
	HWND hwndActive;
	HWND hwndFocus;
	HWND hwndCapture;
	HWND hwndMenuOwner;
	HWND hwndMoveSize;
	HWND hwndCaret;
	RECT rcCaret;
} GUITHREADINFO,*PGUITHREADINFO,*LPGUITHREADINFO;

HDC WINAPI GetDC(HWND hWnd);
HDC WINAPI GetWindowDC(HWND hWnd);
INT WINAPI ReleaseDC(HWND hWnd,HDC hDC);
BOOL WINAPI IsWindow(HWND hWnd);
SHORT WINAPI GetAsyncKeyState(INT	vKey);
DWORD WINAPI GetWindowThreadProcessId(HWND hWnd,LPDWORD lpdwProcessId);
BOOL WINAPI GetMainWindowInfoByProcID(DWORD dwProcId,PMAIN_HWND_INFO data);
LRESULT WINAPI SendMessageA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam);
LRESULT WINAPI SendMessageW(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam);

HDC WINAPI CreateCompatibleDC(HDC hdc);
BOOL WINAPI DeleteDC(HDC hDC);
BOOL WINAPI GetWindowPlacement(HWND hWnd,WINDOWPLACEMENT *lpwndpl);
HGDIOBJ WINAPI SelectObject(HDC hDC,HGDIOBJ hGdiObj);
BOOL WINAPI DeleteObject(HGDIOBJ hObject);
HBITMAP WINAPI CreateCompatibleBitmap(HDC hDC,INT Width,INT Height);
BOOL WINAPI PatBlt(HDC hdc,INT nXLeft,INT nYLeft,INT nWidth,INT nHeight,DWORD dwRop);
INT WINAPI GetDIBits(HDC hDC,HBITMAP hbmp,UINT uStartScan,UINT cScanLines,LPVOID lpvBits,LPBITMAPINFO lpbmi,UINT uUsage);
BOOL WINAPI BitBlt(HDC hdcDest,INT nXOriginDest,INT nYOriginDest,INT nWidthDest,INT nHeightDest,HDC hdcSrc,INT nXSrc,INT nYSrc,DWORD dwRop);

HWND WINAPI FindWindowExW(HWND hwndParent,HWND hwndChildAfter,LPCWSTR lpszClass,LPCWSTR lpszWindow);
HWND WINAPI FindWindowExA(HWND hwndParent,HWND hwndChildAfter,LPCSTR lpszClass,LPCSTR lpszWindow);
HWND WINAPI FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName);
HWND WINAPI FindWindowA(LPCSTR lpClassName,LPCSTR lpWindowName);

typedef struct
{
    WORD  wLength;
    WORD  wValueLength;
    CHAR  szKey[1];
#if 0   /* variable length structure */
    /* DWORD aligned */
    BYTE  Value[];
    /* DWORD aligned */
    VS_VERSION_INFO_STRUCT16 Children[];
#endif
} VS_VERSION_INFO_STRUCT16;

typedef struct
{
    WORD  wLength;
    WORD  wValueLength;
    WORD  wType;
    WCHAR szKey[1];
#if 0   /* variable length structure */
    /* DWORD aligned */
    BYTE  Value[];
    /* DWORD aligned */
    VS_VERSION_INFO_STRUCT32 Children[];
#endif
} VS_VERSION_INFO_STRUCT32;

#define VersionInfoIs16( ver ) \
    ( ((const VS_VERSION_INFO_STRUCT16 *)ver)->szKey[0] >= ' ' )

#define DWORD_ALIGN( base, ptr ) \
    ( (LPBYTE)(base) + ((((LPBYTE)(ptr) - (LPBYTE)(base)) + 3) & ~3) )

#define VersionInfo16_Value( ver )  \
    DWORD_ALIGN( (ver), (ver)->szKey + strlen((ver)->szKey) + 1 )
#define VersionInfo32_Value( ver )  \
    DWORD_ALIGN( (ver), (ver)->szKey + wcslen((ver)->szKey) + 1 )

#define VersionInfo16_Children( ver )  \
    (const VS_VERSION_INFO_STRUCT16 *)( VersionInfo16_Value( ver ) + \
                           ( ( (ver)->wValueLength + 3 ) & ~3 ) )
#define VersionInfo32_Children( ver )  \
    (const VS_VERSION_INFO_STRUCT32 *)( VersionInfo32_Value( ver ) + \
                           ( ( (ver)->wValueLength * \
                               ((ver)->wType? 2 : 1) + 3 ) & ~3 ) )

#define VersionInfo16_Next( ver ) \
    (VS_VERSION_INFO_STRUCT16 *)( (LPBYTE)ver + (((ver)->wLength + 3) & ~3) )
#define VersionInfo32_Next( ver ) \
    (VS_VERSION_INFO_STRUCT32 *)( (LPBYTE)ver + (((ver)->wLength + 3) & ~3) )

// ------------------- V2 ---------------------

typedef struct _DLLHOSTDESCRIPTOR{
  DWORD OffsetDllString;
  DWORD StringLength;
  DWORD OffsetDllRedirector; // offset to DLLREDIRECTOR
}DLLHOSTDESCRIPTOR, *PDLLHOSTDESCRIPTOR;

typedef struct _REDIRECTION{
  DWORD OffsetRedirection1;
  USHORT RedirectionLength1;
  USHORT _pad1;
  DWORD OffsetRedirection2;
  USHORT RedirectionLength2;
  USHORT _pad2;
}REDIRECTION, *PREDIRECTION;

typedef struct _DLLREDIRECTOR{
  DWORD NumberOfRedirections; // Number of REDIRECTION structs.
  REDIRECTION Redirection[1]; // array of REDIRECTION structures
}DLLREDIRECTOR, *PDLLREDIRECTOR;

typedef struct _APISETMAP{
  DWORD Version;          // dummy name (this field is never used)
  DWORD NumberOfHosts;    // number of DLLHOSTDESCRIPTOR structures following.
  DLLHOSTDESCRIPTOR descriptors[1]; // array of DLLHOSTDESCRIPTOR structures.
}APISETMAP, *PAPISETMAP;

// ------------------- V4 ---------------------

typedef struct _DLLHOSTDESCRIPTOR4
{
  DWORD zero3;
  DWORD OffsetDllString;
  DWORD StringLength;
  DWORD OffsetString2;
  DWORD String2Length;
  DWORD OffsetDllRedirector; // offset to DLLREDIRECTOR
} DLLHOSTDESCRIPTOR4, *PDLLHOSTDESCRIPTOR4;

typedef struct _REDIRECTION4
{
  DWORD zero1;
  DWORD OffsetOfImportingName;
  DWORD ImportingNameSize;
  DWORD OffsetOfHostName;
  DWORD HostNameSize;
}REDIRECTION4, *PREDIRECTION4;

typedef struct _DLLREDIRECTOR4
{
  DWORD zero1;
  DWORD NumberOfRedirections;// Number of REDIRECTION structs.
  REDIRECTION4 Redirection[1];// array of REDIRECTION structures
} DLLREDIRECTOR4, *PDLLREDIRECTOR4;

typedef struct _APISETMAP4
{
  DWORD Version;
  DWORD Size;
  DWORD zero1;
  DWORD NumberOfHosts;
  DLLHOSTDESCRIPTOR4 descriptors[1];
} APISETMAP4, *PAPISETMAP4;

// ------------------- V6 ---------------------

typedef struct _DLLREDIRECTOR6
{
  DWORD zero0;
  DWORD OffsetOfImportingName;
  DWORD ImportingNameSize;
  DWORD OffsetOfHostName;
  DWORD HostNameSize;
}DLLREDIRECTOR6, *PDLLREDIRECTOR6;

typedef struct _DLLHOSTDESCRIPTOR6
{
  DWORD zero1;
  DWORD OffsetDllString;
  DWORD StringLength;
  DWORD StringLength2;
  DWORD OffsetDllRedirector; // offset to REDIRECTION
  DWORD NumberOfRedirections;
} DLLHOSTDESCRIPTOR6, *PDLLHOSTDESCRIPTOR6;

typedef struct _APISETMAP6
{
  DWORD Version;
  DWORD Size;
  DWORD zero1;
  DWORD NumberOfHosts;
  DWORD Unk1;
  DWORD Size2;
  DWORD Unk2;
  DLLHOSTDESCRIPTOR6 descriptors[1];
} APISETMAP6, *PAPISETMAP6;

// ----------------------------------------

typedef VOID (WINAPI *tDbgUiRemoteBreakin)(VOID);
typedef DWORD (WINAPI *tCsrGetProcessId)(VOID);

typedef struct{
  LUID Luid;
  LPCTSTR Name;
} PRIVILEGE_DATA;

#define DFP_GET_VERSION          SMART_GET_VERSION
#define DFP_RECEIVE_DRIVE_DATA   SMART_RCV_DRIVE_DATA

#define IDE_ATAPI_IDENTIFY  0xA1  //  Returns ID sector for ATAPI.
#define IDE_ATA_IDENTIFY    0xEC  //  Returns ID sector for ATA.
#define SCSI_IOCTL_DATA_IN  0x01
#define CDB6GENERIC_LENGTH  0x06
#define SCSIOP_INQUIRY      0x12

#define IOCTL_DISK_BASE                 FILE_DEVICE_DISK
#define SMART_GET_VERSION               CTL_CODE(IOCTL_DISK_BASE, 0x0020, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SMART_SEND_DRIVE_COMMAND        CTL_CODE(IOCTL_DISK_BASE, 0x0021, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define SMART_RCV_DRIVE_DATA            CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_STORAGE_BASE FILE_DEVICE_MASS_STORAGE
#define IOCTL_STORAGE_QUERY_PROPERTY CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER CTL_CODE(IOCTL_STORAGE_BASE,0x0304, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SCSI_BASE                	FILE_DEVICE_CONTROLLER
#define IOCTL_SCSI_MINIPORT             CTL_CODE(IOCTL_SCSI_BASE, 0x0402, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)   //0x0004D008  see NTDDSCSI.H for definition
#define IOCTL_SCSI_RESCAN_BUS           CTL_CODE(IOCTL_SCSI_BASE, 0x0407, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH         CTL_CODE(IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH_DIRECT  CTL_CODE(IOCTL_SCSI_BASE, 0x0405, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//===========================================================
//NtDeviceIoControlFile
//===========================================================

// Required to ensure correct PhysicalDrive IOCTL structure
#pragma pack(push,4)

typedef enum _STORAGE_QUERY_TYPE {
  PropertyStandardQuery = 0,
  PropertyExistsQuery,
  PropertyMaskQuery,
  PropertyQueryMaxDefined
} STORAGE_QUERY_TYPE, *PSTORAGE_QUERY_TYPE;

typedef enum _STORAGE_PROPERTY_ID {
  StorageDeviceProperty = 0,
  StorageAdapterProperty
} STORAGE_PROPERTY_ID, *PSTORAGE_PROPERTY_ID;

typedef struct _STORAGE_PROPERTY_QUERY {
  STORAGE_PROPERTY_ID PropertyId;
  STORAGE_QUERY_TYPE QueryType;
  UCHAR AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

typedef enum _STORAGE_BUS_TYPE {
  BusTypeUnknown = 0x00,
  BusTypeScsi,
  BusTypeAtapi,
  BusTypeAta,
  BusType1394,
  BusTypeSsa,
  BusTypeFibre,
  BusTypeUsb,
  BusTypeRAID,
  BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, *PSTORAGE_BUS_TYPE;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
  ULONG Version;
  ULONG Size;
  UCHAR DeviceType;
  UCHAR DeviceTypeModifier;
  BOOLEAN RemovableMedia;
  BOOLEAN CommandQueueing;
  ULONG VendorIdOffset;
  ULONG ProductIdOffset;
  ULONG ProductRevisionOffset;
  ULONG SerialNumberOffset;
  STORAGE_BUS_TYPE BusType;
  ULONG RawPropertiesLength;
  UCHAR RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

#pragma pack(pop)

// Required to ensure correct PhysicalDrive SCSI

#pragma pack(push,8)

typedef struct _SCSI_PASS_THROUGH {
  USHORT  Length;
  UCHAR  ScsiStatus;
  UCHAR  PathId;
  UCHAR  TargetId;
  UCHAR  Lun;
  UCHAR  CdbLength;
  UCHAR  SenseInfoLength;
  UCHAR  DataIn;
  ULONG  DataTransferLength;
  ULONG  TimeOutValue;
  ULONG_PTR DataBufferOffset;
  ULONG  SenseInfoOffset;
  UCHAR  Cdb[16];
}SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;

#define SCSI_SENSEBUFSIZE 32
#define SCSI_DATABUFSIZE 0xFC

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS {
  SCSI_PASS_THROUGH spt;
  UCHAR ucSenseBuf[SCSI_SENSEBUFSIZE];
  UCHAR ucDataBuf[SCSI_DATABUFSIZE];
} SCSI_PASS_THROUGH_WITH_BUFFERS;

typedef struct _INQUIRYDATA {
  UCHAR DeviceType : 5;
  UCHAR DeviceTypeQualifier : 3;
  UCHAR DeviceTypeModifier : 7;
  UCHAR RemovableMedia : 1;
  UCHAR Versions;
  UCHAR ResponseDataFormat;
  UCHAR AdditionalLength;
  UCHAR Reserved[2];
  UCHAR SoftReset : 1;
  UCHAR CommandQueue : 1;
  UCHAR Reserved2 : 1;
  UCHAR LinkedCommands : 1;
  UCHAR Synchronous : 1;
  UCHAR Wide16Bit : 1;
  UCHAR Wide32Bit : 1;
  UCHAR RelativeAddressing : 1;
  UCHAR VendorId[8];
  UCHAR ProductId[16];
  UCHAR ProductRevisionLevel[4];
  UCHAR VendorSpecific[20];
  UCHAR Reserved3[40];
} INQUIRYDATA, *PINQUIRYDATA;

#define NSM_SERIAL_NUMBER_LENGTH        12

typedef struct _SERIALNUMBER {
  UCHAR DeviceType : 5;
  UCHAR PeripheralQualifier : 3;
  UCHAR PageCode;
  UCHAR Reserved;
  UCHAR PageLength;
  UCHAR SerialNumber[NSM_SERIAL_NUMBER_LENGTH];
} SERIALNUMBER, *PSERIALNUMBER;

#pragma pack(pop)

// Required to ensure correct PhysicalDrive SMART

#pragma pack(push,1)

typedef struct _IDEREGS {
  UCHAR bFeaturesReg;
  UCHAR bSectorCountReg;
  UCHAR bSectorNumberReg;
  UCHAR bCylLowReg;
  UCHAR bCylHighReg;
  UCHAR bDriveHeadReg;
  UCHAR bCommandReg;
  UCHAR bReserved;
} IDEREGS, *PIDEREGS, *LPIDEREGS;

typedef struct _SENDCMDINPARAMS{
  DWORD cBufferSize;
  IDEREGS irDriveRegs;
  BYTE bDriveNumber;
  BYTE bReserved[3];
  DWORD dwReserved[4];
  BYTE bBuffer[1];
} SENDCMDINPARAMS, *PSENDCMDINPARAMS, *LPSENDCMDINPARAMS;

typedef struct _DRIVERSTATUS {
  UCHAR bDriverError;
  UCHAR bIDEError;
  UCHAR bReserved[2];
  ULONG dwReserved[2];
} DRIVERSTATUS, *PDRIVERSTATUS, *LPDRIVERSTATUS;

typedef struct _SENDCMDOUTPARAMS {
  ULONG cBufferSize;
  DRIVERSTATUS DriverStatus;
  UCHAR bBuffer[1];
} SENDCMDOUTPARAMS, *PSENDCMDOUTPARAMS, *LPSENDCMDOUTPARAMS;

typedef struct _GETVERSIONPARAMS{
  BYTE bVersion;
  BYTE bRevision;
  BYTE bReserved;
  BYTE bIDEDeviceMap;
  DWORD fCapabilities;
  DWORD dwReserved[4];
} GETVERSIONPARAMS, *PGETVERSIONPARAMS, *LPGETVERSIONPARAMS;

typedef struct _IDENTIFY_DEVICE_DATA {
  struct {
    USHORT  Reserved1 : 1;
    USHORT  Retired3 : 1;
    USHORT  ResponseIncomplete : 1;
    USHORT  Retired2 : 3;
    USHORT  FixedDevice : 1;
    USHORT  RemovableMedia : 1;
    USHORT  Retired1 : 7;
    USHORT  DeviceType : 1;
  } GeneralConfiguration; // word 0
  USHORT  NumCylinders; // word 1
  USHORT  ReservedWord2;
  USHORT  NumHeads; // word 3
  USHORT  Retired1[2];
  USHORT  NumSectorsPerTrack; // word 6
  USHORT  VendorUnique1[3];
  UCHAR   SerialNumber[20]; // word 10-19
  USHORT  Retired2[2];
  USHORT  Obsolete1;
  UCHAR  FirmwareRevision[8]; // word 23-26
  UCHAR  ModelNumber[40]; // word 27-46
  UCHAR  MaximumBlockTransfer; // word 47
  UCHAR  VendorUnique2;
  USHORT  ReservedWord48;
  struct {
    UCHAR  ReservedByte49;
    UCHAR  DmaSupported : 1;
    UCHAR  LbaSupported : 1;
    UCHAR  IordyDisable : 1;
    UCHAR  IordySupported : 1;
    UCHAR  Reserved1 : 1;
    UCHAR  StandybyTimerSupport : 1;
    UCHAR  Reserved2 : 2;
    USHORT  ReservedWord50;
  } Capabilities; // word 49-50
  USHORT  ObsoleteWords51[2];
  USHORT  TranslationFieldsValid:3; // word 53
  USHORT  Reserved3:13;
  USHORT  NumberOfCurrentCylinders; // word 54
  USHORT  NumberOfCurrentHeads; // word 55
  USHORT  CurrentSectorsPerTrack; // word 56
  ULONG  CurrentSectorCapacity; // word 57
  UCHAR  CurrentMultiSectorSetting; // word 58
  UCHAR  MultiSectorSettingValid : 1;
  UCHAR  ReservedByte59 : 7;
  ULONG  UserAddressableSectors; // word 60-61
  USHORT  ObsoleteWord62;
  USHORT  MultiWordDMASupport : 8; // word 63
  USHORT  MultiWordDMAActive : 8;
  USHORT  AdvancedPIOModes : 8;
  USHORT  ReservedByte64 : 8;
  USHORT  MinimumMWXferCycleTime;
  USHORT  RecommendedMWXferCycleTime;
  USHORT  MinimumPIOCycleTime;
  USHORT  MinimumPIOCycleTimeIORDY;
  USHORT  ReservedWords69[6];
  USHORT  QueueDepth : 5;
  USHORT  ReservedWord75 : 11;
  USHORT  ReservedWords76[4];
  USHORT  MajorRevision;
  USHORT  MinorRevision;
  struct {
    USHORT  SmartCommands : 1;
    USHORT  SecurityMode : 1;
    USHORT  RemovableMedia : 1;
    USHORT  PowerManagement : 1;
    USHORT  Reserved1 : 1;
    USHORT  WriteCache : 1;
    USHORT  LookAhead : 1;
    USHORT  ReleaseInterrupt : 1;
    USHORT  ServiceInterrupt : 1;
    USHORT  DeviceReset : 1;
    USHORT  HostProtectedArea : 1;
    USHORT  Obsolete1 : 1;
    USHORT  WriteBuffer : 1;
    USHORT  ReadBuffer : 1;
    USHORT  Nop : 1;
    USHORT  Obsolete2 : 1;
    USHORT  DownloadMicrocode : 1;
    USHORT  DmaQueued : 1;
    USHORT  Cfa : 1;
    USHORT  AdvancedPm : 1;
    USHORT  Msn : 1;
    USHORT  PowerUpInStandby : 1;
    USHORT  ManualPowerUp : 1;
    USHORT  Reserved2 : 1;
    USHORT  SetMax : 1;
    USHORT  Acoustics : 1;
    USHORT  BigLba : 1;
    USHORT  Resrved3 : 5;
  } CommandSetSupport; // word 82-83
  USHORT  ReservedWord84;
  struct {
    USHORT  SmartCommands : 1;
    USHORT  SecurityMode : 1;
    USHORT  RemovableMedia : 1;
    USHORT  PowerManagement : 1;
    USHORT  Reserved1 : 1;
    USHORT  WriteCache : 1;
    USHORT  LookAhead : 1;
    USHORT  ReleaseInterrupt : 1;
    USHORT  ServiceInterrupt : 1;
    USHORT  DeviceReset : 1;
    USHORT  HostProtectedArea : 1;
    USHORT  Obsolete1 : 1;
    USHORT  WriteBuffer : 1;
    USHORT  ReadBuffer : 1;
    USHORT  Nop : 1;
    USHORT  Obsolete2 : 1;
    USHORT  DownloadMicrocode : 1;
    USHORT  DmaQueued : 1;
    USHORT  Cfa : 1;
    USHORT  AdvancedPm : 1;
    USHORT  Msn : 1;
    USHORT  PowerUpInStandby : 1;
    USHORT  ManualPowerUp : 1;
    USHORT  Reserved2 : 1;
    USHORT  SetMax : 1;
    USHORT  Acoustics : 1;
    USHORT  BigLba : 1;
    USHORT  Resrved3 : 5;
  } CommandSetActive; // word 85-86
  USHORT  ReservedWord87;
  USHORT  UltraDMASupport : 8; // word 88
  USHORT  UltraDMAActive  : 8;
  USHORT  ReservedWord89[4];
  USHORT  HardwareResetResult;
  USHORT  CurrentAcousticValue : 8;
  USHORT  RecommendedAcousticValue : 8;
  USHORT  ReservedWord95[5];
  ULONG  Max48BitLBA[2]; // word 100-103
  USHORT  ReservedWord104[23];
  USHORT  MsnSupport : 2;
  USHORT  ReservedWord127 : 14;
  USHORT  SecurityStatus;
  USHORT  ReservedWord129[126];
  USHORT  Signature : 8;
  USHORT  CheckSum : 8;
} IDENTIFY_DEVICE_DATA, *PIDENTIFY_DEVICE_DATA;

#pragma pack(pop)

#endif //KERNEL_H
