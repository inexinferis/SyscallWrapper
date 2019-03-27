#ifndef SYSCALLER_H
#define SYSCALLER_H

#include <ddk/ntddk.h>

#define WUNKNOWN  (DWORD)-1
#define WINXP     0
#define WIN2K3    1
#define WINVISTA  2
#define WIN7      3
#define WIN8      4
#define WIN81     5
#define WIN10     6
#define WIN10TH2  7
#define WIN10AU   8
#define WIN10CU   9
#define WIN10FCU  10
#define WVERSIONS 11

BOOL SetServices();

extern HMODULE hAplication;
extern HMODULE hNtDll;
extern HMODULE hKernel32;
extern DWORD wversion,iswow64;
extern DWORD syscallTable[93][WVERSIONS];
extern DWORD wowsyscallTable[93][WVERSIONS];
extern "C" DWORD WINAPI GetFuncOffset(DWORD index);
extern "C" NTSTATUS FastSystemCall(DWORD _offset,...);

#ifndef NT_SUCCESS
  #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef NT_ERROR
  #define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)
#endif

#define _NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength) \
  FastSystemCall(0, TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)

#define _NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, AllocationSize, AllocationType, Protect) \
  FastSystemCall(1, ProcessHandle, BaseAddress, ZeroBits, AllocationSize, AllocationType, Protect)

#define _NtClearEvent(EventHandle) \
  FastSystemCall(2, EventHandle)

#define _NtClose(Handle) \
  FastSystemCall(3, Handle)

#define _NtCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState) \
  FastSystemCall(4, EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState)

#define _NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength) \
  FastSystemCall(5, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)

#define _NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition) \
  FastSystemCall(6, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)

#define _NtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner) \
  FastSystemCall(7, MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner)

#define _NtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, TypeMessage, ReadmodeMessage, Nonblocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTime) \
  FastSystemCall(8, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, TypeMessage, ReadmodeMessage, Nonblocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTime)

#define _NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort) \
  FastSystemCall(9, ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort)

#define _NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, SectionSize, Protect, Attributes, FileHandle) \
  FastSystemCall(10, SectionHandle, DesiredAccess, ObjectAttributes, SectionSize, Protect, Attributes, FileHandle)

#define _NtCreateSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount) \
  FastSystemCall(11, SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount)

#define _NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, UserStack, CreateSuspended) \
  FastSystemCall(12, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, UserStack, CreateSuspended)

#define _NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackZeroBits, dwSizeOfStackCommit, dwSizeOfStackReserve, lpBytesBuffer) \
  FastSystemCall(13, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackZeroBits, dwSizeOfStackCommit, dwSizeOfStackReserve, lpBytesBuffer)

#define _NtDelayExecution(Alertable, Interval) \
  FastSystemCall(14, Alertable, Interval)

#define _NtDeleteKey(KeyHandle) \
  FastSystemCall(15, KeyHandle)

#define _NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength) \
  FastSystemCall(16, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)

#define _NtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength) \
  FastSystemCall(17, KeyHandle, Index, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength)

#define _NtFlushInstructionCache(ProcessHandle, BaseAddress, FlushSize) \
  FastSystemCall(18, ProcessHandle, BaseAddress, FlushSize)

#define _NtFreeVirtualMemory(ProcessHandle, BaseAddress, FreeSize, FreeType) \
  FastSystemCall(19, ProcessHandle, BaseAddress, FreeSize, FreeType)

#define _NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength) \
  FastSystemCall(20, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)

#define _NtGetContextThread(ThreadHandle, Context) \
  FastSystemCall(21, ThreadHandle, Context)

#define _NtLoadDriver(DriverServiceName) \
  FastSystemCall(22, DriverServiceName)

#define _NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect) \
  FastSystemCall(23, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect)

#define _NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes) \
  FastSystemCall(24, DirectoryHandle, DesiredAccess, ObjectAttributes)

#define _NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes) \
  FastSystemCall(25, EventHandle, DesiredAccess, ObjectAttributes)

#define _NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions) \
  FastSystemCall(26, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions)

#define _NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes) \
  FastSystemCall(27, KeyHandle, DesiredAccess, ObjectAttributes)

#define _NtOpenMutant(MutantHandle, DesiredAccess, ObjectAttributes) \
  FastSystemCall(28, MutantHandle, DesiredAccess, ObjectAttributes)

#define _NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId) \
  FastSystemCall(29, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)

#define _NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle) \
  FastSystemCall(30, ProcessHandle, DesiredAccess, TokenHandle)

#define _NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes) \
  FastSystemCall(31, SectionHandle, DesiredAccess, ObjectAttributes)

#define _NtOpenSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes) \
  FastSystemCall(32, SemaphoreHandle, DesiredAccess, ObjectAttributes)

#define _NtOpenSymbolicLinkObject(SymbolicLinkHandle, DesiredAccess, ObjectAttributes) \
  FastSystemCall(33, SymbolicLinkHandle, DesiredAccess, ObjectAttributes)

#define _NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId) \
  FastSystemCall(34, ThreadHandle, DesiredAccess, ObjectAttributes, ClientId)

#define _NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle) \
  FastSystemCall(35, ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)

#define _NtProtectVirtualMemory(ProcessHandle, BaseAddress, ProtectSize, NewProtect, OldProtect) \
  FastSystemCall(36, ProcessHandle, BaseAddress, ProtectSize, NewProtect, OldProtect)

#define _NtPulseEvent(EventHandle, PreviousState) \
  FastSystemCall(37, EventHandle, PreviousState)

#define _NtQueryAttributesFile(ObjectAttributes, FileInformation) \
  FastSystemCall(38, ObjectAttributes, FileInformation)

#define _NtQueryDirectoryObject(DirectoryHandle, Buffer, BufferLength, ReturnSingleEntry, RestartScan, Context, ReturnLength) \
  FastSystemCall(39, DirectoryHandle, Buffer, BufferLength, ReturnSingleEntry, RestartScan, Context, ReturnLength)

#define _NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, FileInformationLength, FileInformationClass) \
  FastSystemCall(40, FileHandle, IoStatusBlock, FileInformation, FileInformationLength, FileInformationClass)

#define _NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength) \
  FastSystemCall(41, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)

#define _NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength) \
  FastSystemCall(42, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)

#define _NtQueryPerformanceCounter(PerformanceCount, PerformanceFrequency) \
  FastSystemCall(43, PerformanceCount, PerformanceFrequency)

#define _NtQuerySymbolicLinkObject(SymbolicLinkHandle, TargetName, ReturnLength) \
  FastSystemCall(44, SymbolicLinkHandle, TargetName, ReturnLength)

#define _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength) \
  FastSystemCall(45, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)

#define _NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength) \
  FastSystemCall(46, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength)

#define _NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength) \
  FastSystemCall(47, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength)

#define _NtRaiseHardError(Status, NumberOfArguments, StringArgumentsMask, Arguments, ResponseOption, Response) \
  FastSystemCall(48, Status, NumberOfArguments, StringArgumentsMask, Arguments, ResponseOption, Response)

#define _NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key) \
  FastSystemCall(49, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key)

#define _NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength) \
  FastSystemCall(50, ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength)

#define _NtReleaseMutant(MutantHandle, PreviousState) \
  FastSystemCall(51, MutantHandle, PreviousState)

#define _NtReleaseSemaphore(SemaphoreHandle, ReleaseCount, PPreviousCount) \
  FastSystemCall(52, SemaphoreHandle, ReleaseCount, PPreviousCount)

#define _NtResumeThread(ThreadHandle, PreviousSuspendCount) \
  FastSystemCall(53, ThreadHandle, PreviousSuspendCount)

#define _NtSetContextThread(ThreadHandle, Context) \
  FastSystemCall(54, ThreadHandle, Context)

#define _NtSetEvent(EventHandle, PreviousState) \
  FastSystemCall(55, EventHandle, PreviousState)

#define _NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, FileInformationLength, FileInformationClass) \
  FastSystemCall(56, FileHandle, IoStatusBlock, FileInformation, FileInformationLength, FileInformationClass)

#define _NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength) \
  FastSystemCall(57, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength)

#define _NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength) \
  FastSystemCall(58, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength)

#define _NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize) \
  FastSystemCall(59, KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)

#define _NtSuspendThread(ThreadHandle, PreviousSuspendCount) \
  FastSystemCall(60, ThreadHandle, PreviousSuspendCount)

#define _NtTerminateProcess(ProcessHandle, ExitStatus) \
  FastSystemCall(61, ProcessHandle, ExitStatus)

#define _NtTerminateThread(ThreadHandle, ExitStatus) \
  FastSystemCall(62, ThreadHandle, ExitStatus)

#define _NtUnloadDriver(DriverServiceName) \
  FastSystemCall(63, DriverServiceName)

#define _NtUnmapViewOfSection(ProcessHandle, BaseAddress) \
  FastSystemCall(64, ProcessHandle, BaseAddress)

#define _NtWaitForMultipleObjects(HandleCount, Handles, WaitType, Alertable, Time) \
  FastSystemCall(65, HandleCount, Handles, WaitType, Alertable, Time)

#define _NtWaitForSingleObject(Handle, Alertable, Time) \
  FastSystemCall(66, Handle, Alertable, Time)

#define _NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key) \
  FastSystemCall(67, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key)

#define _NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength) \
  FastSystemCall(68, ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength)

//win32k

#define _NtGdiBitBlt(hdcDst, x, y, cx, cy, hdcSrc, xSrc, ySrc, rop4, crBackColor, fl) \
	FastSystemCall(69, hdcDst, x, y, cx, cy, hdcSrc, xSrc, ySrc, rop4, crBackColor, fl)

#define _NtGdiCreateCompatibleBitmap(hdc, cx, cy) \
	FastSystemCall(70, hdc, cx, cy)

#define _NtGdiCreateCompatibleDC(hdc) \
	FastSystemCall(71, hdc)

#define _NtGdiDeleteObjectApp(hobj) \
	FastSystemCall(72, hobj)

#define _NtGdiExtSelectClipRgn(hDC, hGdiObj, iMode) \
	FastSystemCall(73, hDC, hGdiObj, iMode)

#define _NtGdiGetDIBitsInternal(hdc, hbm, iStartScan, cScans, pBits, pbmi, iUsage, cjMaxBits, cjMaxInfo) \
	FastSystemCall(74, hdc, hbm, iStartScan, cScans, pBits, pbmi, iUsage, cjMaxBits, cjMaxInfo)

#define _NtGdiPatBlt(hdcDst, x, y, cx, cy, rop4) \
	FastSystemCall(75, hdcDst, x, y, cx, cy, rop4)

#define _NtGdiSelectBrush(hDC, hGdiObj) \
	FastSystemCall(76, hDC, hGdiObj)

#define _NtGdiSelectFont(hDC, hGdiObj) \
	FastSystemCall(77, hDC, hGdiObj)

#define _NtGdiSelectPen(hDC, hGdiObj) \
	FastSystemCall(78, hDC, hGdiObj)

#define _NtGdiSetDIBitsToDeviceInternal(arg) \
	FastSystemCall(79, arg)

#define _NtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, BufSize, pWnd, pNeededBufSize) \
  FastSystemCall(80, hDesktop, hwndParent, bChildren, dwThreadId, BufSize, pWnd, pNeededBufSize)

#define _NtUserBuildHwndListEx(hUnknown, hDesktop, hwndParent, bChildren, dwThreadId, BufSize, pWnd, pNeededBufSize) \
  FastSystemCall(80, hUnknown, hDesktop, hwndParent, bChildren, dwThreadId, BufSize, pWnd, pNeededBufSize)

#define _NtUserCallOneParam(Param, Routine) \
  FastSystemCall(81,Param, Routine)

#define _NtUserFindWindowEx(hwndParent, hwndChildAfter, pucClassName, pucWindowName, dwType) \
	FastSystemCall(82, hwndParent, hwndChildAfter, pucClassName, pucWindowName, dwType)

#define _NtUserGetAsyncKeyState(vKey) \
  FastSystemCall(83,vKey)

#define _NtUserGetDC(arg) \
	FastSystemCall(84, arg)

#define _NtUserGetGUIThreadInfo(idThread, lpgui) \
	FastSystemCall(85, idThread, lpgui)

#define _NtUserGetWindowDC(arg) \
	FastSystemCall(86, arg)

#define _NtUserGetWindowPlacement(arg1, arg2) \
	FastSystemCall(87, arg1, arg2)

#define _NtUserPostMessage(hWnd, Msg, wParam, lParam) \
	FastSystemCall(88, hWnd, Msg, wParam, lParam)

#define _NtUserQueryWindow(hWnd, Index) \
  FastSystemCall(89,hWnd, Index)

#define _NtUserValidateHandleSecure(handle, Restricted) \
  FastSystemCall(90,handle, Restricted)

#define _NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi) \
	FastSystemCall(91, hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi)

#define _NtGdiSelectBitmap(hDC, hGdiObj) \
	FastSystemCall(92, hDC, hGdiObj)

#endif //SYSCALLER_H
