#ifndef HWBP_H
#define HWBP_H

#include "utils.h"

#define CONTEXT_DEBUG_REGISTERS_EX 0xFFFFFFFF //for internal use whit driver...
#define HWBP_MAXINDEX 4

typedef struct _HWBPFUNC{
  PBYTE address;
  PBYTE newaddress;
  PBYTE buffer;//empty buffer is data hwbp...
}HWBPFUNC,*PHWBPFUNC;

typedef PVOID (WINAPI *tRtlAddVectoredExceptionHandler)(ULONG FirstHandler,PVECTORED_EXCEPTION_HANDLER VectoredHandler);
typedef ULONG (WINAPI *tRtlRemoveVectoredExceptionHandler)(PVOID);

class cHWBP;

typedef struct sHWBPList{
  class cHWBP *hwbp;
  struct sHWBPList *next;
}tsHWBPList,*ptsHWBPList;

class cHWBP{
  public:
    cHWBP(DWORD dwThreadId=0);
    ~cHWBP();
    BOOL Init(DWORD dwThreadId);
    PVOID SetBP(UINT index,PBYTE Address,PBYTE NewAddress);
    BOOL UnsetBP(UINT index);
    PHWBPFUNC GetBPInfo(UINT index);
  private:
    VOID Push();
    BOOL Pop();
    DWORD  dwThreadId;
    HWBPFUNC HWBPFunc[4];
  //statics...
    static cHWBP *Get(DWORD dwThreadId);
    static LONG WINAPI HWBPHandler(struct _EXCEPTION_POINTERS* ExceptionInfo);
    static tRtlAddVectoredExceptionHandler RtlAddVectoredExceptionHandler;
    static tRtlRemoveVectoredExceptionHandler RtlRemoveVectoredExceptionHandler;
    static HANDLE g_hHWBPHandler;
    static ptsHWBPList HWBPList;
};

extern cHWBP gHWBP;

#endif //HWBP_H
