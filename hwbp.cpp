#include "hwbp.h"
#include "main.h"

cHWBP gHWBP;

HANDLE cHWBP::g_hHWBPHandler=NULL;
tRtlAddVectoredExceptionHandler cHWBP::RtlAddVectoredExceptionHandler=NULL;
tRtlRemoveVectoredExceptionHandler cHWBP::RtlRemoveVectoredExceptionHandler=NULL;
ptsHWBPList cHWBP::HWBPList=NULL;

cHWBP::cHWBP(DWORD ThreadId){
  dwThreadId=ThreadId;
  ZeroMemory(&HWBPFunc,sizeof(HWBPFunc));
  if(!RtlAddVectoredExceptionHandler){
    HMODULE hNtDll=GetModuleHandle("ntdll.dll");
    RtlAddVectoredExceptionHandler=(tRtlAddVectoredExceptionHandler)GetProcAddress(hNtDll,"RtlAddVectoredExceptionHandler");
    if(RtlAddVectoredExceptionHandler){
      g_hHWBPHandler=RtlAddVectoredExceptionHandler(1,HWBPHandler);
      Push();
    }
  }
}

cHWBP::~cHWBP(){
  if(g_hHWBPHandler&&Pop()){
    if(!RtlRemoveVectoredExceptionHandler){
      HMODULE hNtDll=GetModuleHandle("ntdll.dll");
      RtlRemoveVectoredExceptionHandler=(tRtlRemoveVectoredExceptionHandler)GetProcAddress(hNtDll,"RtlRemoveVectoredExceptionHandler");
    }
    if(RtlRemoveVectoredExceptionHandler)
      RtlRemoveVectoredExceptionHandler(g_hHWBPHandler);
  }
}

BOOL cHWBP::Init(DWORD ThreadId){
  dwThreadId=ThreadId;
  return (g_hHWBPHandler!=NULL);
}

LONG WINAPI cHWBP::HWBPHandler(PEXCEPTION_POINTERS ExceptionInfo){
  PVOID _this;//save this pointer for thiscall class methods!
  asm("mov %%ecx,%0;\r\t":"=m"(_this));
	if((int)ExceptionInfo->ExceptionRecord->ExceptionCode==EXCEPTION_SINGLE_STEP){
    cHWBP* pHWBP=cHWBP::Get(GetCurrentThreadId());
    if(pHWBP){
      UINT i;
      for(i=0;i<HWBP_MAXINDEX;i++){
        //function hwbp
        if(pHWBP->HWBPFunc[i].address&&ExceptionInfo->ExceptionRecord->ExceptionAddress==(PVOID)pHWBP->HWBPFunc[i].address){
          //change EIP
          ExceptionInfo->ContextRecord->Eip=(DWORD)pHWBP->HWBPFunc[i].newaddress;
          asm("mov %0,%%ecx;\r\t"::"m"(_this));
          return EXCEPTION_CONTINUE_EXECUTION;
        }
      }
	  }
	}
	asm("mov %0,%%ecx;\r\t"::"m"(_this));
	return EXCEPTION_CONTINUE_SEARCH;
}

PVOID cHWBP::SetBP(UINT index,PBYTE Address,PBYTE NewAddress){
  if(g_hHWBPHandler&&dwThreadId&&index<HWBP_MAXINDEX&&Address){
    //calc 1st instruction size
    UINT Len=IstructionSize((PBYTE)Address);
    if(!Len)return NULL;
    //copy orignal to us (jmp)
    PBYTE buff=(PBYTE)VirtualAlloc(NULL,Len+5,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!buff)return NULL;
    memmove(buff,Address,Len);
    *((PBYTE)buff+Len)=0xE9;
    *(DWORD*)((PBYTE)buff+Len+1)=(DWORD)(Address-(PBYTE)buff)-5;
    //set hwbp
    HWBPFunc[index].address=Address;
    HWBPFunc[index].newaddress=NewAddress;
    HWBPFunc[index].buffer=buff;
    // Prepare Hardware breakpoints
    BOOL bNeedSuspend=(dwThreadId!=GetCurrentThreadId());
    CONTEXT Context={CONTEXT_DEBUG_REGISTERS_EX};
    HANDLE hThread=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,FALSE,dwThreadId);
    if(hThread==INVALID_HANDLE_VALUE){
      return NULL;
    }
    // Set Hardware breakpoints
    if(bNeedSuspend)
      SuspendThread(hThread);
    GetThreadContext(hThread,&Context);
    switch(index){
      case 0:Context.Dr0=(DWORD)Address;break;
      case 1:Context.Dr1=(DWORD)Address;break;
      case 2:Context.Dr2=(DWORD)Address;break;
      default:Context.Dr3=(DWORD)Address;break;
    }
    Context.Dr6=0x00000000;
    Context.Dr7|=(1<<2*index);
    Context.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    if(!SetThreadContext(hThread,&Context)){
      VirtualFree(buff,0,MEM_RELEASE);
      HWBPFunc[index].buffer=NULL;
      buff=NULL;
    }
    if(bNeedSuspend)
      ResumeThread(hThread);
    CloseHandle(hThread);
    return buff;
	}
	return NULL;
}

BOOL cHWBP::UnsetBP(UINT index){
  if(g_hHWBPHandler&&dwThreadId&&index<HWBP_MAXINDEX){
    // Prepare Hardware breakpoints
    BOOL bNeedSuspend=(dwThreadId!=GetCurrentThreadId());
    CONTEXT Context={CONTEXT_DEBUG_REGISTERS_EX};
    HANDLE hThread=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,FALSE,dwThreadId);
    if(hThread==INVALID_HANDLE_VALUE){
      return FALSE;
    }
    // Set Hardware breakpoints
    if(bNeedSuspend)
      SuspendThread(hThread);
    GetThreadContext(hThread,&Context);
    switch(index){
      case 0:Context.Dr0=0;break;
      case 1:Context.Dr1=0;break;
      case 2:Context.Dr2=0;break;
      default:Context.Dr3=0;break;
    }
    Context.Dr6=0x00000000;
    Context.Dr7&=~(1<<2*index);
    Context.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(hThread,&Context);
    if(bNeedSuspend)
      ResumeThread(hThread);
    CloseHandle(hThread);
    //free buffer
    if(HWBPFunc[index].buffer)
      VirtualFree(HWBPFunc[index].buffer,0,MEM_RELEASE);
    HWBPFunc[index].address=NULL;
    HWBPFunc[index].newaddress=NULL;
    HWBPFunc[index].buffer=NULL;
    return TRUE;
	}
	return FALSE;
}

VOID cHWBP::Push(){
  ptsHWBPList tmp=(ptsHWBPList)LocalAlloc(0,sizeof(tsHWBPList));
  if(tmp){
    tmp->hwbp=this;
    tmp->next=HWBPList;
    HWBPList=tmp;
  }
}

BOOL cHWBP::Pop(){
  ptsHWBPList tmp=HWBPList,prev=NULL;
  while(tmp){
    if(tmp->hwbp==this){
      if(prev!=NULL)
        prev->next=tmp->next;
      else
        HWBPList=tmp->next;
      LocalFree(tmp);
      break;
    }
    prev=tmp;
    tmp=tmp->next;
  }
  return (HWBPList==NULL);
}

cHWBP *cHWBP::Get(DWORD dwThreadId){
  ptsHWBPList tmp=HWBPList;
  while(tmp){
    if(tmp->hwbp&&tmp->hwbp->dwThreadId==dwThreadId)
      return tmp->hwbp;
    tmp=tmp->next;
  }
  return NULL;
}
