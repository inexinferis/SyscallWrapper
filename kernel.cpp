#include "kernel.h"
#include<limits.h>
#include "hwbp.h"

tDbgUiRemoteBreakin pDbgUiRemoteBreakin=NULL,oDbgUiRemoteBreakin=NULL;
tCsrGetProcessId pCsrGetProcessId=NULL,oCsrGetProcessId=NULL;
HANDLE hAntiDbgThread=NULL;

PIMAGE_NT_HEADERS WINAPI RtlImageNtHeader(PVOID base){
  if(base&&base!=(PVOID)-1){
    PIMAGE_DOS_HEADER pIDH=(PIMAGE_DOS_HEADER)base;
    if(pIDH->e_magic==IMAGE_DOS_SIGNATURE){
      if(pIDH->e_lfanew<0x10000000){
        PIMAGE_NT_HEADERS pINH=(PIMAGE_NT_HEADERS)((DWORD)base+pIDH->e_lfanew);
        if(pINH->Signature==IMAGE_NT_SIGNATURE)
          return pINH;
      }
    }
  }
  return NULL;
}

PIMAGE_SECTION_HEADER NTAPI RtlImageRvaToSection(PIMAGE_NT_HEADERS NtHeader,PVOID BaseAddress,ULONG Rva){
  ULONG Count=NtHeader->FileHeader.NumberOfSections;
  PIMAGE_SECTION_HEADER Section=IMAGE_FIRST_SECTION(NtHeader);
  while(Count--){
    ULONG Va=Section->VirtualAddress;
    if((Va<=Rva)&&(Rva<Va+Section->Misc.VirtualSize))
      return Section;
    Section++;
  }
  return NULL;
}

PVOID NTAPI RtlImageRvaToVa(PIMAGE_NT_HEADERS NtHeader,PVOID BaseAddress,ULONG Rva,PIMAGE_SECTION_HEADER *SectionHeader){
  PIMAGE_SECTION_HEADER Section=NULL;
  if(SectionHeader)
    Section=*SectionHeader;
  if(!NtHeader){
    NtHeader=RtlImageNtHeader(BaseAddress);
    if(!NtHeader)
      return NULL;
  }
  if(Section==NULL||Rva<Section->VirtualAddress||
    Rva>=Section->VirtualAddress+Section->Misc.VirtualSize){
    Section=RtlImageRvaToSection(NtHeader,BaseAddress,Rva);
    if(Section==NULL)
      return 0;
    if(SectionHeader)
      *SectionHeader=Section;
  }
  return (PVOID)((ULONG_PTR)BaseAddress+Rva+
    Section->PointerToRawData-(ULONG_PTR)Section->VirtualAddress);
}

PIMAGE_SECTION_HEADER RtlGetSectionHeader(PIMAGE_NT_HEADERS NtHeader,UINT nsec){
  return (PIMAGE_SECTION_HEADER)(
    (LPBYTE)&NtHeader->OptionalHeader+NtHeader->FileHeader.SizeOfOptionalHeader+
    (nsec*sizeof(IMAGE_SECTION_HEADER))
  );
}

PVOID WINAPI RtlImageDirectoryEntryToData(PVOID BaseAddress,BOOL MappedAsImage,USHORT Directory,PULONG Size){
  PIMAGE_NT_HEADERS NtHeader;ULONG Va;
  if((ULONG_PTR)BaseAddress&1){
    BaseAddress=(PVOID)((ULONG_PTR)BaseAddress&~1);
    MappedAsImage=FALSE;
  }
  NtHeader=RtlImageNtHeader(BaseAddress);
  if(NtHeader==NULL)
    return NULL;
  if(Directory>=NtHeader->OptionalHeader.NumberOfRvaAndSizes)
    return NULL;
  Va=NtHeader->OptionalHeader.DataDirectory[Directory].VirtualAddress;
  if(Va==0)
    return NULL;
  if(Size)
  *Size=NtHeader->OptionalHeader.DataDirectory[Directory].Size;
  if(MappedAsImage||Va<NtHeader->OptionalHeader.SizeOfHeaders)
    return (PVOID)((ULONG_PTR)BaseAddress+Va);
  return RtlImageRvaToVa(NtHeader,BaseAddress,Va,NULL);
}

LPVOID WINAPI RtlGetRawSectionPtr(DWORD imageBase,LPCSTR name,PIMAGE_NT_HEADERS pNTHeader,PULONG Size){
  PIMAGE_SECTION_HEADER section=IMAGE_FIRST_SECTION(pNTHeader);
  for(UINT i=0;i<pNTHeader->FileHeader.NumberOfSections;i++,section++){
    if(!strnicmp((PCHAR)section->Name,name,IMAGE_SIZEOF_SHORT_NAME)){
      if(Size)*Size=section->SizeOfRawData;
      return RVAPTR(LPVOID,imageBase,section->PointerToRawData);
    }
  }
  return NULL;
}

PVOID RtlFindRawResourceDirectory(PVOID pBase,BOOL IsImage,PIMAGE_RESOURCE_DIRECTORY resDir,DWORD rBase,DWORD rType,DWORD rId,PDWORD pSize);
PVOID RtlFindRawResourceEntry(PVOID pBase,BOOL IsImage,PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry,DWORD rBase,DWORD rType,DWORD rId,PDWORD pSize){
  if(resDirEntry->DataIsDirectory)
    return RtlFindRawResourceDirectory(pBase,IsImage,RVAPTR(PIMAGE_RESOURCE_DIRECTORY,rBase,resDirEntry->OffsetToDirectory),rBase,rId,0,pSize);
  PIMAGE_RESOURCE_DATA_ENTRY pData=RVAPTR(PIMAGE_RESOURCE_DATA_ENTRY,(DWORD)rBase,resDirEntry->OffsetToData);
  if(pSize)*pSize=pData->Size;
  if(IsImage)return (PVOID)((ULONG_PTR)pBase+pData->OffsetToData);
  return (PVOID)RtlImageRvaToVa(NULL,pBase,pData->OffsetToData,NULL);
}

PVOID RtlFindRawResourceDirectory(PVOID pBase,BOOL IsImage,PIMAGE_RESOURCE_DIRECTORY resDir,DWORD rBase,DWORD rType,DWORD rId,PDWORD pSize){
  DWORD nEntries=resDir->NumberOfNamedEntries;
  nEntries+=resDir->NumberOfIdEntries;
  PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry=(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir+1);
  for(UINT i=0;i<nEntries;i++){
    if(resDirEntry[i].Id==rType||!rType)
      return RtlFindRawResourceEntry(pBase,IsImage,&resDirEntry[i],rBase,rType,rId,pSize);
  }
  return NULL;
}

PVOID WINAPI RtlFindRawResource(PVOID pBase,BOOL IsImage,DWORD rType,DWORD rId,PDWORD pSize){
  PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pBase;
  if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
    return NULL;
  PIMAGE_NT_HEADERS pNtHeader=RVAPTR(PIMAGE_NT_HEADERS,pDosHeader,pDosHeader->e_lfanew);
  if(pNtHeader->Signature!=IMAGE_NT_SIGNATURE)
    return NULL;
  PIMAGE_RESOURCE_DIRECTORY resDir=(PIMAGE_RESOURCE_DIRECTORY)
    RtlImageDirectoryEntryToData(pBase,IsImage,IMAGE_DIRECTORY_ENTRY_RESOURCE,NULL);
  if(!resDir)
    return NULL;
  return RtlFindRawResourceDirectory(pBase,IsImage,resDir,(DWORD)resDir,rType,rId,pSize);
}

PVOID WINAPI RtlFindResource(HMODULE hModule,DWORD rId,DWORD rType,PDWORD pSize){
  return RtlFindRawResource((PVOID)hModule,TRUE,rType,rId,pSize);
}

BOOL WINAPI RtlGetModuleVersion(HMODULE hModule,DLLVERSIONINFO *aVersion){
  PBYTE info=(PBYTE)RtlFindRawResource((PVOID)hModule,TRUE,16,VS_VERSION_INFO,NULL);
  if(info){
    VS_FIXEDFILEINFO* vsfi=(VS_FIXEDFILEINFO*)(info+40);
    if(0xfeef04bd==vsfi->dwSignature){
      aVersion->dwMajorVersion=HIWORD(vsfi->dwFileVersionMS);
      aVersion->dwMinorVersion=LOWORD(vsfi->dwFileVersionMS);
      aVersion->dwBuildNumber=HIWORD(vsfi->dwFileVersionLS);
      aVersion->dwPlatformID=LOWORD(vsfi->dwFileVersionLS);
      return TRUE;
    }
  }
  return FALSE;
}

BOOL WINAPI RtlVerQueryValue(LPCVOID pBlock,LPCSTR lpSubBlock,LPVOID *lplpBuffer,PUINT puLen){
  static const char rootA[] = "\\";
  static const char varfileinfoA[] = "\\VarFileInfo\\Translation";
  if(!pBlock||!lplpBuffer)
    return FALSE;

  const VS_VERSION_INFO_STRUCT16 *info16=(const VS_VERSION_INFO_STRUCT16 *)pBlock;
  if(lpSubBlock==NULL||lpSubBlock[0]=='\0')
    lpSubBlock=rootA;

  if(!VersionInfoIs16(info16)){
    const VS_VERSION_INFO_STRUCT32 *info32=(const VS_VERSION_INFO_STRUCT32 *)pBlock;
    BOOL ret=FALSE;
    LPWSTR lpSubBlockW=RtlCreateWideCharFromMultiByte(lpSubBlock,-1);
    if(!lpSubBlockW)
      return FALSE;
    LPCWSTR lpStrW=lpSubBlockW;
    while(*lpStrW){
      LPCWSTR lpNextSlashW;
      for(lpNextSlashW=lpStrW;*lpNextSlashW;lpNextSlashW++)
        if(*lpNextSlashW=='\\')
          break;
      if(lpNextSlashW==lpStrW){
        lpStrW++;
        continue;
      }
      const VS_VERSION_INFO_STRUCT32 *child32=VersionInfo32_Children(info32);
      for(;child32;){
        if((char *)child32>(char *)info32+info32->wLength){
          info32=NULL;
          break;
        }
        if(!wcsnicmp(child32->szKey,lpStrW,lpNextSlashW-lpStrW)&&!child32->szKey[lpNextSlashW-lpStrW]){
          info32=child32;
          break;
        }
        if(!(child32->wLength)){
          info32=NULL;
          break;
        }
        child32=VersionInfo32_Next(child32);
      }
      if(!info32){
        if(puLen)*puLen=0;
        break;
      }
      lpStrW=lpNextSlashW;
    }
    if(info32){
      *lplpBuffer=VersionInfo32_Value(info32);
      if(puLen)
        *puLen=info32->wValueLength;
      ret=TRUE;
    }
    RtlFreeWideCharString(lpSubBlockW);
    if(ret&&stricmp(lpSubBlock,rootA)&&stricmp(lpSubBlock,varfileinfoA)){
      *lplpBuffer=(LPVOID)RtlCreateMultiByteFromWideChar((LPCWSTR)*lplpBuffer,-1);
      if(puLen)
        *puLen=info32->wValueLength/sizeof(WCHAR);
    }
    return ret;
  }

  while(*lpSubBlock){
    LPCSTR lpNextSlash;
    for(lpNextSlash=lpSubBlock;*lpNextSlash;lpNextSlash++)
      if(*lpNextSlash=='\\')
        break;
    if(lpNextSlash==lpSubBlock){
      lpSubBlock++;
      continue;
    }
    const VS_VERSION_INFO_STRUCT16 *child16=VersionInfo16_Children(info16);
    for(;child16;){
      if((char *)child16>(char *)info16+info16->wLength){
        info16=NULL;
        break;
      }
      if(!strnicmp(child16->szKey,lpSubBlock,lpNextSlash-lpSubBlock)&&!child16->szKey[lpNextSlash-lpSubBlock]){
        info16=child16;
        break;
      }
      if(!(child16->wLength)){
        info16=NULL;
        break;
      }
      child16=VersionInfo16_Next(child16);
    }
    if(!info16){
      if(puLen)*puLen=0;
      break;
    }
    lpSubBlock=lpNextSlash;
  }
  if(info16){
    *lplpBuffer=VersionInfo16_Value(info16);
    if(puLen)
      *puLen=info16->wValueLength;
    return TRUE;
  }
  return FALSE;
}

ULONG WINAPI RtlNtStatusToDosError(NTSTATUS status){
  PTEB Teb=NtCurrentTeb();
  if(NULL!=Teb)
     Teb->LastStatusValue=status;
  if(!status||(status&0x20000000))
    return status;
  // 0xd... is equivalent to 0xc...
  if((status&0xf0000000)==0xd0000000)
    status&=~0x10000000;

  if((unsigned)status==0xC0000035)return ERROR_ALREADY_EXISTS;
  //if(status==0x80070241)return ERROR_INVALID_IMAGE_HASH;

  // now some special cases
  if(HIWORD(status)==0xc001)return LOWORD(status);
  if(HIWORD(status)==0x8007)return LOWORD(status);
  return status;
}

// ******************************************************************************
// Rtl util functions
// ******************************************************************************

VOID WINAPI RtlEmpyUnicodeString(PUNICODE_STRING DestinationString,LPCWSTR SourceString,USHORT Length){
  DestinationString->Buffer=(LPWSTR)SourceString;
  DestinationString->Length=0;
  DestinationString->MaximumLength=Length;
}

VOID WINAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString,LPCWSTR SourceString){
  if(SourceString){
    ULONG DestSize=wcslen(SourceString)*sizeof(WCHAR);
    //if(DestSize>(USHRT_MAX-sizeof(WCHAR)))return STATUS_NAME_TOO_LONG;
    DestinationString->Length=DestSize;
    DestinationString->MaximumLength=DestSize+sizeof(UNICODE_NULL);
  }else{
    DestinationString->Length=0;
    DestinationString->MaximumLength=0;
  }
  DestinationString->Buffer=(LPWSTR)SourceString;
  //return STATUS_SUCCESS;
}

VOID WINAPI RtlEmpyAnsiString(PANSI_STRING DestinationString,LPCSTR SourceString,USHORT Length){
  DestinationString->Buffer=(LPSTR)SourceString;
  DestinationString->Length=0;
  DestinationString->MaximumLength=Length;
}

VOID WINAPI RtlInitAnsiString(PANSI_STRING DestinationString,LPCSTR SourceString){
  ULONG DestSize;
  if(SourceString){
    DestSize=strlen(SourceString)*sizeof(CHAR);
    //if(DestSize>(USHRT_MAX-sizeof(CHAR)))return STATUS_NAME_TOO_LONG;
    DestinationString->Length=DestSize;
    DestinationString->MaximumLength=DestSize+sizeof(ANSI_NULL);
  }else{
    DestinationString->Length=0;
    DestinationString->MaximumLength=0;
  }
  DestinationString->Buffer=(LPSTR)SourceString;
  //return STATUS_SUCCESS;
}

ULONG WINAPI RtlMultiByteToUnicode(LPWSTR UnicodeString,ULONG UnicodeSize,LPCSTR MbString,ULONG MbSize){
  ULONG i;
  if(MbSize==(ULONG)-1)
    MbSize=(strlen(MbString)+1)*sizeof(CHAR);
  if(!UnicodeSize)
    return MbSize/sizeof(CHAR);
  PCSTR MbEnd=MbString+MbSize;
  for(i=0;i<UnicodeSize/sizeof(WCHAR)&&MbString<MbEnd;i++)
    //No Unicode table so use only basic ANSI chars
    *UnicodeString++=*(PUCHAR)MbString++;
  return i;
}

ULONG WINAPI RtlUnicodeToMultiByte(LPSTR MbString,ULONG MbSize,LPCWSTR UnicodeString,ULONG UnicodeSize){
  ULONG i;
  if(UnicodeSize==(ULONG)-1)
    UnicodeSize=(wcslen(UnicodeString)+1)*sizeof(WCHAR);
  if(!MbSize)
    return UnicodeSize/sizeof(WCHAR);
  PCWSTR UnicodeEnd=(PCWSTR)((ULONG)UnicodeString+UnicodeSize);
  for(i=0;i<MbSize/sizeof(CHAR)&&UnicodeString<UnicodeEnd;i++)
    //No Unicode table so use only basic ANSI chars
    *MbString++=LOBYTE(*UnicodeString++);
  return i;
}

INT WINAPI WideCharToMultiByte(UINT CodePage,DWORD Flags,LPCWSTR WideCharString,INT WideCharCount,
  LPSTR MultiByteString,INT MultiByteCount,LPCSTR DefaultChar,LPBOOL UsedDefaultChar){
  if(WideCharString==NULL||WideCharCount==0||(MultiByteString==NULL&&MultiByteCount>0)||
    (PVOID)WideCharString==(PVOID)MultiByteString||MultiByteCount<0)
    return 0;
  if(WideCharCount<0)
    WideCharCount=wcslen(WideCharString)+1;
  if(!MultiByteCount)
    return WideCharCount;
  WideCharCount*=sizeof(WCHAR);
  return RtlUnicodeToMultiByte(MultiByteString,MultiByteCount,WideCharString,WideCharCount);
}

INT WINAPI MultiByteToWideChar(UINT CodePage,DWORD Flags,LPCSTR MultiByteString,INT MultiByteCount,
  LPWSTR WideCharString,INT WideCharCount){
  if(MultiByteString==NULL||MultiByteCount==0||(WideCharString==NULL&&WideCharCount>0)||
    (PVOID)MultiByteString==(PVOID)WideCharString)
    return 0;
  if(MultiByteCount<0)
    MultiByteCount=strlen(MultiByteString)+1;
  if(!WideCharCount)
    return MultiByteCount;
  WideCharCount*=sizeof(WCHAR);
  return RtlMultiByteToUnicode(WideCharString,WideCharCount,MultiByteString,MultiByteCount);
}

NTSTATUS WINAPI RtlAllocateUnicodeString(PUNICODE_STRING UnicodeString,ULONG MaximumLength){
  if(UnicodeString){
    if(MaximumLength>USHRT_MAX)return STATUS_NAME_TOO_LONG;
    UnicodeString->Buffer=(WCHAR*)RtlAllocateHeap(RtlGetProcessHeap(),0,MaximumLength+sizeof(UNICODE_NULL));
    if(!UnicodeString->Buffer)return STATUS_NO_MEMORY;
    UnicodeString->MaximumLength=(USHORT)MaximumLength;
    UnicodeString->Length=0;
  }
  return STATUS_SUCCESS;
}

NTSTATUS WINAPI RtlAllocateAnsiString(PANSI_STRING AnsiString,ULONG MaximumLength){
  if(AnsiString){
    if(MaximumLength>USHRT_MAX)return STATUS_NAME_TOO_LONG;
    AnsiString->Buffer=(CHAR*)RtlAllocateHeap(RtlGetProcessHeap(),0,MaximumLength+sizeof(ANSI_NULL));
    if(!AnsiString->Buffer)return STATUS_NO_MEMORY;
    AnsiString->MaximumLength=(USHORT)MaximumLength;
    AnsiString->Length=0;
  }
  return STATUS_SUCCESS;
}

VOID WINAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString){
  if(UnicodeString&&UnicodeString->Buffer){
    RtlFreeHeap(RtlGetProcessHeap(),0,UnicodeString->Buffer);
    RtlZeroMemory(UnicodeString,sizeof(UNICODE_STRING));
  }
}

VOID WINAPI RtlFreeAnsiString(PANSI_STRING AnsiString){
  if(AnsiString&&AnsiString->Buffer){
    RtlFreeHeap(RtlGetProcessHeap(),0,AnsiString->Buffer);
    RtlZeroMemory(AnsiString,sizeof(ANSI_STRING));
  }
}

VOID WINAPI RtlCopyUnicodeString(PUNICODE_STRING DestinationString,PUNICODE_STRING SourceString){
  ULONG SourceLength;
  if(SourceString==NULL)
    DestinationString->Length=0;
  else{
    SourceLength=min(DestinationString->MaximumLength,SourceString->Length);
    DestinationString->Length=(USHORT)SourceLength;
    RtlCopyMemory(DestinationString->Buffer,SourceString->Buffer,SourceLength);
    if(DestinationString->Length<DestinationString->MaximumLength)
      DestinationString->Buffer[SourceLength/sizeof(WCHAR)]=UNICODE_NULL;
  }
}

BOOLEAN WINAPI RtlCreateUnicodeString(PUNICODE_STRING UniDest,PCWSTR Source){
  ULONG Length=(wcslen(Source)+1)*sizeof(WCHAR);
  if(Length>USHRT_MAX)return FALSE;
  if(!NT_SUCCESS(RtlAllocateUnicodeString(UniDest,Length)))
    return FALSE;
  RtlCopyMemory(UniDest->Buffer,Source,Length);
  UniDest->MaximumLength=(USHORT)Length;
  UniDest->Length=(USHORT)Length-sizeof(WCHAR);
  return TRUE;
}

NTSTATUS WINAPI RtlAnsiStringToUnicodeString(PUNICODE_STRING UniDest,PANSI_STRING AnsiSource,BOOL AllocateDestinationString){
  ULONG RetLen=0,Length=AnsiSource->Length*sizeof(WCHAR)+sizeof(UNICODE_NULL);
  if(Length>USHRT_MAX)return STATUS_INVALID_PARAMETER_2;
  if(AllocateDestinationString&&!NT_SUCCESS(RtlAllocateUnicodeString(UniDest,Length)))
    return STATUS_NO_MEMORY;
  else if((Length-sizeof(WCHAR))>=UniDest->MaximumLength)
    return STATUS_BUFFER_OVERFLOW;
  UniDest->Length=Length-sizeof(UNICODE_NULL);
  RetLen=RtlMultiByteToUnicode(UniDest->Buffer,UniDest->Length,AnsiSource->Buffer,AnsiSource->Length);
  UniDest->Buffer[RetLen]=UNICODE_NULL;
  return RetLen;
}

NTSTATUS WINAPI RtlUnicodeStringToAnsiString(PANSI_STRING AnsiDest,PUNICODE_STRING UniSource,BOOL AllocateDestinationString){
  ULONG RetLen=0,Length=UniSource->Length/sizeof(WCHAR)+sizeof(ANSI_NULL);
  if(Length>USHRT_MAX)return STATUS_INVALID_PARAMETER_2;
  if(AllocateDestinationString&&!NT_SUCCESS(RtlAllocateAnsiString(AnsiDest,Length)))
    return STATUS_NO_MEMORY;
  else if((Length-sizeof(CHAR))>=AnsiDest->MaximumLength)
    return STATUS_BUFFER_OVERFLOW;
  AnsiDest->Length=Length-sizeof(ANSI_NULL);
  RetLen=RtlUnicodeToMultiByte(AnsiDest->Buffer,AnsiDest->Length,UniSource->Buffer,UniSource->Length);
  AnsiDest->Buffer[RetLen]=ANSI_NULL;
  return RetLen;
}

BOOLEAN WINAPI RtlCreateUnicodeStringFromAsciiz(PUNICODE_STRING Destination,PCSZ Source){
  ANSI_STRING AnsiString;
  RtlInitAnsiString(&AnsiString, Source);
  return NT_SUCCESS(RtlAnsiStringToUnicodeString(Destination,&AnsiString,TRUE));
}

/*VOID WINAPI RtlAnsiStringToWideString(LPCSTR AnsiString,LPWSTR *UnicodeString){
  ANSI_STRING AnsiTemp;UNICODE_STRING UnicodeTemp;
  RtlInitAnsiString(&AnsiTemp, AnsiString);
  if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&UnicodeTemp,&AnsiTemp,TRUE)))
    *UnicodeString = UnicodeTemp.Buffer;
  else
    *UnicodeString = NULL;
}*/

LPWSTR WINAPI RtlCreateWideCharFromMultiByte(LPCSTR MultiByteString,INT MultiByteCount){
  LPWSTR WideCharString=NULL;DWORD WideCharCount=0;
  if(!MultiByteString||!MultiByteCount)
    return NULL;
  if(MultiByteCount==-1)
    MultiByteCount=(strlen(MultiByteString)+1)*sizeof(ANSI_NULL);
  WideCharCount=MultiByteCount*sizeof(UNICODE_NULL);
  WideCharString=(WCHAR*)RtlAllocateHeap(RtlGetProcessHeap(),0,WideCharCount);
  if(!WideCharString)
    return NULL;
  RtlMultiByteToUnicode(WideCharString,WideCharCount,MultiByteString,MultiByteCount);
  return WideCharString;
}

LPSTR WINAPI RtlCreateMultiByteFromWideChar(LPCWSTR WideCharString,INT WideCharCount){
  LPSTR MultiByteString=NULL;DWORD MultiByteCount=0;
  if(!WideCharString||!WideCharCount)
    return NULL;
  if(WideCharCount==-1)
    WideCharCount=(wcslen(WideCharString)+1)*sizeof(UNICODE_NULL);
  MultiByteCount=WideCharCount/sizeof(UNICODE_NULL);
  MultiByteString=(CHAR*)RtlAllocateHeap(RtlGetProcessHeap(),0,MultiByteCount);
  if(!WideCharString)
    return NULL;
  RtlUnicodeToMultiByte(MultiByteString,MultiByteCount,WideCharString,WideCharCount);
  return MultiByteString;
}

VOID WINAPI RtlFreeWideCharString(LPWSTR WideCharString){
  if(WideCharString)
    RtlFreeHeap(RtlGetProcessHeap(),0,WideCharString);
}

VOID WINAPI RtlFreeMultiByteString(LPSTR MultiByteString){
  if(MultiByteString)
    RtlFreeHeap(RtlGetProcessHeap(),0,MultiByteString);
}

WCHAR WINAPI RtlUpcaseUnicodeChar(WCHAR Source){
  if(Source>=L'a'&&Source<=L'z')
    return (Source-(L'a'-L'A'));
  return Source;
}

WCHAR WINAPI RtlDowncaseUnicodeChar(IN WCHAR Source){
  if(Source>=L'A'&&Source<=L'Z')
    return Source+(L'a'-L'A');
  return Source;
}

NTSTATUS WINAPI RtlCharToInteger(PCSZ str,ULONG base,PULONG value){
  BOOL bMinus=FALSE;INT digit;ULONG RunningTotal=0;
  if(!value)
    return STATUS_ACCESS_VIOLATION;
  while(*str!='\0'&&*str<=' ')str++;
  if(*str=='+')str++;
  else if(*str=='-'){
    bMinus=TRUE;
    str++;
  }
  if(base==0){
    base=10;
    if(str[0]=='0'){
      if(str[1]=='b'){
        str+=2;
        base=2;
      }else if(str[1]=='o'){
        str+=2;
        base=8;
      }else if(str[1]=='x'){
        str+=2;
        base=16;
      }
    }
  }else if(base!=2&&base!=8&&base!=10&&base!=16)
    return STATUS_INVALID_PARAMETER;
  while(*str!='\0'){
    if(*str>='0'&&*str<='9')
      digit=*str-'0';
    else if(*str>='A'&&*str<='Z')
      digit=*str-'A'+10;
    else if(*str>='a'&&*str<='z')
      digit=*str-'a'+10;
    else
      digit=-1;
    if(digit<0||digit>=(int)base){
      *value=bMinus?-RunningTotal:RunningTotal;
      return STATUS_SUCCESS;
    }
    RunningTotal=RunningTotal*base+digit;
    str++;
  }
  *value=bMinus?-RunningTotal:RunningTotal;
  return STATUS_SUCCESS;
}

LONG WINAPI RtlCompareUnicodeString(PCUNICODE_STRING s1,PCUNICODE_STRING s2,BOOL CaseInsensitive){
  UINT len=min(s1->Length,s2->Length)/sizeof(WCHAR);
  LPCWSTR p1=s1->Buffer;
  LPCWSTR p2=s2->Buffer;
  LONG ret=0;
  if(CaseInsensitive)
    while(!ret&&len--)
      ret=RtlUpcaseUnicodeChar(*p1++)-RtlUpcaseUnicodeChar(*p2++);
  else
    while(!ret&&len--)
      ret=*p1++-*p2++;
  if(!ret)
    ret=s1->Length-s2->Length;
  return ret;
}

BOOL WINAPI RtlEqualUnicodeString(CONST UNICODE_STRING *s1,CONST UNICODE_STRING *s2,BOOL CaseInsensitive){
  if(s1->Length!=s2->Length)return FALSE;
  return !RtlCompareUnicodeString(s1,s2,CaseInsensitive);
}

ULONG WINAPI RtlGetCurrentDirectory(ULONG MaximumLength,PWSTR Buffer){
  PCURDIR CurDir=&NtCurrentPeb()->ProcessParameters->CurrentDirectory;
  PWSTR CurDirName=CurDir->DosPath.Buffer;
  ULONG Length=CurDir->DosPath.Length/sizeof(WCHAR);
  if((CurDirName!=NULL)&&(Length>0)){
    ULONG Bytes=Length*sizeof(WCHAR);
    if(MaximumLength<=Bytes){
      if((Length<2)||(Buffer[Length-2]!=L':'))
        return Bytes+sizeof(WCHAR);
      return Bytes;
    }
    RtlCopyMemory(Buffer,CurDirName,Bytes);
    if((Length<2)||(Buffer[Length-2]!=L':')){
      Buffer[Length-1]=UNICODE_NULL;
      --Length;
    }else
      Buffer[Length]=UNICODE_NULL;
  }
  return Length*sizeof(WCHAR);
}

NTSTATUS WINAPI RtlQueryEnvironmentVariable(PWSTR Environment,PUNICODE_STRING Name,PUNICODE_STRING Value){
  NTSTATUS Status;UNICODE_STRING var;
  if(Environment==NULL)
    Environment=NtCurrentPeb()->ProcessParameters->Environment;
  if(Environment==NULL)
    return(STATUS_VARIABLE_NOT_FOUND);
  Value->Length=0;
  PWSTR wcs=Environment;
  while(*wcs){
    var.Buffer=wcs++;
    wcs=wcschr(wcs,L'=');
    if(wcs==NULL)
      wcs=var.Buffer+wcslen(var.Buffer);
    if(*wcs){
      var.Length=var.MaximumLength=(wcs-var.Buffer)*sizeof(WCHAR);
      PWSTR val=++wcs;
      wcs+=wcslen(wcs);
      if(!RtlCompareUnicodeString((PCUNICODE_STRING)&var,Name,TRUE)){
        Value->Length=(wcs-val)*sizeof(WCHAR);
        if(Value->Length<=Value->MaximumLength){
          memcpy(Value->Buffer,val,min(Value->Length+sizeof(WCHAR),Value->MaximumLength));
          Status=STATUS_SUCCESS;
        }else
          Status=STATUS_BUFFER_TOO_SMALL;
        return(Status);
      }
    }
    wcs++;
  }
  return(STATUS_VARIABLE_NOT_FOUND);
}

DOS_PATH_TYPE WINAPI RtlDetermineDosPathNameType(PCUNICODE_STRING UPath){
  if(!UPath)return RTL_INVALID_PATH;
  PWCHAR path=UPath->Buffer;
  ULONG chars=UPath->Length/sizeof(WCHAR);
  if(!chars)return RTL_INVALID_PATH;
  if(IS_SEPARATOR(path[0])){
    if((chars<2)||!IS_SEPARATOR(path[1]))
      return RTL_ABSOLUTE_PATH;         // "\" or "\foo"
    if((chars<3)||((path[2]!= L'.')&&(path[2]!= L'?')))
      return RTL_UNC_PATH;              // "\\" or "\\foo"
    if((chars>3)&&IS_SEPARATOR(path[3]))
      return RTL_DEVICE_PATH;           // "\\.\foo" or "\\?\foo"
    if(chars!=3)
      return RTL_UNC_PATH;              // "\\.foo" or "\\?foo"
    return RTL_UNC_DOT_PATH;            // "\\." or "\\?"
  }else{
    if((chars<2)||(path[1]!=L':'))
      return RTL_RELATIVE_PATH;         // "f" or "foo"
    if((chars>2)&&(IS_SEPARATOR(path[2])))
      return RTL_ABSOLUTE_DRIVE_PATH;   // "c:\foo"
    return RTL_RELATIVE_DRIVE_PATH;     // "c:foo"
  }
}

BOOL WINAPI MakeRedirection(PWSTR FileDir){
  WCHAR Windir[MAX_PATH];
  UINT len=GetWindowsDirectoryW(Windir,sizeof(Windir));
  if(!_wcsnicmp(FileDir,Windir,len)){
    PWSTR p=&FileDir[len+1];
    if(!_wcsnicmp(p,L"System32\\catroot",16)||
       !_wcsnicmp(p,L"System32\\drivers",16)||
       !_wcsnicmp(p,L"System32\\logfiles",17)||
       !_wcsnicmp(p,L"System32\\spool",14))
      return FALSE;
    if(!_wcsnicmp(p,L"System32",8)){
      wcsncpy(p,L"SysWOW64",8);
      return TRUE;
    }
  }
  return FALSE;
}

static BOOL bDoFsRedirection=TRUE;
VOID RtlWow64EnableFsRedirection(BOOL bEnable){
  typedef VOID (WINAPI *tRtlWow64EnableFsRedirection)(BOOL bEnable);
  static tRtlWow64EnableFsRedirection pRtlWow64EnableFsRedirection=NULL;
  CHAR sBuffer[MAX_PATH];
  if(!pRtlWow64EnableFsRedirection){
    HMODULE hNtDll=GetModuleHandle("ntdll.dll");
    pRtlWow64EnableFsRedirection=(tRtlWow64EnableFsRedirection)GetProcAddress(hNtDll,"RtlWow64EnableFsRedirection");
  }
  if(pRtlWow64EnableFsRedirection)
    pRtlWow64EnableFsRedirection(bEnable);
  bDoFsRedirection=bEnable;
}

NTSTATUS WINAPI RtlDosPathNameToNtPathName(PCUNICODE_STRING DosName,PUNICODE_STRING NtName,PCWSTR *PartName){
  #define RTL_NTROOTSLASH_LENGTH   8
  if(!NtName||!DosName||!DosName->Length||!DosName->Buffer||DosName->Buffer[0]==UNICODE_NULL)
    return STATUS_OBJECT_NAME_INVALID;
  PWCHAR NameBuffer=DosName->Buffer;
  ULONG NameLength=DosName->Length;
  if((NameLength>RTL_NTROOTSLASH_LENGTH)&&(NameBuffer[0]==L'\\')&&(NameBuffer[1]==L'\\')&&(NameBuffer[2]==L'?')&&(NameBuffer[3]==L'\\')){
    if(NameLength>=UNICODE_STRING_MAX_BYTES)
      return STATUS_NAME_TOO_LONG;
    NtName->Buffer=(PWCHAR)RtlAllocateHeap(RtlGetProcessHeap(),0,NameLength+sizeof(UNICODE_NULL));
    if(!NtName->Buffer)return STATUS_NO_MEMORY;
    NtName->Length=NameLength;
    NtName->MaximumLength=NameLength+sizeof(UNICODE_NULL);
    RtlCopyMemory(NtName->Buffer,NameBuffer,NameLength);
    NtName->Buffer[1]=L'?';
    NtName->Buffer[NameLength/sizeof(WCHAR)]=UNICODE_NULL;
    if(PartName){
      PWSTR p=&NtName->Buffer[NameLength/sizeof(WCHAR)-1];
      while(p>NtName->Buffer)
        if(*p--==L'\\')break;
      if(p>NtName->Buffer){
        p++;
        if(!*p)
          *PartName=NULL;
        else
          *PartName=p;
      }
    }
    return STATUS_SUCCESS;
  }
  ULONG PathLength=0,DosLength=0;
  DOS_PATH_TYPE dpt=RtlDetermineDosPathNameType(DosName);
  switch(dpt){
    case RTL_INVALID_PATH:case RTL_UNC_PATH:break;
    case RTL_DEVICE_PATH:
      if(!_wcsicmp(NameBuffer+4,L"CON")){
        DosLength=MAKELONG(3*sizeof(WCHAR),4*sizeof(WCHAR));
        break;
      }
    break;
    default:{
      LPCWSTR start,end,p;
      if(dpt==RTL_RELATIVE_DRIVE_PATH)
        start=NameBuffer+2;
      else
        start=NameBuffer;
      for(p=start;*p;p++)
        if(IS_SEPARATOR(*p))
          start=p+1;
      for(end=start;*end;end++)
        if(*end==L'.'||*end==L':')
          break;
      end--;
      while(end>=start&&*end==L' ')
        end--;
      switch(end-start+1){
        case 3:
          if(_wcsnicmp(start,L"PRN",3)&&
             _wcsnicmp(start,L"AUX",3)&&
             _wcsnicmp(start,L"CON",3)&&
             _wcsnicmp(start,L"NUL",3)
          )break;
          DosLength=MAKELONG(3*sizeof(WCHAR),start-NameBuffer);
        break;
        case 4:
          if(_wcsnicmp(start,L"LPT",3)&&
             _wcsnicmp(start,L"COM",3)&&
             (*end<=L'0'||*end>L'9')
          )break;
          DosLength=MAKELONG(4*sizeof(WCHAR),start-NameBuffer);
        break;
        default:break;
      }
    }break;
  }
  WCHAR Buffer[MAX_PATH+1]={0};
  if(DosLength){
    DWORD Offset=HIWORD(DosLength);
    DWORD Length=LOWORD(DosLength);
    DWORD FullLength=Length+8;
    if(FullLength<sizeof(Buffer)){
      RtlMoveMemory(Buffer,L"\\\\.\\",8);
      RtlMoveMemory((PCHAR)Buffer+8,(PCHAR)NameBuffer+Offset,Length);
      *(PWCHAR)((ULONG_PTR)Buffer+FullLength)=UNICODE_NULL;
      PathLength=FullLength;
    }else
      if((FullLength+sizeof(UNICODE_NULL))<UNICODE_STRING_MAX_BYTES)
        PathLength=FullLength+sizeof(UNICODE_NULL);
  }
  if(!PathLength){
    ULONG mark=0,dep=0,deplen,size=sizeof(Buffer);
    LPWSTR ptr,next,ins_str=NULL;WCHAR tmp[4];
    for(ptr=NameBuffer;*ptr;ptr++)if(*ptr!=' ')break;
    if(*ptr){
      const UNICODE_STRING* cd=&NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->CurrentDirectory.DosPath;
      switch(RtlDetermineDosPathNameType(DosName)){
        case RTL_UNC_PATH:
          ptr=NameBuffer+2;
          while(*ptr&&!IS_SEPARATOR(*ptr))ptr++;
          while(IS_SEPARATOR(*ptr))ptr++;
          while(*ptr&&!IS_SEPARATOR(*ptr))ptr++;
          while(IS_SEPARATOR(*ptr))ptr++;
          mark=(ptr-NameBuffer);
        break;
        case RTL_DEVICE_PATH:
          mark=4;
        break;
        case RTL_ABSOLUTE_DRIVE_PATH:
          PathLength=sizeof(WCHAR);
          tmp[0]=RtlUpcaseUnicodeChar(NameBuffer[0]);
          ins_str=tmp;
          dep=1;
          mark=3;
        break;
        case RTL_RELATIVE_DRIVE_PATH:
          dep=2;
          if(RtlUpcaseUnicodeChar(NameBuffer[0])!=RtlUpcaseUnicodeChar(cd->Buffer[0])||cd->Buffer[1]!=':'){
            UNICODE_STRING var,val;
            tmp[0]=L'=';
            tmp[1]=NameBuffer[0];
            tmp[2]=L':';
            tmp[3]=L'\0';
            var.Length=3*sizeof(WCHAR);
            var.MaximumLength=4*sizeof(WCHAR);
            var.Buffer=tmp;
            val.Length=0;
            val.MaximumLength=size;
            val.Buffer=(PWCHAR)RtlAllocateHeap(RtlGetProcessHeap(),0,size);
            if(val.Buffer==NULL){
              PathLength=0;
              goto done;
            }
            switch(RtlQueryEnvironmentVariable(NULL,&var,&val)){
              case STATUS_SUCCESS:
              case STATUS_BUFFER_TOO_SMALL:
                PathLength=val.Length+sizeof(WCHAR);
                val.Buffer[val.Length/sizeof(WCHAR)]='\\';
                ins_str=val.Buffer;
              break;
              case STATUS_VARIABLE_NOT_FOUND:
                PathLength=3 * sizeof(WCHAR);
                tmp[0]=NameBuffer[0];
                tmp[1]=L':';
                tmp[2]=L'\\';
                ins_str=tmp;
                RtlFreeHeap(RtlGetProcessHeap(),0,val.Buffer);
              break;
              default:
                RtlFreeHeap(RtlGetProcessHeap(),0,val.Buffer);
              break;
            }
            mark=3;
            break;
          }
        case RTL_RELATIVE_PATH:
          PathLength=cd->Length;
          ins_str=cd->Buffer;
          if(cd->Buffer[1]!=L':'){
            ptr=cd->Buffer+2;
            while(*ptr&&!IS_SEPARATOR(*ptr))ptr++;
            while(IS_SEPARATOR(*ptr))ptr++;
            while(*ptr&&!IS_SEPARATOR(*ptr))ptr++;
            while(IS_SEPARATOR(*ptr))ptr++;
            mark=ptr-cd->Buffer;
          }else mark=3;
        break;
        case RTL_ABSOLUTE_PATH:
          if(cd->Buffer[1]==L':'){
            PathLength=2*sizeof(WCHAR);
            tmp[0]=cd->Buffer[0];
            tmp[1]=L':';
            ins_str=tmp;
            mark=3;
          }else{
            ptr=cd->Buffer+2;
            while(*ptr&&!IS_SEPARATOR(*ptr))ptr++;
            while(IS_SEPARATOR(*ptr))ptr++;
            while(*ptr&&!IS_SEPARATOR(*ptr))ptr++;
            while(IS_SEPARATOR(*ptr))ptr++;
            PathLength=(ptr-cd->Buffer)*sizeof(WCHAR);
            mark=PathLength/sizeof(WCHAR);
            ins_str=cd->Buffer;
          }
        break;
        case RTL_UNC_DOT_PATH:
          PathLength=4*sizeof(WCHAR);
          dep=3;
          tmp[0]=L'\\';
          tmp[1]=L'\\';
          tmp[2]=L'.';
          tmp[3]=L'\\';
          ins_str=tmp;
          mark=4;
        break;
        case RTL_INVALID_PATH:
        goto done;
      }
      deplen=NameLength+dep*sizeof(WCHAR);
      if(PathLength+deplen+sizeof(WCHAR)>size){
        PathLength+=deplen+sizeof(WCHAR);
        goto done;
      }
      RtlCopyMemory(Buffer+PathLength/sizeof(WCHAR),NameBuffer+dep,deplen+sizeof(WCHAR));
      if(PathLength)RtlCopyMemory(Buffer,ins_str,PathLength);
      PathLength+=deplen;
      if(ins_str!=tmp&&ins_str!=cd->Buffer)
        RtlFreeHeap(GetProcessHeap(),0,(PVOID)ins_str);
      for(ptr=Buffer;*ptr;ptr++)if(*ptr=='/')*ptr='\\';
      next=Buffer+max(1,mark);
      for(ptr=next;*ptr;ptr++)if(*ptr!='\\'||next[-1]!='\\')*next++=*ptr;
      *next=0;
      ptr=Buffer+mark;
      while(*ptr){
        if(*ptr=='.'){
          switch(ptr[1]){
            case '\\':
              next=ptr+2;
              memmove(ptr,next,(wcslen(next)+1)*sizeof(WCHAR));
            continue;
            case 0:
              if(ptr>Buffer+mark)ptr--;
              *ptr=0;
            continue;
            case '.':
              if(ptr[2]=='\\'){
                next=ptr+3;
                if(ptr>Buffer+mark){
                  ptr--;
                  while(ptr>Buffer+mark&&ptr[-1]!='\\')ptr--;
                }
                memmove(ptr,next,(wcslen(next)+1)*sizeof(WCHAR));
                continue;
              }else if(!ptr[2]){
                if(ptr>Buffer+mark){
                  ptr--;
                  while(ptr>Buffer+mark&&ptr[-1]!='\\')ptr--;
                  if(ptr>Buffer+mark)ptr--;
                }
                *ptr=0;
                continue;
              }
            break;
          }
        }
        while(*ptr&&*ptr!='\\')ptr++;
        if(*ptr=='\\'){
          if(ptr>Buffer+mark&&ptr[-1]=='.')
            memmove(ptr-1,ptr,(wcslen(ptr)+1)*sizeof(WCHAR));
          else ptr++;
        }
      }
      while(ptr>Buffer+mark&&(ptr[-1]==' '||ptr[-1]=='.'))ptr--;
      *ptr=0;
      PathLength=wcslen(Buffer)*sizeof(WCHAR);
    }
  }
done:
  if(!PathLength||(PathLength>(MAX_PATH*sizeof(WCHAR))))
    return STATUS_OBJECT_NAME_INVALID;
  LPCWSTR PrefixBuffer=L"\\??\\";
  ULONG PrefixLength=8;
  ULONG PrefixCut=0;
  UNICODE_STRING UBuffer;
  RtlInitUnicodeString(&UBuffer,Buffer);
  switch(RtlDetermineDosPathNameType(&UBuffer)){
    case RTL_UNC_PATH:
      PrefixBuffer=L"\\??\\UNC\\";
      PrefixLength=16;
      PrefixCut=2;
    break;
    case RTL_DEVICE_PATH:
      PrefixCut=4;
    break;
    default:break;
  }
  //Make Wow64 Redirection
  if(iswow64&&bDoFsRedirection)MakeRedirection(Buffer);
  NtName->Buffer=(PWCHAR)RtlAllocateHeap(RtlGetProcessHeap(),0,sizeof(Buffer));
  if(!NtName->Buffer)return STATUS_NO_MEMORY;
  NtName->MaximumLength=sizeof(Buffer);
  RtlCopyMemory(NtName->Buffer,PrefixBuffer,PrefixLength);
  RtlCopyMemory((PCHAR)NtName->Buffer+PrefixLength,&Buffer[PrefixCut],PathLength-(PrefixCut*sizeof(WCHAR)));
  NtName->Length=PathLength-(PrefixCut*sizeof(WCHAR))+PrefixLength;
  NtName->Buffer[NtName->Length/sizeof(WCHAR)]=UNICODE_NULL;
  if(PartName&&*PartName)
    *PartName=NtName->Buffer+NtName->Length/sizeof(WCHAR)-wcslen(*PartName);
  return STATUS_SUCCESS;
}

WCHAR *RtlGetModuleLoadPath(){
  static WCHAR *system_path=NULL;
  UNICODE_STRING name,value;
  int len=3,path_len=0;
  if(!system_path){
    WCHAR *p,*exe_name=NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer;
    if(!(p=wcsrchr(exe_name,'\\')))p=exe_name;
    if(p==exe_name+2&&exe_name[1]==':')p++;
    len+=p-exe_name;
    len+=GetSystemDirectoryW(NULL,0);
    len+=GetWindowsDirectoryW(NULL,0);
    system_path=(WCHAR*)RtlAllocateHeap(RtlGetProcessHeap(),0,len*sizeof(WCHAR));
    memcpy(system_path,exe_name,(p-exe_name)*sizeof(WCHAR));
    p=system_path+(p-exe_name);
    *p++=';';*p++='.';*p++=';';
    GetSystemDirectoryW(p,system_path+len-p);
    p+=wcslen(p);
    *p++=';';
    GetWindowsDirectoryW(p,system_path+len-p);
    len=wcslen(system_path)+2;
    value.Length=0;
    value.MaximumLength=0;
    value.Buffer=NULL;
    RtlInitUnicodeString(&name,L"PATH");
    if(RtlQueryEnvironmentVariable(NULL,&name,&value)==STATUS_BUFFER_TOO_SMALL)
      path_len=value.Length;
    if(!(system_path=(WCHAR*)RtlReAllocateHeap(RtlGetProcessHeap(),0,system_path,path_len+len*sizeof(WCHAR))))
      return NULL;
    p=system_path+wcslen(system_path);
    *p++=';';
    value.Buffer=p;
    value.MaximumLength=path_len;
    while(RtlQueryEnvironmentVariable(NULL,&name,&value)==STATUS_BUFFER_TOO_SMALL){
      WCHAR *new_ptr;
      path_len=value.Length;
      if(!(new_ptr=(WCHAR*)RtlReAllocateHeap(RtlGetProcessHeap(),0,system_path,path_len+len*sizeof(WCHAR)))){
        RtlFreeHeap(RtlGetProcessHeap(),0,system_path);
        return NULL;
      }
      value.Buffer=new_ptr+(value.Buffer-system_path);
      value.MaximumLength=path_len;
      system_path=new_ptr;
    }
    value.Buffer[value.Length/sizeof(WCHAR)]=0;
  }
  return system_path;
}

NTSTATUS NTAPI RtlVolumeDeviceToDosName(LPCWSTR VolumeDeviceName,PUNICODE_STRING DosName){
  NTSTATUS Status;DWORD drive;
  WCHAR sBuffer[MAX_PATH],sLetter[3]=L"X:";
  PROCESS_DEVICEMAP_INFORMATION ProcessDeviceMapInfo;
  HANDLE hDirectory,hDevice;
  UNICODE_STRING UnicodeString;
  OBJECT_ATTRIBUTES ObjectAttributes;
  Status=_NtQueryInformationProcess(NtCurrentProcess(),ProcessDeviceMap,&ProcessDeviceMapInfo,
    sizeof(ProcessDeviceMapInfo),NULL);
  if(!NT_SUCCESS(Status))
    return Status;
  RtlInitUnicodeString(&UnicodeString,L"\\??");
  InitializeObjectAttributes(&ObjectAttributes,&UnicodeString,OBJ_CASE_INSENSITIVE,NULL,NULL);
  Status=_NtOpenDirectoryObject(&hDirectory,DIRECTORY_QUERY,&ObjectAttributes);
  if(!NT_SUCCESS(Status))
    return Status;
  for(drive=0;drive<MAX_DOS_DRIVES;drive++)
  if(ProcessDeviceMapInfo.Query.DriveMap&(1<<drive)){
    sLetter[0]=(WCHAR)(L'A'+drive);
    RtlInitUnicodeString(&UnicodeString,sLetter);
    InitializeObjectAttributes(&ObjectAttributes,&UnicodeString,OBJ_CASE_INSENSITIVE,hDirectory,NULL);
    Status=_NtOpenSymbolicLinkObject(&hDevice,SYMBOLIC_LINK_QUERY,&ObjectAttributes);
    if(NT_SUCCESS(Status)){
      ULONG dw=0;
      UnicodeString.Length=0;
      UnicodeString.Buffer=sBuffer;
      UnicodeString.MaximumLength=MAX_PATH*sizeof(WCHAR);
      Status=_NtQuerySymbolicLinkObject(hDevice,&UnicodeString,&dw);
      if(NT_SUCCESS(Status)&&!wcsncmp(VolumeDeviceName,UnicodeString.Buffer,(UnicodeString.Length/sizeof(WCHAR)))){
        DosName->MaximumLength=MAX_PATH*sizeof(WCHAR);
        DosName->Buffer=(PWCHAR)RtlAllocateHeap(RtlGetProcessHeap(),0,DosName->MaximumLength);
        wcscpy(DosName->Buffer,sLetter);
        wcscpy(&DosName->Buffer[2],&VolumeDeviceName[UnicodeString.Length/sizeof(WCHAR)]);
        DosName->Length=(3+wcslen(&VolumeDeviceName[UnicodeString.Length/sizeof(WCHAR)]))*sizeof(WCHAR);
        _NtClose(hDevice);
        break;
      }
      _NtClose(hDevice);
    }
  }
  _NtClose(hDirectory);
  return Status;
}

BOOL WINAPI RtlDoesFileExists(PCUNICODE_STRING FileName,BOOLEAN SucceedIfBusy){
  OBJECT_ATTRIBUTES ObjectAttributes;FILE_BASIC_INFORMATION BasicInformation;
  NTSTATUS Status;UNICODE_STRING NtPathName;
  if(!FileName||!FileName->Buffer)return FALSE;
  if(!NT_SUCCESS(RtlDosPathNameToNtPathName(FileName,&NtPathName,NULL)))
    return FALSE;
  InitializeObjectAttributes(&ObjectAttributes,&NtPathName,OBJ_CASE_INSENSITIVE,NULL,NULL);
  Status=_NtQueryAttributesFile(&ObjectAttributes,&BasicInformation);
  RtlFreeUnicodeString(&NtPathName);
  if((Status==STATUS_SHARING_VIOLATION)||(Status==STATUS_ACCESS_DENIED))
    return SucceedIfBusy?TRUE:FALSE;
  return NT_SUCCESS(Status);
}

NTSTATUS RtlResolveFilePath(LPCWSTR FileName,LPCWSTR FileExt,PUNICODE_STRING FullFileName,
  PUNICODE_STRING NtPathFileName,LPWSTR *FilePart){
  LPCWSTR FilePath=NULL;UNICODE_STRING Path;WCHAR PathBuf[MAX_PATH];ULONG len;
  if(!FileName||!FullFileName)
    return STATUS_NO_MEMORY;
  LPWSTR q=(LPWSTR)FileName;
  while(*q)q++;
  while(q!=FileName){
    if(IS_SEPARATOR(*q)){
      WCHAR TmpBuf[MAX_PATH];
      wcsncpy(PathBuf,FileName,(q-FileName)+1);
      PathBuf[(q-FileName)+1]=0;
      FileName=q+1;
      RtlInitUnicodeString(&Path,PathBuf);
      const UNICODE_STRING* cd=&NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->CurrentDirectory.DosPath;
      switch(RtlDetermineDosPathNameType(&Path)){
        case RTL_ABSOLUTE_PATH:
          if(cd->Buffer[1]==L':'){
            wcscpy(TmpBuf,PathBuf);
            PathBuf[0]=cd->Buffer[0];
            PathBuf[1]=L':';
            PathBuf[2]=0;
            wcscat(PathBuf,TmpBuf);
          }else
            return STATUS_NO_MEMORY;
        break;
        case RTL_RELATIVE_PATH:
          len=cd->Length/sizeof(WCHAR);
          wcscpy(TmpBuf,PathBuf);
          wcsncpy(PathBuf,cd->Buffer,len);
          PathBuf[len]=0;
          if(PathBuf[len-1]!=L'\\'){
            PathBuf[len]=L'\\';
            PathBuf[len+1]=0;
          }
          wcscat(PathBuf,TmpBuf);
        break;
        default:break;
      }
      FilePath=PathBuf;
      break;
    }
    --q;
  }
  if(!FilePath)FilePath=NtCurrentPeb()->ProcessParameters->DllPath.Buffer;
  if(!FilePath)FilePath=RtlGetModuleLoadPath();
  if(!FilePath){
    return STATUS_NO_MEMORY;
  }
  FullFileName->Buffer=(PWCHAR)RtlAllocateHeap(RtlGetProcessHeap(),0,MAX_PATH*sizeof(WCHAR));
  if(!FullFileName->Buffer){
    return STATUS_NO_MEMORY;
  }
  FullFileName->MaximumLength=MAX_PATH*sizeof(WCHAR);
  PWCHAR pathstart=(LPWSTR)FilePath,patchend=(LPWSTR)FilePath,p=(LPWSTR)FilePath;
  while(*p){
    while(*p&&*p!=L';')p++;
    patchend=p;
    if(*p==L';')++p;
    ULONG Length=patchend-pathstart;
    RtlCopyMemory(FullFileName->Buffer,pathstart,Length*sizeof(WCHAR));
    if(FullFileName->Buffer[Length-1]!=L'\\'){
      FullFileName->Buffer[Length]=L'\\';
      Length++;
    }
    ULONG FileNameLength = wcslen(FileName);
    RtlCopyMemory(&FullFileName->Buffer[Length],FileName,FileNameLength*sizeof(WCHAR));
    if(FilePart)*FilePart=&FullFileName->Buffer[Length];
    Length+=FileNameLength;
    FullFileName->Buffer[Length]=UNICODE_NULL;
    FullFileName->Length=Length*sizeof(WCHAR);
    if(RtlDoesFileExists(FullFileName,FALSE)){
      if(!NtPathFileName)
        return STATUS_SUCCESS;
      return RtlDosPathNameToNtPathName(FullFileName,NtPathFileName,NULL);
    }else if(FileExt){
      ULONG FileExtLength = wcslen(FileExt);
      RtlCopyMemory(&FullFileName->Buffer[Length],FileExt,FileExtLength*sizeof(WCHAR));
      Length+=FileExtLength;
      FullFileName->Buffer[Length]=UNICODE_NULL;
      FullFileName->Length=Length*sizeof(WCHAR);
      if(RtlDoesFileExists(FullFileName,FALSE)){
        if(!NtPathFileName)
          return STATUS_SUCCESS;
        return RtlDosPathNameToNtPathName(FullFileName,NtPathFileName,NULL);
      }
    }
    pathstart=p;
  }
  return STATUS_NOT_FOUND;
}

DWORD WINAPI GetFullPathNameW(LPCWSTR lpFileName,DWORD nBufferLength,LPWSTR lpBuffer,LPWSTR *lpFilePart){
  UNICODE_STRING FileNameString;
  RtlEmpyUnicodeString(&FileNameString,lpBuffer,nBufferLength);
  if(NT_SUCCESS(RtlResolveFilePath(lpFileName,NULL,&FileNameString,NULL,lpFilePart)))
    return FileNameString.Length;
  return 0;
}

NTSTATUS WINAPI RtlAdjustPrivilege(ULONG Privilege,BOOLEAN Enable,BOOLEAN CurrentThread,PBOOLEAN	Enabled){
  NTSTATUS Status;TOKEN_PRIVILEGES OldState,NewState;
  HANDLE TokenHandle;ULONG ReturnLength;
  if(CurrentThread)
    Status=_NtOpenThreadToken(NtCurrentThread(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,FALSE,&TokenHandle);
  else
    Status=_NtOpenProcessToken(NtCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&TokenHandle);
  if(!NT_SUCCESS(Status)){
    return Status;
  }
  OldState.PrivilegeCount=1;
  NewState.PrivilegeCount=1;
  NewState.Privileges[0].Luid.LowPart=Privilege;
  NewState.Privileges[0].Luid.HighPart=0;
  NewState.Privileges[0].Attributes=(Enable)?SE_PRIVILEGE_ENABLED:0;
  Status=_NtAdjustPrivilegesToken(TokenHandle,FALSE,&NewState,sizeof(TOKEN_PRIVILEGES),&OldState,&ReturnLength);
  _NtClose(TokenHandle);
  if(Status==STATUS_NOT_ALL_ASSIGNED){
    return STATUS_PRIVILEGE_NOT_HELD;
  }
  if(!NT_SUCCESS(Status)){
    return Status;
  }
  if(OldState.PrivilegeCount==0)
    *Enabled=Enable;
  else
    *Enabled=(OldState.Privileges[0].Attributes&SE_PRIVILEGE_ENABLED);
  return STATUS_SUCCESS;
}

BOOLEAN WINAPI RtlAreAllAccessesGranted(ACCESS_MASK GrantedAccess,ACCESS_MASK DesiredAccess){
  return !(~GrantedAccess & DesiredAccess);
}

VOID WINAPI RtlMapGenericMask(PACCESS_MASK AccessMask,PGENERIC_MAPPING GenericMapping){
  if(*AccessMask & GENERIC_READ) *AccessMask |= GenericMapping->GenericRead;
  if(*AccessMask & GENERIC_WRITE) *AccessMask |= GenericMapping->GenericWrite;
  if(*AccessMask & GENERIC_EXECUTE) *AccessMask |= GenericMapping->GenericExecute;
  if(*AccessMask & GENERIC_ALL) *AccessMask |= GenericMapping->GenericAll;
  *AccessMask &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

NTSTATUS WINAPI BaseGetNamedObjectDirectory(HANDLE *pBaseNamedObjectDirectory){
  static HANDLE BaseNamedObjectDirectory=NULL;
  NTSTATUS Status=STATUS_SUCCESS;
  if(!BaseNamedObjectDirectory){
    UNICODE_STRING *pNamedObjectDirectory,RestrictedObjectDirectory;
    OBJECT_ATTRIBUTES Obja;HANDLE hRootNamedObject=NULL;
    ACCESS_MASK DirAccess=DIRECTORY_ALL_ACCESS&~(DELETE|WRITE_DAC|WRITE_OWNER);
    WCHAR buffer[MAX_PATH];DWORD dwSessionId;UNICODE_STRING NamedObjectDirectory;
    ProcessIdToSessionId(GetCurrentProcessId(),&dwSessionId);
    if(!dwSessionId)wcscpy(buffer,L"\\BaseNamedObjects");
    else swprintf(buffer,L"\\Sessions\\%d\\BaseNamedObjects",dwSessionId);
    RtlInitUnicodeString(&NamedObjectDirectory,(LPCWSTR)buffer);
    pNamedObjectDirectory=&NamedObjectDirectory;
    InitializeObjectAttributes(&Obja,pNamedObjectDirectory,OBJ_CASE_INSENSITIVE,NULL,NULL);
    Status=_NtOpenDirectoryObject(&BaseNamedObjectDirectory,DirAccess,&Obja);
    if(!NT_SUCCESS(Status)){
      Status=_NtOpenDirectoryObject(&hRootNamedObject,DIRECTORY_TRAVERSE,&Obja);
      if(NT_SUCCESS(Status)){
        RtlInitUnicodeString(&RestrictedObjectDirectory,L"Restricted");
        InitializeObjectAttributes(&Obja,&RestrictedObjectDirectory,OBJ_CASE_INSENSITIVE,hRootNamedObject,NULL);
        Status=_NtOpenDirectoryObject(&BaseNamedObjectDirectory,DirAccess,&Obja);
        _NtClose(hRootNamedObject);
      }
      if(!NT_SUCCESS(Status))
        BaseNamedObjectDirectory=NULL;
    }
  }
  *pBaseNamedObjectDirectory=BaseNamedObjectDirectory;
  return Status;
}

POBJECT_ATTRIBUTES WINAPI BaseFormatObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes,LPSECURITY_ATTRIBUTES SecurityAttributes,PUNICODE_STRING ObjectName){
  HANDLE RootDirectory=NULL;ULONG Attributes=0;PVOID SecurityDescriptor=NULL;
  if(!ARGUMENT_PRESENT(SecurityAttributes)&&!ARGUMENT_PRESENT(ObjectName))
    return NULL;
  if(ARGUMENT_PRESENT(SecurityAttributes)){
    SecurityDescriptor=SecurityAttributes->lpSecurityDescriptor;
    Attributes=SecurityAttributes->bInheritHandle?OBJ_INHERIT:0;
  }
  if(ARGUMENT_PRESENT(ObjectName)){
    Attributes|=OBJ_OPENIF;
    BaseGetNamedObjectDirectory(&RootDirectory);
  }
  InitializeObjectAttributes(ObjectAttributes,ObjectName,Attributes,RootDirectory,SecurityDescriptor);
  return ObjectAttributes;
}

NTSTATUS WINAPI BaseCreateStack(HANDLE Process,ULONG StackSize,ULONG MaximumStackSize,PINITIAL_TEB InitialTeb){
  NTSTATUS Status;ULONG RegionSize,OldProtect;
  ULONG ImageStackSize,ImageStackCommit;
  PIMAGE_NT_HEADERS NtHeaders;PCH Stack=NULL;
  BOOL PageGuard=FALSE;

  NtHeaders=RtlImageNtHeader(NtCurrentPeb()->ImageBaseAddress);
  if(NtHeaders){

    ImageStackSize=NtHeaders->OptionalHeader.SizeOfStackReserve;
    ImageStackCommit=NtHeaders->OptionalHeader.SizeOfStackCommit;

    if(!MaximumStackSize)
      MaximumStackSize=ImageStackSize;
    if(!StackSize)
      StackSize=ImageStackCommit;
    else if(StackSize>=MaximumStackSize)
      MaximumStackSize=ROUND_UP(StackSize,0x100000);

    StackSize=ROUND_UP(StackSize,PAGE_SIZE);
    MaximumStackSize=ROUND_UP(MaximumStackSize,0x100000);

    Status=_NtAllocateVirtualMemory(Process,&Stack,0,&MaximumStackSize,MEM_RESERVE,PAGE_READWRITE);
    if(!NT_SUCCESS(Status)){
      return Status;
    }

    InitialTeb->StackCommit=0;
    InitialTeb->StackReserve=0;
    InitialTeb->StackBase=MaximumStackSize+Stack;
    InitialTeb->StackAllocate=Stack;

    Stack+=MaximumStackSize-StackSize;
    if(MaximumStackSize>StackSize){
      Stack-=PAGE_SIZE;
      StackSize+=PAGE_SIZE;
      PageGuard=TRUE;
    }

    Status=_NtAllocateVirtualMemory(Process,&Stack,0,&StackSize,MEM_COMMIT,PAGE_READWRITE);
    if(!NT_SUCCESS(Status)){
      RegionSize=0;
      _NtFreeVirtualMemory(Process,&Stack,&RegionSize,MEM_RELEASE);
      return Status;
    }

    InitialTeb->StackLimit=Stack;
    if(PageGuard){
      RegionSize=PAGE_SIZE;
      Status=_NtProtectVirtualMemory(Process,&Stack,&RegionSize,PAGE_GUARD|PAGE_READWRITE,&OldProtect);
      if(!NT_SUCCESS(Status)){
        return Status;
      }
      InitialTeb->StackLimit=(PVOID)((DWORD)InitialTeb->StackLimit+RegionSize);
    }
  }else
    return STATUS_INVALID_IMAGE_FORMAT;
  return STATUS_SUCCESS;
}

extern "C"{
  VOID WINAPI ThreadStart(LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter){
    _NtTerminateThread(NULL,lpStartAddress(lpParameter));
  }

  VOID WINAPI BaseThreadStart(VOID);
  asm(
    ".globl _BaseThreadStart\r\n"
    "_BaseThreadStart:\r\n"
    "  xor %ebp,%ebp;\r\n"
    "  push %ebx;\r\n"//push arg
    "  push %eax;\r\n"//push start address
    "  push $0;\r\n"  //push ret (return to hell!)
    "  jmp  _ThreadStart;\r\n"
  );
}

PVOID WINAPI CreateRemoteThreadStart(HANDLE hProcess){
  NTSTATUS Status;
  static BYTE startcode[52];
  PBYTE pcode=startcode;
  *(pcode++)=0x53;//push ebx
  *(pcode++)=0x50;//push eax
  *((WORD*)pcode)=0x006A;//push 0
  pcode+=2;
  *((WORD*)pcode)=0xEC8B;//mov ebp,esp
  pcode+=2;
  *((WORD*)pcode)=0x75FF;//push (ebp+8)
  pcode+=2;
  *(pcode++)=0x08;
  *((WORD*)pcode)=0x55FF;//call (ebp+4)
  pcode+=2;
  *(pcode++)=0x04;
  *(pcode++)=0x50;//push eax
  *((WORD*)pcode)=0x006A;//push 0
  pcode+=2;
  *(pcode++)=0xB8;//mov eax, NtTerminateThread (Offset)
  *((DWORD*)pcode)=GetFuncOffset(184);
  pcode+=4;
  *((WORD*)pcode)=0xD48B;//mov edx,esp
  pcode+=2;
  if(iswow64){
    *((WORD*)pcode)=0xC933;//xor ecx,ecx
    pcode+=2;
    *((WORD*)pcode)=0x006A;//push 0 (return to hell!)
    pcode+=2;
    *((WORD*)pcode)=0xFF64;//call fs:[c0]
    pcode+=2;
    *(pcode++)=0x15;
    *((DWORD*)pcode)=0x000000C0;
    pcode+=4;
  }else{
    *((WORD*)pcode)=0x2ECD;//int 2E
    pcode+=2;
  }
  *(pcode++)=0xC3;//ret
  PBYTE lpAddress=NULL;DWORD dwSize=sizeof(startcode),dwRet=0;
  Status=_NtAllocateVirtualMemory(hProcess,&lpAddress,0,&dwSize,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
  Status=_NtWriteVirtualMemory(hProcess,lpAddress,startcode,32,&dwRet);
  return lpAddress;
}

VOID WINAPI BaseInitializeContext(HANDLE hProcess,PCONTEXT Context,PVOID Parameter,PVOID InitialPc,PVOID InitialSp,BASE_CONTEXT_TYPE ContextType){
  ZeroMemory(Context,sizeof(CONTEXT));
  Context->Eax=(ULONG)InitialPc;
  Context->Ebx=(ULONG)Parameter;
  Context->SegGs=0;
  Context->SegFs=KGDT_R3_TEB;
  Context->SegEs=KGDT_R3_DATA;
  Context->SegDs=KGDT_R3_DATA;
  Context->SegSs=KGDT_R3_DATA;
  Context->SegCs=KGDT_R3_CODE;
  Context->EFlags=0x3000;
  Context->Esp=(ULONG)InitialSp;
  if(hProcess==NtCurrentProcess())
    Context->Eip=(DWORD)BaseThreadStart;
  else
    Context->Eip=(DWORD)CreateRemoteThreadStart(hProcess);
  Context->ContextFlags=CONTEXT_FULL;
  Context->Esp-=sizeof(Parameter);
}

// ****************************************************************************************
// End RTL Apis
// ****************************************************************************************

typedef UINT (WINAPI *tGetSystemWow64DirectoryW)(LPWSTR lpBuffer,UINT uSize);
UINT WINAPI GetSystemWow64DirectoryW(LPWSTR lpBuffer,UINT uSize){
  static tGetSystemWow64DirectoryW pGetSystemWow64DirectoryW=NULL;
  if(!pGetSystemWow64DirectoryW)
    pGetSystemWow64DirectoryW=(tGetSystemWow64DirectoryW)GetProcAddress(hKernel32,"GetSystemWow64DirectoryW");
  if(pGetSystemWow64DirectoryW)
    return pGetSystemWow64DirectoryW(lpBuffer,uSize);
  return 0;
}

UINT WINAPI GetSystemWow64DirectoryA(LPSTR lpBuffer,UINT uSize){
  WCHAR WindowsSystemWow64Directory[MAX_PATH];
  ULONG ReturnLength=GetSystemWow64DirectoryW(WindowsSystemWow64Directory,MAX_PATH);
  if(ReturnLength){
    if(uSize>=ReturnLength)
      return RtlUnicodeToMultiByte(lpBuffer,uSize,WindowsSystemWow64Directory,(ReturnLength+1)*sizeof(WCHAR));
    return ReturnLength;
  }
  return 0;
}

typedef UINT (WINAPI *tGetSystemDirectoryW)(LPWSTR lpBuffer,UINT uSize);
UINT WINAPI GetSystemDirectoryW(LPWSTR lpBuffer,UINT uSize){
  static tGetSystemDirectoryW pGetSystemDirectoryW=NULL;
  if(!pGetSystemDirectoryW)
    pGetSystemDirectoryW=(tGetSystemDirectoryW)GetProcAddress(hKernel32,"GetSystemDirectoryW");
  if(pGetSystemDirectoryW)
    return pGetSystemDirectoryW(lpBuffer,uSize);
  return 0;
}

UINT WINAPI GetSystemDirectoryA(LPSTR lpBuffer,UINT uSize){
  WCHAR WindowsSystemDirectory[MAX_PATH];
  ULONG ReturnLength=GetSystemDirectoryW(WindowsSystemDirectory,MAX_PATH);
  if(ReturnLength){
    if(uSize>=ReturnLength)
      return RtlUnicodeToMultiByte(lpBuffer,uSize,WindowsSystemDirectory,(ReturnLength+1)*sizeof(WCHAR));
    return ReturnLength;
  }
  return 0;
}

typedef UINT (WINAPI *tGetWindowsDirectoryW)(LPWSTR lpBuffer,UINT uSize);
UINT WINAPI GetWindowsDirectoryW(LPWSTR lpBuffer,UINT uSize){
  static tGetWindowsDirectoryW pGetWindowsDirectoryW=NULL;
  if(!pGetWindowsDirectoryW)
    pGetWindowsDirectoryW=(tGetWindowsDirectoryW)GetProcAddress(hKernel32,"GetWindowsDirectoryW");
  if(pGetWindowsDirectoryW)
    return pGetWindowsDirectoryW(lpBuffer,uSize);
  return 0;
}

typedef BOOL (WINAPI *tCreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
  BOOL,DWORD,PVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcessA(LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation){
  static tCreateProcessA pCreateProcess=NULL;
  if(!pCreateProcess)
    pCreateProcess=(tCreateProcessA)GetProcAddress(hKernel32,"CreateProcessA");
  if(pCreateProcess)
    return pCreateProcess(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,
      dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
  return FALSE;
}

typedef BOOL (WINAPI *tCreateProcessW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
  BOOL,DWORD,PVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation){
  static tCreateProcessW pCreateProcess=NULL;
  if(!pCreateProcess)
    pCreateProcess=(tCreateProcessW)GetProcAddress(hKernel32,"CreateProcessW");
  if(pCreateProcess)
    return pCreateProcess(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,
      dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
  return FALSE;
}

UINT WINAPI GetWindowsDirectoryA(LPSTR lpBuffer,UINT uSize){
  WCHAR WindowsDirectory[MAX_PATH];
  ULONG ReturnLength=GetWindowsDirectoryW(WindowsDirectory,MAX_PATH);
  if(ReturnLength){
    if(uSize>=ReturnLength)
      return RtlUnicodeToMultiByte(lpBuffer,uSize,WindowsDirectory,(ReturnLength+1)*sizeof(WCHAR));
    return ReturnLength;
  }
  return 0;
}

FARPROC WINAPI GetProcAddress(HMODULE hModule,LPCSTR lpProcName){
  DWORD index,dwExportSize,dwOrdinal=0;
  if(!hModule)return NULL;
  PIMAGE_DOS_HEADER pDosHeader;
  PIMAGE_NT_HEADERS pNTHeader;
  PIMAGE_EXPORT_DIRECTORY pExportDir;
	pDosHeader=(PIMAGE_DOS_HEADER)hModule;
	if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
		return NULL;
  pNTHeader=RVAPTR(PIMAGE_NT_HEADERS,pDosHeader,pDosHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
		return NULL;
  pExportDir=RVAPTR(PIMAGE_EXPORT_DIRECTORY,pDosHeader,pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  dwExportSize=pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  if(!pExportDir)
    return NULL;
  PCHAR* pszName=RVAPTR(PCHAR*,pDosHeader,pExportDir->AddressOfNames);
  PDWORD pdwAddress=RVAPTR(PDWORD,pDosHeader,pExportDir->AddressOfFunctions);
  PWORD pwOrdinals=RVAPTR(PWORD,pDosHeader,pExportDir->AddressOfNameOrdinals);
  if(!pszName||!pwOrdinals||!pdwAddress)
    return NULL;
  if(HIWORD(lpProcName)==0)
    dwOrdinal=(LOWORD((DWORD)lpProcName)-pExportDir->Base);
  else{
    for(index=0;index<pExportDir->NumberOfNames;index++){
      if(!strcmp(RVAPTR(PCHAR,pDosHeader,pszName[index]),lpProcName)){
        dwOrdinal=pwOrdinals[index];
        break;
      }
    }
  }
  DWORD dwFunction=RVAPTR(DWORD,pDosHeader,pdwAddress[dwOrdinal]);
  if((dwFunction>(ULONG_PTR)pExportDir)&&(dwFunction<((ULONG_PTR)pExportDir+dwExportSize))){
    CHAR ForwarderDllName[MAX_PATH],*ForwardImportName;USHORT len;
    ForwardImportName=strchr((LPSTR)dwFunction,'.');
    len=ForwardImportName++-(LPSTR)dwFunction;
    strncpy(ForwarderDllName,(LPSTR)dwFunction,len);
    strcpy(&ForwarderDllName[len],".dll");
    return GetProcAddress(GetModuleHandleA(ForwarderDllName),ForwardImportName);
  }
  return (FARPROC)dwFunction;
}

HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName){
  PTEB teb=NtCurrentTeb();
  if(teb){
    if(!lpModuleName)
      return (HMODULE)NtCurrentPeb()->ImageBaseAddress;
    PPEB_LDR_DATA ldrData=teb->ProcessEnvironmentBlock->Ldr;
    if(ldrData){
      PLIST_ENTRY pDTHead=&ldrData->InLoadOrderModuleList;
      PLDR_DATA_TABLE_ENTRY pDTEntry=(PLDR_DATA_TABLE_ENTRY)ldrData->InLoadOrderModuleList.Flink;
      while(pDTHead&&pDTEntry&&pDTHead!=(PLIST_ENTRY)pDTEntry){
        CHAR ModName[MAX_PATH];
        RtlUnicodeToMultiByte(ModName,sizeof(ModName),pDTEntry->BaseDllName.Buffer,pDTEntry->BaseDllName.Length);
        ModName[pDTEntry->BaseDllName.Length/sizeof(WCHAR)]=0;
        if(!stricmp(ModName,lpModuleName))
          return (HMODULE)pDTEntry->DllBase;
        pDTEntry=(PLDR_DATA_TABLE_ENTRY)pDTEntry->InLoadOrderLinks.Flink;
      }
    }
  }
  return NULL;
}

HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName){
  PTEB teb=NtCurrentTeb();
  if(teb){
    if(!lpModuleName)
      return (HMODULE)NtCurrentPeb()->ImageBaseAddress;
    PPEB_LDR_DATA ldrData=teb->ProcessEnvironmentBlock->Ldr;
    if(ldrData){
      PLIST_ENTRY pDTHead=&ldrData->InLoadOrderModuleList;
      PLDR_DATA_TABLE_ENTRY pDTEntry=(PLDR_DATA_TABLE_ENTRY)ldrData->InLoadOrderModuleList.Flink;
      while(pDTHead&&pDTEntry&&pDTHead!=(PLIST_ENTRY)pDTEntry){
        WCHAR ModName[MAX_PATH];
        wcsncpy(ModName,pDTEntry->BaseDllName.Buffer,pDTEntry->BaseDllName.Length);
        ModName[pDTEntry->BaseDllName.Length]=0;
        if(!_wcsicmp(ModName,lpModuleName))
          return (HMODULE)pDTEntry->DllBase;
        pDTEntry=(PLDR_DATA_TABLE_ENTRY)pDTEntry->InLoadOrderLinks.Flink;
      }
    }
  }
  return NULL;
}

DWORD WINAPI GetModuleBaseAndSizeA(LPCSTR lpModuleName,PDWORD pSize){
  PTEB teb=NtCurrentTeb();
  if(teb){
    PPEB_LDR_DATA ldrData=teb->ProcessEnvironmentBlock->Ldr;
    if(ldrData){
      PLIST_ENTRY pDTHead=&ldrData->InLoadOrderModuleList;
      PLDR_DATA_TABLE_ENTRY pDTEntry=(PLDR_DATA_TABLE_ENTRY)ldrData->InLoadOrderModuleList.Flink;
      while(pDTHead&&pDTEntry&&pDTHead!=(PLIST_ENTRY)pDTEntry){
        CHAR ModName[MAX_PATH];
        RtlUnicodeToMultiByte(ModName,sizeof(ModName),pDTEntry->BaseDllName.Buffer,pDTEntry->BaseDllName.Length);
        ModName[pDTEntry->BaseDllName.Length/sizeof(WCHAR)]=0;
        if(!lpModuleName||!stricmp(ModName,lpModuleName)){
          if(pSize)*pSize=pDTEntry->SizeOfImage;
          return (DWORD)pDTEntry->DllBase;
        }
        pDTEntry=(PLDR_DATA_TABLE_ENTRY)pDTEntry->InLoadOrderLinks.Flink;
      }
    }
  }
  //scan memory...
  return (DWORD)QueryRemoteModuleHandleAndSize(NtCurrentProcess(),lpModuleName,pSize);
}

DWORD WINAPI GetModuleBaseAndSizeByAddress(PVOID dwAddress,PDWORD pSize){
  PTEB teb=NtCurrentTeb();
  if(teb){
    PPEB_LDR_DATA ldrData=teb->ProcessEnvironmentBlock->Ldr;
    if(ldrData){
      PLIST_ENTRY pDTHead=&ldrData->InLoadOrderModuleList;
      PLDR_DATA_TABLE_ENTRY pDTEntry=(PLDR_DATA_TABLE_ENTRY)ldrData->InLoadOrderModuleList.Flink;
      while(pDTHead&&pDTEntry&&pDTHead!=(PLIST_ENTRY)pDTEntry){
        if(pDTEntry->DllBase<=dwAddress&&(PVOID)((ULONG)pDTEntry->DllBase+pDTEntry->SizeOfImage)>=dwAddress){
          if(pSize)*pSize=pDTEntry->SizeOfImage;
          return (DWORD)pDTEntry->DllBase;
        }
        pDTEntry=(PLDR_DATA_TABLE_ENTRY)pDTEntry->InLoadOrderLinks.Flink;
      }
    }
  }
  //scan memory
  return (DWORD)QueryRemoteModuleHandleAndSizeByAddress(NtCurrentProcess(),dwAddress,pSize);
}

DWORD WINAPI GetModuleBaseAndSizeW(LPCWSTR lpModuleName,PDWORD pSize){
  PTEB teb=NtCurrentTeb();
  if(teb){
    PPEB_LDR_DATA ldrData=teb->ProcessEnvironmentBlock->Ldr;
    if(ldrData){
      PLIST_ENTRY pDTHead=&ldrData->InLoadOrderModuleList;
      PLDR_DATA_TABLE_ENTRY pDTEntry=(PLDR_DATA_TABLE_ENTRY)ldrData->InLoadOrderModuleList.Flink;
      while(pDTHead&&pDTEntry&&pDTHead!=(PLIST_ENTRY)pDTEntry){
        WCHAR ModName[MAX_PATH];
        wcsncpy(ModName,pDTEntry->BaseDllName.Buffer,pDTEntry->BaseDllName.Length);
        ModName[pDTEntry->BaseDllName.Length]=0;
        if(!lpModuleName||!_wcsicmp(ModName,lpModuleName)){
          if(pSize)*pSize=pDTEntry->SizeOfImage;
          return (DWORD)pDTEntry->DllBase;
        }
        pDTEntry=(PLDR_DATA_TABLE_ENTRY)pDTEntry->InLoadOrderLinks.Flink;
      }
    }
  }
  return 0;
}

DWORD WINAPI GetModuleFileName(HMODULE hModule,LPSTR lpFilename,DWORD nSize){
  PTEB teb=NtCurrentTeb();
  if(teb){
    if(!hModule)hModule=(HMODULE)NtCurrentPeb()->ImageBaseAddress;
    PPEB_LDR_DATA ldrData=teb->ProcessEnvironmentBlock->Ldr;
    if(ldrData){
      PLIST_ENTRY pDTHead=&ldrData->InLoadOrderModuleList;
      PLDR_DATA_TABLE_ENTRY pDTEntry=(PLDR_DATA_TABLE_ENTRY)ldrData->InLoadOrderModuleList.Flink;
      while(pDTHead&&pDTEntry&&pDTHead!=(PLIST_ENTRY)pDTEntry){
        if(pDTEntry->DllBase==hModule){
          DWORD len=RtlUnicodeToMultiByte(lpFilename,nSize,pDTEntry->FullDllName.Buffer,pDTEntry->FullDllName.Length);
          lpFilename[len]=0;
          return len;
        }
        pDTEntry=(PLDR_DATA_TABLE_ENTRY)pDTEntry->InLoadOrderLinks.Flink;
      }
    }
  }
  return 0;
}

DWORD WINAPI GetModuleNameByAddress(PVOID dwAddress,LPSTR sModuleName,DWORD nSize){
  PTEB teb=NtCurrentTeb();
  if(teb){
    PPEB_LDR_DATA ldrData=teb->ProcessEnvironmentBlock->Ldr;
    if(ldrData){
      PLIST_ENTRY pDTHead=&ldrData->InLoadOrderModuleList;
      PLDR_DATA_TABLE_ENTRY pDTEntry=(PLDR_DATA_TABLE_ENTRY)ldrData->InLoadOrderModuleList.Flink;
      while(pDTHead&&pDTEntry&&pDTHead!=(PLIST_ENTRY)pDTEntry){
        if(pDTEntry->DllBase<=dwAddress&&(PVOID)((ULONG)pDTEntry->DllBase+pDTEntry->SizeOfImage)>=dwAddress){
          DWORD len=RtlUnicodeToMultiByte(sModuleName,nSize,pDTEntry->FullDllName.Buffer,pDTEntry->FullDllName.Length);
          sModuleName[len]=0;
          return len;
        }
        pDTEntry=(PLDR_DATA_TABLE_ENTRY)pDTEntry->InLoadOrderLinks.Flink;
      }
    }
  }
  //scan memory...
  return QueryRemoteModuleByAddress(NtCurrentProcess(),dwAddress,sModuleName,nSize);
}

HMODULE WINAPI GetRemoteModuleHandle(HANDLE hProcess,LPCSTR lpModuleName){
  PROCESS_BASIC_INFORMATION pbiInfo;PEB_LDR_DATA pldLdrData;PEB peb;
  NTSTATUS Status=_NtQueryInformationProcess(hProcess,ProcessBasicInformation,&pbiInfo,sizeof(pbiInfo),NULL);
  if(!NT_SUCCESS(Status))
    return NULL;
  Status=_NtReadVirtualMemory(hProcess,pbiInfo.PebBaseAddress,&peb,sizeof(peb),NULL);
  if(!NT_SUCCESS(Status))
    return NULL;
  Status=_NtReadVirtualMemory(hProcess,peb.Ldr,&pldLdrData,sizeof(pldLdrData),NULL);
  if(!NT_SUCCESS(Status))
    return NULL;
  PLIST_ENTRY pleListHead=&peb.Ldr->InLoadOrderModuleList;
  PLIST_ENTRY pleCurEntry=pldLdrData.InLoadOrderModuleList.Flink;
  while(pleCurEntry!=pleListHead){
    LDR_DATA_TABLE_ENTRY lmModule;CHAR ModuleName[MAX_PATH];WCHAR Buffer[MAX_PATH];
    Status=_NtReadVirtualMemory(hProcess,CONTAINING_RECORD(pleCurEntry,LDR_DATA_TABLE_ENTRY,InLoadOrderLinks),&lmModule,sizeof(LDR_DATA_TABLE_ENTRY),NULL);
    if(!NT_SUCCESS(Status))
      return NULL;
    Status=_NtReadVirtualMemory(hProcess,lmModule.BaseDllName.Buffer,Buffer,lmModule.BaseDllName.Length,NULL);
    if(!NT_SUCCESS(Status))
      return NULL;
    Buffer[lmModule.BaseDllName.Length/sizeof(WCHAR)]=0;
    RtlUnicodeToMultiByte(ModuleName,sizeof(ModuleName),Buffer,(ULONG)-1);
    if(!stricmp(ModuleName,lpModuleName))
      return (HMODULE)lmModule.DllBase;
    pleCurEntry=lmModule.InLoadOrderLinks.Flink;
  }
  return NULL;
}

FARPROC WINAPI GetRemoteProcAddress(HANDLE hProcess,HMODULE hModule,LPCSTR lpProcName){
  IMAGE_DOS_HEADER hdrDos={0};IMAGE_NT_HEADERS hdrNt={0};
  DWORD dwExportSize=0,dwExportBase=0;DWORD dwFunction=0;
  DWORD index,dwOrdinal=0;

  if(hModule==NULL)
    return NULL;

  ReadProcessMemory(hProcess,hModule,&hdrDos,sizeof(hdrDos),NULL);
  if(hdrDos.e_magic!=IMAGE_DOS_SIGNATURE){
    return NULL;
  }

  ReadProcessMemory(hProcess,(PVOID)((DWORD)hModule+hdrDos.e_lfanew),&hdrNt,sizeof(IMAGE_NT_HEADERS),NULL);
  if(hdrNt.Signature!=IMAGE_NT_SIGNATURE){
    return NULL;
  }

  if(hdrNt.OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    dwExportBase=hdrNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  else{
    return NULL;
  }

  if(dwExportBase){
    dwExportSize=hdrNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    IMAGE_EXPORT_DIRECTORY* pExportDir=(IMAGE_EXPORT_DIRECTORY*)LocalAlloc(LPTR,dwExportSize);
    if(!pExportDir){
      return 0;
    }

    ReadProcessMemory(hProcess,(PVOID)((DWORD)hModule+dwExportBase),pExportDir,dwExportSize,NULL);
    PCHAR* pszName=RVAPTR(PCHAR*,(DWORD)pExportDir-dwExportBase,pExportDir->AddressOfNames);
    PDWORD pdwAddress=RVAPTR(PDWORD,(DWORD)pExportDir-dwExportBase,pExportDir->AddressOfFunctions);
    PWORD pwOrdinals=RVAPTR(PWORD,(DWORD)pExportDir-dwExportBase,pExportDir->AddressOfNameOrdinals);
    if(!pszName||!pwOrdinals||!pdwAddress){
      LocalFree(pExportDir);
      return NULL;
    }
    if(HIWORD(lpProcName)==0)
      dwOrdinal=(LOWORD((DWORD)lpProcName)-pExportDir->Base);
    else{
      for(index=0;index<pExportDir->NumberOfNames;index++){
        if(!strcmp(RVAPTR(PCHAR,(DWORD)pExportDir-dwExportBase,pszName[index]),lpProcName)){
          dwOrdinal=pwOrdinals[index];
          break;
        }
      }
    }
    dwFunction=RVAPTR(DWORD,hModule,pdwAddress[dwOrdinal]);
    if((dwFunction>((ULONG_PTR)hModule+dwExportBase))&&(dwFunction<((ULONG_PTR)hModule+dwExportBase+dwExportSize))){
      CHAR ForwarderDllName[MAX_PATH],*ForwardImportName;USHORT len;
      dwFunction=RVAPTR(DWORD,(DWORD)pExportDir-dwExportBase,pdwAddress[dwOrdinal]);
      ForwardImportName=strchr((LPSTR)dwFunction,'.');
      len=ForwardImportName++-(LPSTR)dwFunction;
      strncpy(ForwarderDllName,(LPSTR)dwFunction,len);
      strcpy(&ForwarderDllName[len],".dll");
      dwFunction=(DWORD)GetRemoteProcAddress(hProcess,GetRemoteModuleHandle(hProcess,ForwarderDllName),ForwardImportName);
    }
    LocalFree(pExportDir);
  }
  return (FARPROC)dwFunction;
}

// *******************************************************************************
// Fake RtlHeap Functions
// *******************************************************************************

PVOID WINAPI RtlAllocateHeap(HANDLE hHeap,DWORD dwFlags,SIZE_T dwBytes){
  return HeapAlloc(hHeap,dwFlags,dwBytes);
}

PVOID WINAPI RtlReAllocateHeap(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem,SIZE_T dwBytes){
  return HeapReAlloc(hHeap,dwFlags,lpMem,dwBytes);
}

BOOL WINAPI RtlFreeHeap(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem){
  return HeapFree(hHeap,dwFlags,lpMem);
}

PVOID WINAPI RtlCreateHeap(DWORD flOptions,PVOID HeapBase,SIZE_T ReserveSize,SIZE_T CommitSize,PVOID Lock,PVOID Parameters){
  return HeapCreate(flOptions,CommitSize,ReserveSize);
}

BOOL WINAPI RtlDestroyHeap(HANDLE hHeap){
  return HeapDestroy(hHeap);
}

BOOL WINAPI RtlLockHeap(HANDLE hHeap){
  return HeapLock(hHeap);
}

BOOL WINAPI RtlUnlockHeap(HANDLE hHeap){
  return HeapUnlock(hHeap);
}

HLOCAL WINAPI LocalAlloc(UINT uFlags,SIZE_T dwBytes){
  ULONG Flags=0;
  if(uFlags&LMEM_ZEROINIT)Flags|=HEAP_ZERO_MEMORY;
  if((uFlags&LMEM_MOVEABLE))
    return NULL;//not supported!
  return RtlAllocateHeap(RtlGetProcessHeap(),Flags,dwBytes);
}

HLOCAL WINAPI LocalFree(HLOCAL hMem){
  if(RtlFreeHeap(RtlGetProcessHeap(),0,hMem))
    return NULL;
  return hMem;
}

// *******************************************************************************
// Kernel32 Virtual Memory Functions
// *******************************************************************************

BOOL WINAPI VirtualProtectEx(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect){
  NTSTATUS Status=_NtProtectVirtualMemory(hProcess,&lpAddress,&dwSize,flNewProtect,lpflOldProtect);
  return NT_SUCCESS(Status);
}

LPVOID WINAPI VirtualAllocEx(HANDLE hProcess,LPVOID lpAddress,DWORD dwSize,DWORD flAllocationType,DWORD flProtect){
  NTSTATUS Status=_NtAllocateVirtualMemory(hProcess,&lpAddress,0,&dwSize,flAllocationType,flProtect);
  if(!NT_SUCCESS(Status))
    return NULL;
  return lpAddress;
}

BOOL WINAPI VirtualFreeEx(HANDLE hProcess,LPVOID lpAddress,DWORD dwSize,DWORD dwFreeType){
  if((dwFreeType&MEM_RELEASE)&&(dwSize!=0))
    return FALSE;
  NTSTATUS Status=_NtFreeVirtualMemory(hProcess,&lpAddress,&dwSize,dwFreeType);
  if(!NT_SUCCESS(Status))
    return FALSE;
  return TRUE;
}

DWORD WINAPI VirtualQueryEx(HANDLE hProcess,LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength){
  ULONG ResultLength;
  NTSTATUS Status=_NtQueryVirtualMemory(hProcess,(LPVOID)lpAddress,MemoryBasicInformation,lpBuffer,dwLength,&ResultLength);
  if(NT_SUCCESS(Status))
    return ResultLength;
  return 0;
}

BOOL WINAPI VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect){
  if(!VirtualProtectEx((HANDLE)-1,lpAddress,dwSize,flNewProtect,lpflOldProtect)){
    return FALSE;
  }
  return TRUE;
}

LPVOID WINAPI VirtualAlloc(LPVOID lpAddress,DWORD dwSize,DWORD flAllocationType,DWORD flProtect){
  return VirtualAllocEx((HANDLE)-1,lpAddress,dwSize,flAllocationType,flProtect);
}

BOOL WINAPI VirtualFree(LPVOID lpAddress,DWORD dwSize,DWORD dwFreeType){
  return VirtualFreeEx((HANDLE)-1,lpAddress,dwSize,dwFreeType);
}

DWORD WINAPI VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength){
  return VirtualQueryEx((HANDLE)-1,lpAddress,lpBuffer,dwLength);
}

BOOL WINAPI WriteProcessMemory(HANDLE hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesWritten){
  ULONG OldValue;SIZE_T sNumberOfBytesWritten=0;
  SIZE_T RegionSize=nSize;
  PVOID Base=lpBaseAddress;
  NTSTATUS Status=_NtProtectVirtualMemory(hProcess,&Base,&RegionSize,PAGE_EXECUTE_READWRITE,&OldValue);
  if(NT_SUCCESS(Status)){
    Status=_NtWriteVirtualMemory(hProcess,lpBaseAddress,(LPVOID)lpBuffer,nSize,&sNumberOfBytesWritten);
    _NtProtectVirtualMemory(hProcess,&Base,&RegionSize,OldValue,&OldValue);
    if(!NT_SUCCESS(Status))
      return FALSE;
    Status=_NtFlushInstructionCache(hProcess,lpBaseAddress,nSize);
    if(lpNumberOfBytesWritten)
      *lpNumberOfBytesWritten=sNumberOfBytesWritten;
    return TRUE;
  }
  return FALSE;
}

BOOL WINAPI ReadProcessMemory(HANDLE hProcess,LPCVOID lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesRead){
  NTSTATUS Status=_NtReadVirtualMemory(hProcess,(PVOID)lpBaseAddress,lpBuffer,nSize,&nSize);
  if(lpNumberOfBytesRead)
    *lpNumberOfBytesRead=nSize;
  return NT_SUCCESS(Status);
}

BOOL WINAPI FlushInstructionCache(HANDLE hProcess,LPCVOID lpBaseAddress,SIZE_T dwSize){
  NTSTATUS Status=_NtFlushInstructionCache(hProcess,(PVOID)lpBaseAddress,dwSize);
  return NT_SUCCESS(Status);
}

HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwProcessId){
  HANDLE hProcess;OBJECT_ATTRIBUTES ObjectAttributes;
  CLIENT_ID ClientId={(PVOID)dwProcessId,0};
  InitializeObjectAttributes(&ObjectAttributes,NULL,(bInheritHandle?OBJ_INHERIT:0),NULL,NULL);
  NTSTATUS Status=_NtOpenProcess(&hProcess,dwDesiredAccess,&ObjectAttributes,&ClientId);
  if(NT_SUCCESS(Status))
    return hProcess;
  return NULL;
}

HANDLE WINAPI OpenThread(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwThreadId){
  HANDLE hThread;OBJECT_ATTRIBUTES ObjectAttributes;
  CLIENT_ID ClientId={0,(PVOID)dwThreadId};
  InitializeObjectAttributes(&ObjectAttributes,NULL,(bInheritHandle?OBJ_INHERIT:0),NULL,NULL);
  NTSTATUS Status=_NtOpenThread(&hThread,dwDesiredAccess,&ObjectAttributes,&ClientId);
  if(NT_SUCCESS(Status))
    return hThread;
  return NULL;
}

BOOL WINAPI GetThreadSelectorEntry(HANDLE hThread,DWORD dwSelector,LPLDT_ENTRY lpSelectorEntry){
  DESCRIPTOR_TABLE_ENTRY DescriptionTableEntry;
  DescriptionTableEntry.Selector=dwSelector;
  NTSTATUS Status=_NtQueryInformationThread(hThread,ThreadDescriptorTableEntry,
    &DescriptionTableEntry,sizeof(DESCRIPTOR_TABLE_ENTRY),NULL);
  if(NT_SUCCESS(Status)){
    *lpSelectorEntry=DescriptionTableEntry.Descriptor;
    return TRUE;
  }
  return FALSE;
}

BOOL WINAPI GetThreadContext(HANDLE hThread,LPCONTEXT lpContext){
  NTSTATUS Status=_NtGetContextThread(hThread,lpContext);
  return NT_SUCCESS(Status);
}

BOOL WINAPI SetThreadContext(HANDLE hThread,CONST LPCONTEXT lpContext){
  NTSTATUS Status=_NtSetContextThread(hThread,(PCONTEXT)lpContext);
  return NT_SUCCESS(Status);
}

DWORD WINAPI GetCurrentThreadId(VOID){
  return HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread);
}

DWORD WINAPI GetCurrentProcessId(VOID){
  return HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess);
}

BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle,DWORD DesiredAccess,PHANDLE TokenHandle){
  NTSTATUS Status=_NtOpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
  return NT_SUCCESS(Status);
}

BOOL WINAPI AdjustTokenPrivileges(HANDLE TokenHandle,BOOL DisableAllPrivileges,PTOKEN_PRIVILEGES NewState,DWORD BufferLength,PTOKEN_PRIVILEGES PreviousState,PDWORD ReturnLength){
  NTSTATUS Status=_NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
  return NT_SUCCESS(Status);
}

BOOL WINAPI ProcessIdToSessionId(DWORD dwProcessId,DWORD *pSessionId){
  PROCESS_SESSION_INFORMATION SessionInformation;CLIENT_ID ClientId;
  OBJECT_ATTRIBUTES ObjectAttributes;HANDLE ProcessHandle;
  if(!pSessionId)
    return FALSE;
  ClientId.UniqueProcess=(PVOID)dwProcessId;
  ClientId.UniqueThread=0;
  InitializeObjectAttributes(&ObjectAttributes,NULL,0,NULL,NULL);
  NTSTATUS Status=_NtOpenProcess(&ProcessHandle,PROCESS_QUERY_INFORMATION,&ObjectAttributes,&ClientId);
  if(NT_SUCCESS(Status)){
    Status=_NtQueryInformationProcess(ProcessHandle,ProcessSessionInformation,&SessionInformation,sizeof(SessionInformation),NULL);
    _NtClose(ProcessHandle);
    if(NT_SUCCESS(Status)){
      *pSessionId=SessionInformation.SessionId;
      return TRUE;
    }
  }
  return FALSE;
}

// *******************************************************************************
// Kernel32 Threads Functions
// *******************************************************************************

PLARGE_INTEGER WINAPI BaseFormatTimeOut(PLARGE_INTEGER Timeout,DWORD dwMilliseconds){
  if(dwMilliseconds==INFINITE)return NULL;
  Timeout->QuadPart=UInt32x32To64(dwMilliseconds,-10000);
  return Timeout;
}

NTSTATUS WINAPI BaseFreeThreadStack(HANDLE Process,DWORD dwReserved,PINITIAL_TEB InitialTeb){
  SIZE_T RegionSize=0;
  return _NtFreeVirtualMemory(Process,(PVOID *)&InitialTeb->StackLimit,&RegionSize,MEM_RELEASE);
}

HANDLE WINAPI CreateRemoteThread(HANDLE hProcess,LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId){
  NTSTATUS Status;INITIAL_TEB InitialTeb;CLIENT_ID ClientId;
  ULONG StackSize,MaximumStackSize;OBJECT_ATTRIBUTES Obja,*pObja;
  CONTEXT ThreadContext;HANDLE ThreadHandle=NULL;
  THREAD_BASIC_INFORMATION TBI;ULONG uCount=0;

  pObja=BaseFormatObjectAttributes(&Obja,lpThreadAttributes,0);

  if(wversion<WIN10CU){
    if((dwCreationFlags>>8)&1){
      MaximumStackSize=dwStackSize;
      StackSize=0;
    }else{
      MaximumStackSize=0;
      StackSize=dwStackSize;
    }

    Status=BaseCreateStack(hProcess,StackSize,MaximumStackSize,&InitialTeb);//OK!
    if(!NT_SUCCESS(Status)){
      return NULL;
    }

    BaseInitializeContext(hProcess,&ThreadContext,lpParameter,(PVOID)lpStartAddress,InitialTeb.StackBase,BaseContextTypeProcess);//OK!

    ClientId.UniqueProcess=hProcess;

    Status=_NtCreateThread(&ThreadHandle,THREAD_ALL_ACCESS,pObja,hProcess,&ClientId,&ThreadContext,&InitialTeb,TRUE);
  }else
    Status=_NtCreateThreadEx(&ThreadHandle,THREAD_ALL_ACCESS,pObja,hProcess,lpStartAddress,lpParameter,TRUE,0,0,0,NULL);

  if(NT_SUCCESS(Status)){
    Status=_NtQueryInformationThread(ThreadHandle,ThreadBasicInformation,&TBI,sizeof(THREAD_BASIC_INFORMATION),NULL);
    if(NT_SUCCESS(Status)){
      if(!(dwCreationFlags&CREATE_SUSPENDED)){
        Status=_NtResumeThread(ThreadHandle,&uCount);
      }
      if(lpThreadId)
        *lpThreadId=(DWORD)ClientId.UniqueThread;
      return ThreadHandle;
    }
  }
  BaseFreeThreadStack(hProcess,0,&InitialTeb);
  return NULL;
}

HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId){
  return CreateRemoteThread((HANDLE)-1,lpThreadAttributes,dwStackSize,lpStartAddress,lpParameter,dwCreationFlags,lpThreadId);
}

BOOL WINAPI TerminateThread(HANDLE hThread,DWORD dwExitCode){
  return NT_SUCCESS(_NtTerminateThread(hThread,dwExitCode));
}

VOID WINAPI __attribute__((noreturn)) ExitThread(DWORD uExitCode){
  _NtTerminateThread(NULL,uExitCode);
  __builtin_unreachable();
}

BOOL WINAPI TerminateProcess(HANDLE hProcess,UINT uExitCode){
  return NT_SUCCESS(_NtTerminateProcess(hProcess,uExitCode));
}

VOID WINAPI __attribute__((noreturn)) ExitProcess(UINT uExitCode){
  _NtTerminateProcess(NtCurrentProcess(),uExitCode);
  __builtin_unreachable();
}

BOOL WINAPI GetExitCodeProcess(HANDLE hProcess,LPDWORD lpExitCode){
  PROCESS_BASIC_INFORMATION ProcessBasic;
  if(!lpExitCode)
    return FALSE;
  NTSTATUS Status=_NtQueryInformationProcess(hProcess,ProcessBasicInformation,&ProcessBasic,sizeof(ProcessBasic),NULL);
  if(NT_SUCCESS(Status)){
    *lpExitCode=(DWORD)ProcessBasic.ExitStatus;
    return TRUE;
  }
  return FALSE;
}

BOOL WINAPI GetExitCodeThread(HANDLE hThread,LPDWORD lpExitCode){
  THREAD_BASIC_INFORMATION ThreadBasic;
  if(!lpExitCode)
    return FALSE;
  NTSTATUS Status=_NtQueryInformationThread(hThread,ThreadBasicInformation,&ThreadBasic,sizeof(ThreadBasic),NULL);
  if(NT_SUCCESS(Status)){
    *lpExitCode=ThreadBasic.ExitStatus;
    return TRUE;
  }
  return FALSE;
}

DWORD WINAPI SuspendThread(HANDLE hThread){
  ULONG PreviousSuspendCount=0;
  NTSTATUS Status=_NtSuspendThread(hThread,&PreviousSuspendCount);
  if(NT_SUCCESS(Status))
    return PreviousSuspendCount;
  return (DWORD)-1;
}

DWORD WINAPI ResumeThread(HANDLE hThread){
  ULONG PreviousResumeCount=0;
  NTSTATUS Status=_NtResumeThread(hThread,&PreviousResumeCount);
  if(NT_SUCCESS(Status))
    return PreviousResumeCount;
  return (DWORD)-1;
}

INT WINAPI GetThreadPriority(HANDLE hThread){
  THREAD_BASIC_INFORMATION ThreadBasic;
  NTSTATUS Status=_NtQueryInformationThread(hThread,ThreadBasicInformation,&ThreadBasic,sizeof(THREAD_BASIC_INFORMATION),NULL);
  if(!NT_SUCCESS(Status))
    return THREAD_PRIORITY_ERROR_RETURN;
  if(ThreadBasic.BasePriority==((HIGH_PRIORITY+1)/2))
    ThreadBasic.BasePriority=THREAD_PRIORITY_TIME_CRITICAL;
  else if(ThreadBasic.BasePriority==-((HIGH_PRIORITY+1)/2))
    ThreadBasic.BasePriority=THREAD_PRIORITY_IDLE;
  return ThreadBasic.BasePriority;
}

BOOL WINAPI SetThreadPriority(HANDLE hThread,INT nPriority){
  LONG Prio=nPriority;
  if(Prio==THREAD_PRIORITY_TIME_CRITICAL)
    Prio=(HIGH_PRIORITY+1)/2;
  else if(Prio==THREAD_PRIORITY_IDLE)
    Prio=-((HIGH_PRIORITY+1)/2);
  NTSTATUS Status=_NtSetInformationThread(hThread,ThreadBasePriority,&Prio,sizeof(LONG));
  return NT_SUCCESS(Status);
}

LPVOID WINAPI TlsGetValueFromTeb(PTEB Teb,DWORD Index){
  if(Index<TLS_MINIMUM_AVAILABLE)
    return Teb->TlsSlots[Index];
  if(Index>=TLS_EXPANSION_SLOTS+TLS_MINIMUM_AVAILABLE||!Teb->TlsExpansionSlots)
    return NULL;
  return Teb->TlsExpansionSlots[Index-TLS_MINIMUM_AVAILABLE];
}

#if (__GNUC__ > 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ > 6 )))

#define _BITCOUNT 32
#define MAXINDEX 0xFFFFFFFF

typedef ULONG BITMAP_INDEX, *PBITMAP_INDEX;
typedef ULONG BITMAP_BUFFER, *PBITMAP_BUFFER;

VOID WINAPI RtlFillMemoryUlong(PVOID Destination,SIZE_T Length,ULONG Fill){
  PULONG Dest  = (PULONG)Destination;
  SIZE_T Count = Length / sizeof(ULONG);
  while (Count > 0){
    *Dest = Fill;
    Dest++;
    Count--;
  }
}

unsigned char BitScanForward(ULONG * Index, unsigned long Mask){
  *Index = 0;
  while (Mask && ((Mask & 1) == 0)){
    Mask >>= 1;
    ++(*Index);
  }
  return Mask ? 1 : 0;
}

unsigned char BitScanReverse(ULONG * const Index, unsigned long Mask){
  *Index = 0;
  while (Mask && ((Mask & (1 << 31)) == 0)){
    Mask <<= 1;
    ++(*Index);
  }
  return Mask ? 1 : 0;
}

BITMAP_INDEX WINAPI RtlpGetLengthOfRunSet(PRTL_BITMAP BitMapHeader,BITMAP_INDEX StartingIndex,BITMAP_INDEX MaxLength){
  BITMAP_INDEX InvValue, BitPos, Length;
  PBITMAP_BUFFER Buffer, MaxBuffer;
  if (StartingIndex >= BitMapHeader->SizeOfBitMap)
    return 0;
  Buffer = BitMapHeader->Buffer + StartingIndex / _BITCOUNT;
  BitPos = StartingIndex & (_BITCOUNT - 1);
  MaxLength = min(MaxLength, BitMapHeader->SizeOfBitMap - StartingIndex);
  MaxBuffer = Buffer + (BitPos + MaxLength + _BITCOUNT - 1) / _BITCOUNT;
  InvValue = ~(*Buffer++) >> BitPos << BitPos;
  while (InvValue == 0 && Buffer < MaxBuffer)
    InvValue = ~(*Buffer++);
  if (InvValue == 0)
    return MaxLength;
  BitScanForward(&BitPos, InvValue);
  Length = (ULONG)(Buffer - BitMapHeader->Buffer) * _BITCOUNT - StartingIndex;
  Length += BitPos - _BITCOUNT;
  if (Length > BitMapHeader->SizeOfBitMap - StartingIndex)
    Length = BitMapHeader->SizeOfBitMap - StartingIndex;
  return Length;
}

BITMAP_INDEX WINAPI RtlpGetLengthOfRunClear(PRTL_BITMAP BitMapHeader,BITMAP_INDEX StartingIndex,BITMAP_INDEX MaxLength){
  BITMAP_INDEX Value, BitPos, Length;
  PBITMAP_BUFFER Buffer, MaxBuffer;
  if (StartingIndex >= BitMapHeader->SizeOfBitMap)
    return 0;
  Buffer = BitMapHeader->Buffer + StartingIndex / _BITCOUNT;
  BitPos = StartingIndex & (_BITCOUNT - 1);
  MaxLength = min(MaxLength, BitMapHeader->SizeOfBitMap - StartingIndex);
  MaxBuffer = Buffer + (BitPos + MaxLength + _BITCOUNT - 1) / _BITCOUNT;
  Value = *Buffer++ >> BitPos << BitPos;
  while (Value == 0 && Buffer < MaxBuffer)
    Value = *Buffer++;
  if (Value == 0)
    return MaxLength;
  BitScanForward(&BitPos, Value);
  Length = (BITMAP_INDEX)(Buffer - BitMapHeader->Buffer) * _BITCOUNT - StartingIndex;
  Length += BitPos - _BITCOUNT;
  if (Length > BitMapHeader->SizeOfBitMap - StartingIndex)
    Length = BitMapHeader->SizeOfBitMap - StartingIndex;
  return Length;
}

BOOLEAN WINAPI RtlAreBitsSet(PRTL_BITMAP BitMapHeader,BITMAP_INDEX StartingIndex,BITMAP_INDEX Length){
  if((StartingIndex + Length > BitMapHeader->SizeOfBitMap) || (StartingIndex + Length <= StartingIndex))
    return FALSE;
  return RtlpGetLengthOfRunSet(BitMapHeader, StartingIndex, Length) >= Length;
}

VOID WINAPI RtlClearBits(PRTL_BITMAP BitMapHeader,BITMAP_INDEX StartingIndex,BITMAP_INDEX NumberToClear){
  BITMAP_INDEX Bits, Mask;PBITMAP_BUFFER Buffer;
  Buffer = &BitMapHeader->Buffer[StartingIndex / _BITCOUNT];
  Bits = StartingIndex & (_BITCOUNT - 1);
  if (Bits){
    Mask = MAXINDEX << Bits;
    Bits = _BITCOUNT - Bits;
    if (NumberToClear < Bits){
      Bits -= NumberToClear;
      Mask = Mask << Bits >> Bits;
      *Buffer &= ~Mask;
      return;
    }
    *Buffer &= ~Mask;
    Buffer++;
    NumberToClear -= Bits;
  }
  RtlFillMemoryUlong(Buffer, NumberToClear >> 3, 0);
  Buffer += NumberToClear / _BITCOUNT;
  NumberToClear &= (_BITCOUNT - 1);
  Mask = MAXINDEX << NumberToClear;
  *Buffer &= Mask;
}

VOID WINAPI RtlSetBits(PRTL_BITMAP BitMapHeader,BITMAP_INDEX StartingIndex,BITMAP_INDEX NumberToSet){
  BITMAP_INDEX Bits, Mask;PBITMAP_BUFFER Buffer;
  Buffer = &BitMapHeader->Buffer[StartingIndex / _BITCOUNT];
  Bits = StartingIndex & (_BITCOUNT - 1);
  if (Bits){
    Mask = MAXINDEX << Bits;
    Bits = _BITCOUNT - Bits;
    if (NumberToSet < Bits){
      Bits -= NumberToSet;
      Mask = Mask << Bits >> Bits;
      *Buffer |= Mask;
      return;
    }
    *Buffer |= Mask;
    Buffer++;
    NumberToSet -= Bits;
  }
  RtlFillMemoryUlong(Buffer, NumberToSet >> 3, MAXINDEX);
  Buffer += NumberToSet / _BITCOUNT;
  NumberToSet &= (_BITCOUNT - 1);
  Mask = MAXINDEX << NumberToSet;
  *Buffer |= ~Mask;
}

BITMAP_INDEX WINAPI RtlFindClearBits(PRTL_BITMAP BitMapHeader,BITMAP_INDEX NumberToFind,BITMAP_INDEX HintIndex){
  BITMAP_INDEX CurrentBit, Margin, CurrentLength;
  if (!BitMapHeader || NumberToFind > BitMapHeader->SizeOfBitMap)
    return MAXINDEX;
  if (HintIndex >= BitMapHeader->SizeOfBitMap)
  HintIndex = 0;
  if (NumberToFind == 0)
    return HintIndex & ~7;
  Margin = BitMapHeader->SizeOfBitMap;
retry:
  CurrentBit = HintIndex;
  while (CurrentBit + NumberToFind < Margin){
    CurrentBit += RtlpGetLengthOfRunSet(BitMapHeader,CurrentBit,MAXINDEX);
    CurrentLength = RtlpGetLengthOfRunClear(BitMapHeader,CurrentBit,NumberToFind);
    if (CurrentLength >= NumberToFind)
      return CurrentBit;
    CurrentBit += CurrentLength;
  }
  if (HintIndex){
    Margin = min(HintIndex + NumberToFind, BitMapHeader->SizeOfBitMap);
    HintIndex = 0;
    goto retry;
  }
  return MAXINDEX;
}

BITMAP_INDEX WINAPI RtlFindClearBitsAndSet(PRTL_BITMAP BitMapHeader,BITMAP_INDEX NumberToFind,BITMAP_INDEX HintIndex){
  ULONG Position=RtlFindClearBits(BitMapHeader,NumberToFind,HintIndex);
  if(Position!=(ULONG)-1)
    RtlSetBits(BitMapHeader,Position,NumberToFind);
  return Position;
}

BITMAP_INDEX WINAPI RtlFindSetBits(PRTL_BITMAP BitMapHeader,BITMAP_INDEX NumberToFind,BITMAP_INDEX HintIndex){
  BITMAP_INDEX CurrentBit, Margin, CurrentLength;
  if (!BitMapHeader || NumberToFind > BitMapHeader->SizeOfBitMap)
    return MAXINDEX;
  if (HintIndex >= BitMapHeader->SizeOfBitMap)
  HintIndex = 0;
  if (NumberToFind == 0)
    return HintIndex & ~7;
  Margin = BitMapHeader->SizeOfBitMap;
retry:
  CurrentBit = HintIndex;
  while (CurrentBit + NumberToFind <= Margin){
    CurrentBit += RtlpGetLengthOfRunClear(BitMapHeader,CurrentBit,MAXINDEX);
    CurrentLength = RtlpGetLengthOfRunSet(BitMapHeader,CurrentBit,NumberToFind);
    if (CurrentLength >= NumberToFind)
      return CurrentBit;
    CurrentBit += CurrentLength;
  }
  if (HintIndex){
    Margin = min(HintIndex + NumberToFind, BitMapHeader->SizeOfBitMap);
    HintIndex = 0;
    goto retry;
  }
  return MAXINDEX;
}

BITMAP_INDEX WINAPI RtlFindSetBitsAndClear(PRTL_BITMAP BitMapHeader,BITMAP_INDEX NumberToFind,BITMAP_INDEX HintIndex){
  BITMAP_INDEX Position=RtlFindSetBits(BitMapHeader, NumberToFind, HintIndex);
  if(Position != MAXINDEX)
    RtlClearBits(BitMapHeader,Position,NumberToFind);
  return Position;
}

DWORD WINAPI TlsAlloc(VOID){
  ULONG Index=TLS_OUT_OF_INDEXES;
  PTEB Teb=NtCurrentTeb();
  PPEB Peb=NtCurrentPeb();
  Index=RtlFindClearBitsAndSet((PRTL_BITMAP)Peb->TlsBitmap,1,0);
  if(Index==TLS_OUT_OF_INDEXES){
    Index=RtlFindClearBitsAndSet((PRTL_BITMAP)Peb->TlsExpansionBitmap,1,0);
    if(Index!=TLS_OUT_OF_INDEXES){
      if(Teb->TlsExpansionSlots==NULL)
        Teb->TlsExpansionSlots=(PVOID*)HeapAlloc(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,TLS_EXPANSION_SLOTS *sizeof(PVOID));
      if(Teb->TlsExpansionSlots==NULL){
        RtlClearBits(Peb->TlsExpansionBitmap,Index,1);
        Index=TLS_OUT_OF_INDEXES;
      }else{
        Teb->TlsExpansionSlots[Index]=0;
        Index+=TLS_MINIMUM_AVAILABLE;
      }
    }
  }else
    Teb->TlsSlots[Index]=0;
  return Index;
}

BOOL WINAPI TlsFree(DWORD Index){
  BOOL BitSet;
  PPEB Peb=NtCurrentPeb();
  if(Index>=TLS_EXPANSION_SLOTS+TLS_MINIMUM_AVAILABLE)
    return FALSE;
  if(Index>=TLS_MINIMUM_AVAILABLE){
    BitSet=RtlAreBitsSet((PRTL_BITMAP)Peb->TlsExpansionBitmap,Index-TLS_MINIMUM_AVAILABLE,1);
    if(BitSet)
      RtlClearBits((PRTL_BITMAP)Peb->TlsExpansionBitmap,Index-TLS_MINIMUM_AVAILABLE,1);
  }else{
    BitSet=RtlAreBitsSet((PRTL_BITMAP)Peb->TlsBitmap,Index,1);
    if(BitSet)
      RtlClearBits((PRTL_BITMAP)Peb->TlsBitmap,Index,1);
  }
  if(BitSet)
    _NtSetInformationThread(NtCurrentThread(),ThreadZeroTlsCell,&Index,sizeof(DWORD));
  return BitSet;
}

LPVOID WINAPI TlsGetValue(DWORD Index){
  PTEB Teb=NtCurrentTeb();
  if(Index>=TLS_EXPANSION_SLOTS+TLS_MINIMUM_AVAILABLE)
    return NULL;
  if(Index>=TLS_MINIMUM_AVAILABLE){
    if(Teb->TlsExpansionSlots==NULL)
      return NULL;
    return Teb->TlsExpansionSlots[Index-TLS_MINIMUM_AVAILABLE];
  }
  return Teb->TlsSlots[Index];
}

BOOL WINAPI TlsSetValue(DWORD Index,LPVOID Value){
  PTEB Teb=NtCurrentTeb();
  if(Index>=TLS_EXPANSION_SLOTS+TLS_MINIMUM_AVAILABLE)
    return FALSE;
  if(Index>=TLS_MINIMUM_AVAILABLE){
    if(Teb->TlsExpansionSlots==NULL){
      Teb->TlsExpansionSlots=(PVOID*)HeapAlloc(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,TLS_EXPANSION_SLOTS *sizeof(PVOID));
      if(Teb->TlsExpansionSlots==NULL)
        return FALSE;
    }
    Teb->TlsExpansionSlots[Index-TLS_MINIMUM_AVAILABLE]=Value;
  }else
    Teb->TlsSlots[Index]=Value;
  return TRUE;
}

#endif // defined

// *******************************************************************************
// Kernel32 Semaphore Functions
// *******************************************************************************

HANDLE WINAPI CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName){
  HANDLE hSemaphore=NULL;UNICODE_STRING ObjectName;
  OBJECT_ATTRIBUTES ObjectAttributes,*pObjectAttributes;
  if(lpName)RtlInitUnicodeString(&ObjectName,(LPCWSTR)lpName);
  pObjectAttributes=BaseFormatObjectAttributes(&ObjectAttributes,lpAttributes,(lpName?&ObjectName:NULL));
  NTSTATUS Status=_NtCreateSemaphore(&hSemaphore,SEMAPHORE_ALL_ACCESS,pObjectAttributes,lInitialCount,lMaximumCount);
  if(NT_SUCCESS(Status))
    return hSemaphore;
  return NULL;
}

HANDLE WINAPI CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpAttributes,LONG lInitialCount,LONG lMaximumCount,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)
    return CreateSemaphoreW(lpAttributes,lInitialCount,lMaximumCount,NULL);
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return CreateSemaphoreW(lpAttributes,lInitialCount,lMaximumCount,wBuffer);
}

HANDLE WINAPI OpenSemaphoreW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName){
  HANDLE hSemaphore=NULL,RootDirectory;UNICODE_STRING ObjectName;
  OBJECT_ATTRIBUTES ObjectAttributes;
  if(!lpName)return NULL;
  BaseGetNamedObjectDirectory(&RootDirectory);
  RtlInitUnicodeString(&ObjectName,(LPCWSTR)lpName);
  InitializeObjectAttributes(&ObjectAttributes,&ObjectName,OBJ_OPENIF|bInheritHandle?OBJ_INHERIT:0,RootDirectory,NULL);
  NTSTATUS Status=_NtOpenSemaphore(&hSemaphore,dwDesiredAccess,&ObjectAttributes);
  if(NT_SUCCESS(Status))
    return hSemaphore;
  return NULL;
}

HANDLE WINAPI OpenSemaphoreA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)return NULL;
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return OpenSemaphoreW(dwDesiredAccess,bInheritHandle,wBuffer);
}

BOOL WINAPI ReleaseSemaphore(HANDLE hSemaphore,LONG lReleaseCount,LPLONG lpPreviousCount){
  NTSTATUS Status=_NtReleaseSemaphore(hSemaphore,lReleaseCount,lpPreviousCount);
  return NT_SUCCESS(Status);
}

// *******************************************************************************
// Kernel32 Mutex Functions
// *******************************************************************************

HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES lpAttributes,BOOL bInitialOwner,LPCWSTR lpName){
  HANDLE hMutex=NULL;UNICODE_STRING ObjectName;
  OBJECT_ATTRIBUTES ObjectAttributes,*pObjectAttributes;
  if(lpName)RtlInitUnicodeString(&ObjectName,(LPCWSTR)lpName);
  pObjectAttributes=BaseFormatObjectAttributes(&ObjectAttributes,lpAttributes,(lpName?&ObjectName:NULL));
  NTSTATUS Status=_NtCreateMutant(&hMutex,MUTEX_ALL_ACCESS,pObjectAttributes,bInitialOwner);
  if(NT_SUCCESS(Status))
    return hMutex;
  return NULL;
}

HANDLE WINAPI CreateMutexA(LPSECURITY_ATTRIBUTES lpAttributes,BOOL bInitialOwner,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)
    return CreateMutexW(lpAttributes,bInitialOwner,NULL);
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return CreateMutexW(lpAttributes,bInitialOwner,wBuffer);
}

HANDLE WINAPI OpenMutexW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName){
  HANDLE hMutex=NULL,RootDirectory;UNICODE_STRING ObjectName;
  OBJECT_ATTRIBUTES ObjectAttributes;
  if(!lpName)return NULL;
  BaseGetNamedObjectDirectory(&RootDirectory);
  RtlInitUnicodeString(&ObjectName,(LPCWSTR)lpName);
  InitializeObjectAttributes(&ObjectAttributes,&ObjectName,OBJ_OPENIF|bInheritHandle?OBJ_INHERIT:0,RootDirectory,NULL);
  NTSTATUS Status=_NtOpenMutant(&hMutex,dwDesiredAccess,&ObjectAttributes);
  if(NT_SUCCESS(Status))
    return hMutex;
  return NULL;
}

HANDLE WINAPI OpenMutexA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)return NULL;
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return OpenMutexW(dwDesiredAccess,bInheritHandle,wBuffer);
}

HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpAttributes,BOOL bManualReset,BOOL bInitialState,LPCWSTR lpName){
  HANDLE hEvent=NULL;UNICODE_STRING ObjectName;
  OBJECT_ATTRIBUTES ObjectAttributes,*pObjectAttributes;
  if(lpName)RtlInitUnicodeString(&ObjectName,(LPCWSTR)lpName);
  pObjectAttributes=BaseFormatObjectAttributes(&ObjectAttributes,lpAttributes,(lpName?&ObjectName:NULL));
  NTSTATUS Status=_NtCreateEvent(&hEvent,EVENT_ALL_ACCESS,pObjectAttributes,bManualReset==FALSE,bInitialState);
  if(NT_SUCCESS(Status))
    return hEvent;
  return NULL;
}

HANDLE WINAPI CreateEventA(LPSECURITY_ATTRIBUTES lpAttributes,BOOL bManualReset,BOOL bInitialState,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)
    return CreateEventW(lpAttributes,bManualReset,bInitialState,NULL);
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return CreateEventW(lpAttributes,bManualReset,bInitialState,wBuffer);
}

HANDLE WINAPI OpenEventW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName){
  HANDLE hEvent=NULL,RootDirectory;UNICODE_STRING ObjectName;
  OBJECT_ATTRIBUTES ObjectAttributes;
  if(!lpName)return NULL;
  BaseGetNamedObjectDirectory(&RootDirectory);
  RtlInitUnicodeString(&ObjectName,(LPCWSTR)lpName);
  InitializeObjectAttributes(&ObjectAttributes,&ObjectName,bInheritHandle?OBJ_INHERIT:0,RootDirectory,NULL);
  NTSTATUS Status=_NtOpenEvent(&hEvent,dwDesiredAccess,&ObjectAttributes);
  if(NT_SUCCESS(Status))
    return hEvent;
  return NULL;
}

HANDLE WINAPI OpenEventA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)return NULL;
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return OpenEventW(dwDesiredAccess,bInheritHandle,wBuffer);
}

BOOL WINAPI SetEvent(HANDLE hEvent){
  NTSTATUS Status=_NtSetEvent(hEvent,0);
  return (NT_SUCCESS(Status));
}

BOOL WINAPI ResetEvent(HANDLE hEvent){
  NTSTATUS Status=_NtClearEvent(hEvent);
  return (NT_SUCCESS(Status));
}

BOOL WINAPI PulseEvent(HANDLE hEvent){
  NTSTATUS Status=_NtPulseEvent(hEvent,0);
  return (NT_SUCCESS(Status));
}

DWORD WINAPI WaitForSingleObjectEx(HANDLE hHandle,DWORD dwMilliseconds,BOOL bAlertable){
  LARGE_INTEGER Time,*TimePtr=NULL;NTSTATUS Status;
  PRTL_USER_PROCESS_PARAMETERS Ppb=NtCurrentPeb()->ProcessParameters;
  switch((ULONG)hHandle){
    case STD_INPUT_HANDLE:hHandle=Ppb->StandardInput;break;
    case STD_OUTPUT_HANDLE:hHandle=Ppb->StandardOutput;break;
    case STD_ERROR_HANDLE:hHandle=Ppb->StandardError;break;
    default:break;
  }
  if(dwMilliseconds!=INFINITE){
    Time.QuadPart=((DWORDLONG)dwMilliseconds*(DWORDLONG)-10000);
    TimePtr=&Time;
  }
  do{
    Status=_NtWaitForSingleObject(hHandle,bAlertable,TimePtr);
    if(!NT_SUCCESS(Status))
      Status=WAIT_FAILED;
  }while((Status==STATUS_ALERTED)&&(bAlertable));
  return Status;
}

//Used internaly by CRT
#if (__GNUC__ > 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ > 6 )))

DWORD WINAPI WaitForSingleObject(HANDLE hHandle,DWORD dwMilliseconds){
  return WaitForSingleObjectEx(hHandle,dwMilliseconds,FALSE);
}

DWORD WINAPI GetLastError(VOID){
  return NtCurrentTeb()->LastErrorValue;
}

VOID WINAPI SetLastError(DWORD dwErrCode){
  NtCurrentTeb()->LastErrorValue=dwErrCode;
}

#endif // defined

#define TICKSPERMIN        600000000
#define TICKSPERSEC        10000000
#define TICKSPERMSEC       10000
#define SECSPERDAY         86400
#define SECSPERHOUR        3600
#define SECSPERMIN         60
#define MINSPERHOUR        60
#define HOURSPERDAY        24
#define EPOCHWEEKDAY       1
#define DAYSPERWEEK        7
#define EPOCHYEAR          1601
#define DAYSPERNORMALYEAR  365
#define DAYSPERLEAPYEAR    366
#define MONSPERYEAR        12

VOID WINAPI RtlTimeToTimeFields(IN PLARGE_INTEGER Time,OUT PTIME_FIELDS TimeFields){
  const UCHAR *Months;ULONG SecondsInDay,CurYear,PrevYear;
  ULONG LeapYear,CurMonth,Days,YearLength;
  static const UCHAR MonthLengths[2][MONSPERYEAR]={
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
  };
  ULONGLONG IntTime=Time->QuadPart;
  TimeFields->Milliseconds=(CSHORT)((IntTime%TICKSPERSEC)/TICKSPERMSEC);
  IntTime=IntTime/TICKSPERSEC;
  Days=(ULONG)(IntTime/SECSPERDAY);
  SecondsInDay=IntTime%SECSPERDAY;
  TimeFields->Hour=(CSHORT)(SecondsInDay/SECSPERHOUR);
  SecondsInDay=SecondsInDay%SECSPERHOUR;
  TimeFields->Minute=(CSHORT)(SecondsInDay/SECSPERMIN);
  TimeFields->Second=(CSHORT)(SecondsInDay%SECSPERMIN);
  TimeFields->Weekday=(CSHORT)((EPOCHWEEKDAY+Days)%DAYSPERWEEK);
  CurYear=EPOCHYEAR+(Days/DAYSPERLEAPYEAR);
  PrevYear=CurYear-1;
  Days-=(PrevYear*DAYSPERNORMALYEAR+PrevYear/4-PrevYear/100+PrevYear/400)-
    ((EPOCHYEAR-1)*DAYSPERNORMALYEAR+(EPOCHYEAR-1)/4-(EPOCHYEAR-1)/100+(EPOCHYEAR-1)/400);
  while(1){
    LeapYear=(CurYear%4==0&&(CurYear%100!=0||CurYear%400==0))?1:0;
    YearLength=LeapYear?DAYSPERLEAPYEAR:DAYSPERNORMALYEAR;
    if(Days<YearLength)
      break;
    CurYear++;
    Days-=YearLength;
  }
  TimeFields->Year=(CSHORT)CurYear;
  Months=MonthLengths[LeapYear];
  for(CurMonth=0;Days>=Months[CurMonth];CurMonth++)
    Days-=Months[CurMonth];
  TimeFields->Month=(CSHORT)(CurMonth+1);
  TimeFields->Day=(CSHORT)(Days+1);
}

DWORD WINAPI GetTickCount(VOID){
  if(wversion>=WINVISTA){
    ULARGE_INTEGER TickCount;
    while(TRUE){
      TickCount.HighPart=(ULONG)USER_SHARED_DATA->TickCount.High1Time;
      TickCount.LowPart=USER_SHARED_DATA->TickCount.LowPart;
      if(TickCount.HighPart==(ULONG)USER_SHARED_DATA->TickCount.High2Time)
        break;
    }
    return (ULONG)((UInt32x32To64(TickCount.LowPart,USER_SHARED_DATA->TickCountMultiplier)>>24)+
      UInt32x32To64((TickCount.HighPart<<8)&0xFFFFFFFF,USER_SHARED_DATA->TickCountMultiplier));
  }
  return (ULONG)(UInt32x32To64(USER_SHARED_DATA->TickCountLow,USER_SHARED_DATA->TickCountMultiplier)>>24);
}

VOID WINAPI GetLocalTime(LPSYSTEMTIME lpSystemTime){
  LARGE_INTEGER SystemTime, TimeZoneBias;
  TIME_FIELDS TimeFields;
  volatile KSYSTEM_TIME *TimePtr;

  do{
    SystemTime.HighPart = USER_SHARED_DATA->SystemTime.High1Time;
    SystemTime.LowPart = USER_SHARED_DATA->SystemTime.LowPart;
  }while (SystemTime.HighPart != USER_SHARED_DATA->SystemTime.High2Time);

  TimePtr = &USER_SHARED_DATA->TimeZoneBias;
  do{
    TimeZoneBias.HighPart = TimePtr->High1Time;
    TimeZoneBias.LowPart = TimePtr->LowPart;
  }while (TimeZoneBias.HighPart != TimePtr->High2Time);

  SystemTime.QuadPart -= TimeZoneBias.QuadPart;
  RtlTimeToTimeFields(&SystemTime, &TimeFields);
  lpSystemTime->wYear = TimeFields.Year;
  lpSystemTime->wMonth = TimeFields.Month;
  lpSystemTime->wDay = TimeFields.Day;
  lpSystemTime->wHour = TimeFields.Hour;
  lpSystemTime->wMinute = TimeFields.Minute;
  lpSystemTime->wSecond = TimeFields.Second;
  lpSystemTime->wMilliseconds = TimeFields.Milliseconds;
  lpSystemTime->wDayOfWeek = TimeFields.Weekday;
}

VOID WINAPI GetSystemTimeAsFileTime(OUT PFILETIME lpFileTime){
  LARGE_INTEGER SystemTime;
  do{
    SystemTime.HighPart = USER_SHARED_DATA->SystemTime.High1Time;
    SystemTime.LowPart = USER_SHARED_DATA->SystemTime.LowPart;
  }while (SystemTime.HighPart != USER_SHARED_DATA->SystemTime.High2Time);

  lpFileTime->dwLowDateTime = SystemTime.LowPart;
  lpFileTime->dwHighDateTime = SystemTime.HighPart;
}

__time64_t FileTimeToUnixTime(const FILETIME *FileTime, USHORT *millitm){
  #define DIFFTIME   0x19db1ded53e8000ULL
  ULARGE_INTEGER ULargeInt;
  __time64_t time;
  ULargeInt.LowPart = FileTime->dwLowDateTime;
  ULargeInt.HighPart = FileTime->dwHighDateTime;
  ULargeInt.QuadPart -= DIFFTIME;
  time = ULargeInt.QuadPart / 10000000;
  if (millitm)
    *millitm = (USHORT)((ULargeInt.QuadPart % 10000000) / 10000);
  return time;
}

//Used internaly by CRT
#if (__GNUC__ > 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ > 6 )))

DWORD WINAPI SleepEx(DWORD dwMilliseconds,BOOL bAlertable){
  LARGE_INTEGER Time,*TimePtr;
  if(bAlertable)
    return 0;
  TimePtr=BaseFormatTimeOut(&Time,dwMilliseconds);
  if(!TimePtr){
    Time.LowPart=0;
    Time.HighPart=0x80000000;
    TimePtr=&Time;
  }
  _NtDelayExecution(FALSE,TimePtr);
  return 0;
}

VOID WINAPI Sleep(DWORD dwMilliseconds){
  SleepEx(dwMilliseconds,FALSE);
}

BOOL WINAPI QueryPerformanceCounter(PLARGE_INTEGER lpPerformanceCount){
  LARGE_INTEGER Frequency;NTSTATUS Status;
  Status = _NtQueryPerformanceCounter(lpPerformanceCount,&Frequency);
  if(Frequency.QuadPart==0)Status=STATUS_NOT_IMPLEMENTED;
  return NT_SUCCESS(Status);
}

#endif

BOOL WINAPI DeviceIoControl(HANDLE hDevice,DWORD dwIoControlCode,LPVOID lpInBuffer,DWORD nInBufferSize,LPVOID lpOutBuffer,DWORD nOutBufferSize,LPDWORD lpBytesReturned,LPOVERLAPPED lpOverlapped){
  NTSTATUS Status;IO_STATUS_BLOCK Iosb;
  BOOL DevIoCtl=((dwIoControlCode>>16)==FILE_DEVICE_FILE_SYSTEM);
  if(ARGUMENT_PRESENT(lpOverlapped)){
    lpOverlapped->Internal=STATUS_PENDING;
    PVOID ApcContext=(((ULONG_PTR)lpOverlapped->hEvent&0x1)?NULL:lpOverlapped);
    if(DevIoCtl)
      Status=_NtFsControlFile(hDevice,lpOverlapped->hEvent,NULL,ApcContext,lpOverlapped,
        dwIoControlCode,lpInBuffer,nInBufferSize,lpOutBuffer,nOutBufferSize);
    else
      Status=_NtDeviceIoControlFile(hDevice,lpOverlapped->hEvent,NULL,ApcContext,lpOverlapped,
        dwIoControlCode,lpInBuffer,nInBufferSize,lpOutBuffer,nOutBufferSize);
    if(!NT_ERROR(Status)&&ARGUMENT_PRESENT(lpBytesReturned))
      *lpBytesReturned=lpOverlapped->InternalHigh;
    if(!NT_SUCCESS(Status)||(Status==STATUS_PENDING))
      return FALSE;
  }else{
    if(DevIoCtl)
      Status=_NtFsControlFile(hDevice,NULL,NULL,NULL,&Iosb,dwIoControlCode,lpInBuffer,
        nInBufferSize,lpOutBuffer,nOutBufferSize);
    else
      Status=_NtDeviceIoControlFile(hDevice,NULL,NULL,NULL,&Iosb,dwIoControlCode,lpInBuffer,
        nInBufferSize,lpOutBuffer,nOutBufferSize);
    if(Status==STATUS_PENDING){
      Status=_NtWaitForSingleObject(hDevice,FALSE,NULL);
      if(NT_SUCCESS(Status))
        Status=Iosb.Status;
    }
    if((NT_SUCCESS(Status)||!NT_ERROR(Status))&&lpBytesReturned)
      *lpBytesReturned=Iosb.Information;
    if(!NT_SUCCESS(Status))
      return FALSE;
  }
  return TRUE;
}

BOOL WINAPI CloseHandle(HANDLE hHandle){
  PRTL_USER_PROCESS_PARAMETERS Ppb=NtCurrentPeb()->ProcessParameters;
  switch((ULONG)hHandle){
    case STD_INPUT_HANDLE:hHandle=Ppb->StandardInput;break;
    case STD_OUTPUT_HANDLE:hHandle=Ppb->StandardOutput;break;
    case STD_ERROR_HANDLE:hHandle=Ppb->StandardError;break;
    default:break;
  }
  return (!NT_SUCCESS(_NtClose(hHandle)));
}

BOOL WINAPI CreatePipe(PHANDLE hReadPipe,PHANDLE hWritePipe,LPSECURITY_ATTRIBUTES lpPipeAttributes,DWORD nSize){
  UNICODE_STRING PipeName;OBJECT_ATTRIBUTES ObjectAttributes;IO_STATUS_BLOCK StatusBlock;
  LARGE_INTEGER DefaultTimeout;HANDLE ReadPipeHandle;HANDLE WritePipeHandle;
  ULONG Attributes;PSECURITY_DESCRIPTOR SecurityDescriptor=NULL;
  DefaultTimeout.QuadPart=-1200000000;
  static DWORD count=0;
  WCHAR Buffer[64];
  if(!nSize)
    nSize=0x1000;

  swprintf(Buffer,L"\\Device\\NamedPipe\\Inexinferis.%08x.%08x",NtCurrentTeb()->ClientId.UniqueProcess,count++);
  RtlInitUnicodeString(&PipeName,Buffer);
  Attributes=OBJ_CASE_INSENSITIVE;
  if(lpPipeAttributes){
    SecurityDescriptor=(PSECURITY_DESCRIPTOR)lpPipeAttributes->lpSecurityDescriptor;
    if(lpPipeAttributes->bInheritHandle)
      Attributes|=OBJ_INHERIT;
  }

  InitializeObjectAttributes(&ObjectAttributes,&PipeName,Attributes,NULL,SecurityDescriptor);
  NTSTATUS Status=_NtCreateNamedPipeFile(&ReadPipeHandle,GENERIC_READ|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,&ObjectAttributes,&StatusBlock,FILE_SHARE_READ|FILE_SHARE_WRITE,
    FILE_CREATE,FILE_SYNCHRONOUS_IO_NONALERT,FILE_PIPE_BYTE_STREAM_TYPE,FILE_PIPE_BYTE_STREAM_MODE,FILE_PIPE_QUEUE_OPERATION,1,nSize,nSize,&DefaultTimeout);
  if(!NT_SUCCESS(Status)){
    return FALSE;
  }

  Status=_NtOpenFile(&WritePipeHandle,FILE_GENERIC_WRITE|SYNCHRONIZE,&ObjectAttributes,&StatusBlock,FILE_SHARE_READ,FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
  if(!NT_SUCCESS(Status)){
    _NtClose(ReadPipeHandle);
    return FALSE;
  }

  *hReadPipe=ReadPipeHandle;
  *hWritePipe=WritePipeHandle;
  return TRUE;
}

HANDLE WINAPI CreateFileMappingW(HANDLE hFile,LPSECURITY_ATTRIBUTES lpFileMappingAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCWSTR lpName){
  HANDLE SectionHandle;UNICODE_STRING SectionName;
  OBJECT_ATTRIBUTES LocalAttributes,*ObjectAttributes;
  ACCESS_MASK DesiredAccess;ULONG Attributes;
  LARGE_INTEGER LocalSize,*SectionSize=NULL;
  DesiredAccess=STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|SECTION_MAP_READ;
  Attributes=flProtect&(SEC_FILE|SEC_IMAGE|SEC_RESERVE|SEC_NOCACHE|SEC_COMMIT|SEC_LARGE_PAGES);
  flProtect^=Attributes;
  if(!Attributes)Attributes=SEC_COMMIT;
  if(flProtect==PAGE_READWRITE)
    DesiredAccess|=SECTION_MAP_WRITE;
  else if(flProtect==PAGE_EXECUTE_READWRITE)
    DesiredAccess|=(SECTION_MAP_WRITE|SECTION_MAP_EXECUTE);
  else if(flProtect==PAGE_EXECUTE_READ)
    DesiredAccess|=SECTION_MAP_EXECUTE;
  else if((flProtect!=PAGE_READONLY)&&(flProtect!=PAGE_WRITECOPY))
    return NULL;
  if(lpName)RtlInitUnicodeString(&SectionName,lpName);
  ObjectAttributes=BaseFormatObjectAttributes(&LocalAttributes,lpFileMappingAttributes,lpName?&SectionName:NULL);
  if(dwMaximumSizeLow||dwMaximumSizeHigh){
    SectionSize=&LocalSize;
    SectionSize->LowPart=dwMaximumSizeLow;
    SectionSize->HighPart=dwMaximumSizeHigh;
  }
  if(hFile==INVALID_HANDLE_VALUE){
    hFile=NULL;
    if(!SectionSize)
      return NULL;
  }
  NTSTATUS Status=_NtCreateSection(&SectionHandle,DesiredAccess,ObjectAttributes,SectionSize,flProtect,Attributes,hFile);
  if(NT_SUCCESS(Status))
    return SectionHandle;
  return NULL;
}

HANDLE WINAPI CreateFileMappingA(HANDLE hFile,LPSECURITY_ATTRIBUTES lpFileMappingAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)
    return CreateFileMappingW(hFile,lpFileMappingAttributes,flProtect,dwMaximumSizeHigh,dwMaximumSizeLow,NULL);
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return CreateFileMappingW(hFile,lpFileMappingAttributes,flProtect,dwMaximumSizeHigh,dwMaximumSizeLow,wBuffer);
}

HANDLE WINAPI OpenFileMappingW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName){
  HANDLE SectionHandle,RootDirectory;UNICODE_STRING UnicodeName;
  OBJECT_ATTRIBUTES ObjectAttributes;
  if(!lpName)
    return NULL;
  RtlInitUnicodeString(&UnicodeName,lpName);
  BaseGetNamedObjectDirectory(&RootDirectory);
  InitializeObjectAttributes(&ObjectAttributes,&UnicodeName,(bInheritHandle?OBJ_INHERIT:0),RootDirectory,NULL);
  if(dwDesiredAccess==FILE_MAP_COPY)
    dwDesiredAccess=SECTION_MAP_READ;
  else if(dwDesiredAccess&FILE_MAP_EXECUTE)
    dwDesiredAccess=(dwDesiredAccess&~FILE_MAP_EXECUTE)|SECTION_MAP_EXECUTE;
  NTSTATUS Status=_NtOpenSection(&SectionHandle, dwDesiredAccess, &ObjectAttributes);
  if(!NT_SUCCESS(Status))
    return NULL;
  return SectionHandle;
}

HANDLE WINAPI OpenFileMappingA(IN DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName){
  WCHAR wBuffer[MAX_PATH];
  if(!lpName)return NULL;
  RtlMultiByteToUnicode(wBuffer,MAX_PATH,lpName,(ULONG)-1);
  return OpenFileMappingW(dwDesiredAccess,bInheritHandle,wBuffer);
}

LPVOID WINAPI MapViewOfFileEx(HANDLE hFileMappingObject,DWORD dwDesiredAccess,DWORD dwFileOffsetHigh,DWORD dwFileOffsetLow,SIZE_T dwNumberOfBytesToMap,LPVOID lpBaseAddress){
  LARGE_INTEGER SectionOffset;
  SectionOffset.LowPart=dwFileOffsetLow;
  SectionOffset.HighPart=dwFileOffsetHigh;
  ULONG Protect=0;
  if(dwDesiredAccess==FILE_MAP_COPY)
    Protect=PAGE_WRITECOPY;
  else if(dwDesiredAccess&FILE_MAP_WRITE)
    Protect=(dwDesiredAccess&FILE_MAP_EXECUTE)?PAGE_EXECUTE_READWRITE:PAGE_READWRITE;
  else if(dwDesiredAccess&FILE_MAP_READ)
    Protect=(dwDesiredAccess&FILE_MAP_EXECUTE)?PAGE_EXECUTE_READ:PAGE_READONLY;
  else
    Protect=PAGE_NOACCESS;
  NTSTATUS Status=_NtMapViewOfSection(hFileMappingObject,NtCurrentProcess(),&lpBaseAddress,0,0,&SectionOffset,&dwNumberOfBytesToMap,ViewShare,0,Protect);
  if(NT_SUCCESS(Status))
    return (LPVOID)lpBaseAddress;
  return NULL;
}

LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject,DWORD dwDesiredAccess,DWORD dwFileOffsetHigh,DWORD dwFileOffsetLow,SIZE_T dwNumberOfBytesToMap){
  return MapViewOfFileEx(hFileMappingObject,dwDesiredAccess,dwFileOffsetHigh,dwFileOffsetLow,dwNumberOfBytesToMap,0);
}

BOOL WINAPI UnmapViewOfFile(LPCVOID lpBaseAddress){
  NTSTATUS Status=_NtUnmapViewOfSection(NtCurrentProcess(),(PVOID)lpBaseAddress);
  return NT_SUCCESS(Status);
}

HANDLE WINAPI CreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile){
  OBJECT_ATTRIBUTES ObjectAttributes;
  UNICODE_STRING NtPathU,DOSPathU;
  IO_STATUS_BLOCK IoStatusBlock;
  HANDLE FileHandle=NULL;
  ULONG FileAttributes,Flags=0;

  if(hTemplateFile!=NULL||!lpFileName||!lpFileName[0])
    return INVALID_HANDLE_VALUE;

  switch(dwCreationDisposition){
    case CREATE_NEW:
      dwCreationDisposition=FILE_CREATE;
    break;
    case CREATE_ALWAYS:
      dwCreationDisposition=FILE_OVERWRITE_IF;
    break;
    case OPEN_EXISTING:
      dwCreationDisposition=FILE_OPEN;
    break;
    case OPEN_ALWAYS:
      dwCreationDisposition=FILE_OPEN_IF;
    break;
    case TRUNCATE_EXISTING:
      dwCreationDisposition=FILE_OVERWRITE;
    break;
    default:
      return INVALID_HANDLE_VALUE;
  }

  if(!(dwFlagsAndAttributes&FILE_FLAG_OVERLAPPED))
    Flags|=FILE_SYNCHRONOUS_IO_NONALERT;
  if(dwFlagsAndAttributes&FILE_FLAG_WRITE_THROUGH)
    Flags|=FILE_WRITE_THROUGH;
  if(dwFlagsAndAttributes&FILE_FLAG_NO_BUFFERING)
    Flags|=FILE_NO_INTERMEDIATE_BUFFERING;
  if(dwFlagsAndAttributes&FILE_FLAG_RANDOM_ACCESS)
    Flags|=FILE_RANDOM_ACCESS;
  if(dwFlagsAndAttributes&FILE_FLAG_SEQUENTIAL_SCAN)
    Flags|=FILE_SEQUENTIAL_ONLY;
  if(dwFlagsAndAttributes&FILE_FLAG_DELETE_ON_CLOSE)
    Flags|=FILE_DELETE_ON_CLOSE;
  if(dwFlagsAndAttributes&FILE_FLAG_BACKUP_SEMANTICS){
    if(dwDesiredAccess&GENERIC_ALL)
      Flags|=FILE_OPEN_FOR_BACKUP_INTENT;
    else{
      if(dwDesiredAccess&GENERIC_READ)
        Flags|=FILE_OPEN_FOR_BACKUP_INTENT;
    }
  }else
    Flags|=FILE_NON_DIRECTORY_FILE;
  if(dwFlagsAndAttributes&FILE_FLAG_OPEN_REPARSE_POINT)
    Flags|=FILE_OPEN_REPARSE_POINT;
  if(dwFlagsAndAttributes&FILE_FLAG_OPEN_NO_RECALL)
    Flags|=FILE_OPEN_NO_RECALL;
  FileAttributes=(dwFlagsAndAttributes&(FILE_ATTRIBUTE_VALID_FLAGS&~FILE_ATTRIBUTE_DIRECTORY));
  dwDesiredAccess|=SYNCHRONIZE|FILE_READ_ATTRIBUTES;

  RtlInitUnicodeString(&DOSPathU,lpFileName);
  if(!NT_SUCCESS(RtlDosPathNameToNtPathName(&DOSPathU,&NtPathU,NULL))){
    return INVALID_HANDLE_VALUE;
  }

  InitializeObjectAttributes(&ObjectAttributes,&NtPathU,0,NULL,NULL);
  if(lpSecurityAttributes){
    if(lpSecurityAttributes->bInheritHandle)
      ObjectAttributes.Attributes|=OBJ_INHERIT;
    ObjectAttributes.SecurityDescriptor=lpSecurityAttributes->lpSecurityDescriptor;
  }

  if(!(dwFlagsAndAttributes&FILE_FLAG_POSIX_SEMANTICS))
    ObjectAttributes.Attributes|=OBJ_CASE_INSENSITIVE;

  NTSTATUS Status=_NtCreateFile(&FileHandle,dwDesiredAccess,&ObjectAttributes,&IoStatusBlock,
    NULL,FileAttributes,dwShareMode,dwCreationDisposition,Flags,NULL,0);

  RtlFreeHeap(RtlGetProcessHeap(),0,NtPathU.Buffer);

  if(!NT_SUCCESS(Status))
    return INVALID_HANDLE_VALUE;
  return FileHandle;
}

HANDLE WINAPI CreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile){
  WCHAR wFileName[MAX_PATH];
  if(!lpFileName)return INVALID_HANDLE_VALUE;
  RtlMultiByteToUnicode(wFileName,MAX_PATH,lpFileName,(ULONG)-1);
  return CreateFileW(wFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
    dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}

BOOL WINAPI ReadFile(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,LPOVERLAPPED lpOverlapped){
  NTSTATUS Status;
  if(!nNumberOfBytesToRead)
    return TRUE;
  if(lpNumberOfBytesRead!=NULL)
    *lpNumberOfBytesRead=0;
  if(lpOverlapped!=NULL){
    LARGE_INTEGER Offset;
    Offset.u.LowPart=lpOverlapped->Offset;
    Offset.u.HighPart=lpOverlapped->OffsetHigh;
    lpOverlapped->Internal=STATUS_PENDING;
    PVOID ApcContext=(((ULONG_PTR)lpOverlapped->hEvent&0x1)?NULL:lpOverlapped);
    Status=_NtReadFile(hFile,lpOverlapped->hEvent,NULL,ApcContext,(PIO_STATUS_BLOCK)lpOverlapped,lpBuffer,nNumberOfBytesToRead,&Offset,NULL);
    if(!NT_SUCCESS(Status)||Status==STATUS_PENDING)
      return FALSE;
    if(lpNumberOfBytesRead!=NULL)
      *lpNumberOfBytesRead=lpOverlapped->InternalHigh;
  }else{
    IO_STATUS_BLOCK Iosb;
    Status=_NtReadFile(hFile,NULL,NULL,NULL,&Iosb,lpBuffer,nNumberOfBytesToRead,NULL,NULL);
    if(Status==STATUS_PENDING){
      Status=_NtWaitForSingleObject(hFile,FALSE,NULL);
      if(NT_SUCCESS(Status))
        Status=Iosb.Status;
    }
    if(Status==STATUS_END_OF_FILE)
      return TRUE;
    if(!NT_SUCCESS(Status)){
      return FALSE;
    }
    if(lpNumberOfBytesRead!=NULL)
      *lpNumberOfBytesRead=Iosb.Information;
  }
  return TRUE;
}

BOOL WINAPI WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped){
  NTSTATUS Status;
  if(!nNumberOfBytesToWrite)
    return TRUE;
  if(lpNumberOfBytesWritten!=NULL)
    *lpNumberOfBytesWritten=0;
  if(lpOverlapped!=NULL){
    LARGE_INTEGER Offset;
    Offset.u.LowPart=lpOverlapped->Offset;
    Offset.u.HighPart=lpOverlapped->OffsetHigh;
    lpOverlapped->Internal=STATUS_PENDING;
    PVOID ApcContext=(((ULONG_PTR)lpOverlapped->hEvent&0x1)?NULL:lpOverlapped);
    Status=_NtWriteFile(hFile,lpOverlapped->hEvent,NULL,ApcContext,(PIO_STATUS_BLOCK)lpOverlapped,(PVOID)lpBuffer,nNumberOfBytesToWrite,&Offset,NULL);
    if(!NT_SUCCESS(Status)||Status==STATUS_PENDING)
      return FALSE;
    if(lpNumberOfBytesWritten!=NULL)
      *lpNumberOfBytesWritten=lpOverlapped->InternalHigh;
  }else{
    IO_STATUS_BLOCK Iosb;
    Status=_NtWriteFile(hFile,NULL,NULL,NULL,&Iosb,(PVOID)lpBuffer,nNumberOfBytesToWrite,NULL,NULL);
    if(Status==STATUS_PENDING){
      Status=_NtWaitForSingleObject(hFile,FALSE,NULL);
      if(NT_SUCCESS(Status))
        Status=Iosb.Status;
    }
    if(!NT_SUCCESS(Status)){
      return FALSE;
    }
    if(lpNumberOfBytesWritten!=NULL)
      *lpNumberOfBytesWritten=Iosb.Information;
  }
  return TRUE;
}

DWORD WINAPI SetFilePointer(HANDLE hFile,LONG lDistanceToMove,PLONG lpDistanceToMoveHigh,DWORD dwMoveMethod){
  FILE_POSITION_INFORMATION FilePosition;FILE_STANDARD_INFORMATION FileStandard;
  NTSTATUS Status;IO_STATUS_BLOCK IoStatusBlock;LARGE_INTEGER Distance;
  if(lpDistanceToMoveHigh){
    Distance.u.HighPart=*lpDistanceToMoveHigh;
    Distance.u.LowPart=lDistanceToMove;
  }else
    Distance.QuadPart=lDistanceToMove;
  switch(dwMoveMethod){
    case FILE_CURRENT:
      Status=_NtQueryInformationFile(hFile,&IoStatusBlock,&FilePosition,sizeof(FILE_POSITION_INFORMATION),FilePositionInformation);
      FilePosition.CurrentByteOffset.QuadPart+=Distance.QuadPart;
      if(!NT_SUCCESS(Status)){
        if(lpDistanceToMoveHigh!=NULL)
          *lpDistanceToMoveHigh=-1;
        return INVALID_SET_FILE_POINTER;
      }
    break;
    case FILE_END:
      Status=_NtQueryInformationFile(hFile,&IoStatusBlock,&FileStandard,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation);
      FilePosition.CurrentByteOffset.QuadPart=FileStandard.EndOfFile.QuadPart+Distance.QuadPart;
      if(!NT_SUCCESS(Status)){
        if(lpDistanceToMoveHigh!=NULL)
          *lpDistanceToMoveHigh=-1;
        return INVALID_SET_FILE_POINTER;
      }
    break;
    case FILE_BEGIN:
      FilePosition.CurrentByteOffset.QuadPart=Distance.QuadPart;
    break;
    default:return INVALID_SET_FILE_POINTER;
  }
  if(FilePosition.CurrentByteOffset.QuadPart < 0 || (lpDistanceToMoveHigh==NULL&&FilePosition.CurrentByteOffset.HighPart!=0))
    return INVALID_SET_FILE_POINTER;
  Status=_NtSetInformationFile(hFile,&IoStatusBlock,&FilePosition,sizeof(FILE_POSITION_INFORMATION),FilePositionInformation);
  if(!NT_SUCCESS(Status)){
    if(lpDistanceToMoveHigh!=NULL)
      *lpDistanceToMoveHigh=-1;
    return INVALID_SET_FILE_POINTER;
  }
  if (lpDistanceToMoveHigh!=NULL)
    *lpDistanceToMoveHigh=FilePosition.CurrentByteOffset.u.HighPart;
  return FilePosition.CurrentByteOffset.u.LowPart;
}

BOOL WINAPI GetFileSizeEx(HANDLE hFile,PLARGE_INTEGER lpFileSize){
  FILE_STANDARD_INFORMATION FileStandard;
  IO_STATUS_BLOCK IoStatusBlock;
  NTSTATUS Status=_NtQueryInformationFile(hFile,&IoStatusBlock,&FileStandard,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation);
  if(NT_SUCCESS(Status)){
    if(lpFileSize)
     *lpFileSize=FileStandard.EndOfFile;
    return TRUE;
  }
  return FALSE;
}

DWORD WINAPI GetFileSize(HANDLE hFile,LPDWORD lpFileSizeHigh){
  LARGE_INTEGER FileSize;
  if(GetFileSizeEx(hFile,&FileSize)){
    if(lpFileSizeHigh)
      *lpFileSizeHigh=FileSize.HighPart;
    return FileSize.LowPart;
  }
  return (DWORD)-1;
}

BOOL WINAPI DeleteFileW(LPCWSTR lpFileName){
  FILE_DISPOSITION_INFORMATION FileDispInfo;
  OBJECT_ATTRIBUTES ObjectAttributes;
  IO_STATUS_BLOCK IoStatusBlock;
  UNICODE_STRING NtPathU,DOSPathU;
  HANDLE FileHandle;

  RtlInitUnicodeString(&DOSPathU,lpFileName);
  if(!NT_SUCCESS(RtlDosPathNameToNtPathName(&DOSPathU,&NtPathU,NULL))){
    return FALSE;
  }

  InitializeObjectAttributes(&ObjectAttributes,&NtPathU,OBJ_CASE_INSENSITIVE,NULL,NULL);
  NTSTATUS Status=_NtCreateFile(&FileHandle,DELETE,&ObjectAttributes,&IoStatusBlock,NULL,
    FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_OPEN,
    FILE_NON_DIRECTORY_FILE,NULL,0);
  RtlFreeHeap(RtlGetProcessHeap(),0,NtPathU.Buffer);
  if(!NT_SUCCESS(Status)){
    return FALSE;
  }

  FileDispInfo.DoDeleteFile=TRUE;
  Status=_NtSetInformationFile(FileHandle,&IoStatusBlock,&FileDispInfo,
    sizeof(FILE_DISPOSITION_INFORMATION),FileDispositionInformation);

  if(!NT_SUCCESS(Status)){
    _NtClose(FileHandle);
    return FALSE;
  }

  Status=_NtClose(FileHandle);
  if(!NT_SUCCESS(Status)){
    return FALSE;
  }
  return TRUE;
}

BOOL WINAPI DeleteFileA(LPCSTR lpFileName){
  WCHAR wFileName[MAX_PATH];
  if(!lpFileName)return FALSE;
  RtlMultiByteToUnicode(wFileName,MAX_PATH,lpFileName,(ULONG)-1);
  return DeleteFileW(wFileName);
}

DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName){
  OBJECT_ATTRIBUTES ObjectAttributes;FILE_BASIC_INFORMATION FileInformation;
  UNICODE_STRING DOSFileName,NTFileName;
  if(!lpFileName)return INVALID_FILE_ATTRIBUTES;
  RtlInitUnicodeString(&DOSFileName,lpFileName);
  if(!NT_SUCCESS(RtlDosPathNameToNtPathName(&DOSFileName,&NTFileName,NULL))){
    return INVALID_FILE_ATTRIBUTES;
  }
  InitializeObjectAttributes(&ObjectAttributes,&NTFileName,OBJ_CASE_INSENSITIVE,NULL,NULL);
  NTSTATUS Status=_NtQueryAttributesFile(&ObjectAttributes,&FileInformation);
  RtlFreeUnicodeString(&NTFileName);
  if(!NT_SUCCESS(Status)){
    return INVALID_FILE_ATTRIBUTES;
  }
  return FileInformation.FileAttributes;
}

DWORD WINAPI GetFileAttributesA(LPCSTR lpFileName){
  WCHAR wFileName[MAX_PATH];
  if(!lpFileName)return INVALID_FILE_ATTRIBUTES;
  RtlMultiByteToUnicode(wFileName,MAX_PATH,lpFileName,(ULONG)-1);
  return GetFileAttributesW(wFileName);
}

BOOL WINAPI CreateDirectoryW(LPCWSTR lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes){
  OBJECT_ATTRIBUTES ObjectAttributes;HANDLE DirectoryHandle;
  UNICODE_STRING NtPathU,DOSPathU;IO_STATUS_BLOCK IoStatusBlock;
  RtlInitUnicodeString(&DOSPathU,lpPathName);
  if(!NT_SUCCESS(RtlDosPathNameToNtPathName(&DOSPathU,&NtPathU,NULL))){
    return FALSE;
  }
  if(NtPathU.Length>MAX_PATH){
    RtlFreeUnicodeString(&NtPathU);
    return FALSE;
  }
  InitializeObjectAttributes(&ObjectAttributes,&NtPathU,OBJ_CASE_INSENSITIVE,NULL,
    (lpSecurityAttributes?lpSecurityAttributes->lpSecurityDescriptor:NULL));
  NTSTATUS Status=_NtCreateFile(&DirectoryHandle,FILE_LIST_DIRECTORY|SYNCHRONIZE,&ObjectAttributes,&IoStatusBlock,NULL,
    FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_CREATE,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_FOR_BACKUP_INTENT,NULL,0);
  RtlFreeUnicodeString(&NtPathU);
  if(NT_SUCCESS(Status)){
    _NtClose(DirectoryHandle);
    return TRUE;
  }
  return FALSE;
}

BOOL WINAPI CreateDirectoryA(LPCSTR lpFileName,LPSECURITY_ATTRIBUTES lpSecurityAttributes){
  WCHAR wFileName[MAX_PATH];
  if(!lpFileName)return INVALID_FILE_ATTRIBUTES;
  RtlMultiByteToUnicode(wFileName,MAX_PATH,lpFileName,(ULONG)-1);
  return CreateDirectoryW(wFileName,lpSecurityAttributes);
}

VOID WINAPI GetSystemInfo(LPSYSTEM_INFO lpSystemInfo){
  SYSTEM_BASIC_INFORMATION BasicInfo;SYSTEM_PROCESSOR_INFORMATION ProcInfo;
  if(!lpSystemInfo)return;
  if(!NT_SUCCESS(_NtQuerySystemInformation(SystemBasicInformation,&BasicInfo,sizeof(BasicInfo),0))){
    return;
  }
  if(!NT_SUCCESS(_NtQuerySystemInformation(SystemProcessorInformation,&ProcInfo,sizeof(ProcInfo),0))){
    return;
  }
  RtlZeroMemory(lpSystemInfo,sizeof(SYSTEM_INFO));
  lpSystemInfo->dwPageSize=BasicInfo.PageSize;
  lpSystemInfo->lpMinimumApplicationAddress=(PVOID)BasicInfo.MinimumUserModeAddress;
  lpSystemInfo->lpMaximumApplicationAddress=(PVOID)BasicInfo.MaximumUserModeAddress;
  lpSystemInfo->dwActiveProcessorMask=BasicInfo.ActiveProcessorsAffinityMask;
  lpSystemInfo->dwAllocationGranularity=BasicInfo.AllocationGranularity;
  lpSystemInfo->dwNumberOfProcessors=BasicInfo.NumberOfProcessors;
  lpSystemInfo->wProcessorLevel=ProcInfo.ProcessorLevel;
  lpSystemInfo->wProcessorRevision=ProcInfo.ProcessorRevision;
  lpSystemInfo->wProcessorArchitecture=ProcInfo.ProcessorArchitecture;
  switch(ProcInfo.ProcessorArchitecture){
    case PROCESSOR_ARCHITECTURE_INTEL:
      switch(ProcInfo.ProcessorLevel){
        case 3:lpSystemInfo->dwProcessorType=PROCESSOR_INTEL_386;break;
        case 4:lpSystemInfo->dwProcessorType=PROCESSOR_INTEL_486;break;
        default:lpSystemInfo->dwProcessorType=PROCESSOR_INTEL_PENTIUM;break;
      }
    break;
    case PROCESSOR_ARCHITECTURE_AMD64:lpSystemInfo->dwProcessorType=PROCESSOR_AMD_X8664;break;
    case PROCESSOR_ARCHITECTURE_IA64:lpSystemInfo->dwProcessorType=PROCESSOR_INTEL_IA64;break;
    default:lpSystemInfo->dwProcessorType=0;break;
  }
  lpSystemInfo->wReserved=0;
}

PSYSTEM_PROCESS_INFORMATION WINAPI GetSystemProcessInformation(){
  PSYSTEM_PROCESS_INFORMATION pProcThrdInfo=NULL;
  NTSTATUS Status=STATUS_NO_MEMORY;
  SIZE_T ProcThrdInfoSize=10000;
  do{
    pProcThrdInfo=(PSYSTEM_PROCESS_INFORMATION)VirtualAlloc(NULL,ProcThrdInfoSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!pProcThrdInfo)
      break;
    Status=_NtQuerySystemInformation(SystemProcessInformation,pProcThrdInfo,ProcThrdInfoSize,&ProcThrdInfoSize);
    if(!NT_SUCCESS(Status)){
      VirtualFree(pProcThrdInfo,0,MEM_RELEASE);
      pProcThrdInfo=NULL;
    }
  }while(Status==STATUS_BUFFER_TOO_SMALL||Status==STATUS_INFO_LENGTH_MISMATCH);
  return pProcThrdInfo;
}

VOID WINAPI FreeSystemProcessInformation(PSYSTEM_PROCESS_INFORMATION pProcThrdInfo){
  if(pProcThrdInfo)
    VirtualFree(pProcThrdInfo,0,MEM_RELEASE);
}

PSYSTEM_MODULE_INFORMATION WINAPI GetSystemModuleInformation(){
  PSYSTEM_MODULE_INFORMATION pModulesInfo=NULL;
  NTSTATUS Status=STATUS_NO_MEMORY;
  SIZE_T ModulesInfoSize=10000;
  do{
    pModulesInfo=(PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL,ModulesInfoSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!pModulesInfo)
      break;
    Status=_NtQuerySystemInformation(SystemModuleInformation,pModulesInfo,ModulesInfoSize,&ModulesInfoSize);
    if(!NT_SUCCESS(Status)){
      VirtualFree(pModulesInfo,0,MEM_RELEASE);
      pModulesInfo=NULL;
    }
  }while(Status==STATUS_BUFFER_TOO_SMALL||Status==STATUS_INFO_LENGTH_MISMATCH);
  return pModulesInfo;
}

VOID WINAPI FreeSystemModuleInformation(PSYSTEM_MODULE_INFORMATION pModulesInfo){
  if(pModulesInfo)
    VirtualFree(pModulesInfo,0,MEM_RELEASE);
}

ULONG WINAPI GetProcessIdByThreadId(ULONG ThreadId){
  THREAD_BASIC_INFORMATION TBI;
  HANDLE hThread=OpenThread(THREAD_QUERY_INFORMATION,FALSE,ThreadId);
  if(hThread){
    if(NT_SUCCESS(_NtQueryInformationThread(hThread,ThreadBasicInformation,&TBI,sizeof(THREAD_BASIC_INFORMATION),NULL))){
      CloseHandle(hThread);
      return (ULONG)TBI.ClientId.UniqueProcess;
    }
    CloseHandle(hThread);
  }
  return 0;
}

PSYSTEM_THREAD_INFORMATION WINAPI GetProcessThreadInformation(ULONG ProcessId,PULONG pNumberOfThreads){
  PSYSTEM_PROCESS_INFORMATION pProcThrdInfo=GetSystemProcessInformation();
  PSYSTEM_THREAD_INFORMATION pThrdInfo=NULL;UINT i;
  if(pProcThrdInfo){
    PSYSTEM_PROCESS_INFORMATION pInfo=pProcThrdInfo;
    for(;;){
      if(pInfo->UniqueProcessId==(HANDLE)ProcessId){
        pThrdInfo=(PSYSTEM_THREAD_INFORMATION)VirtualAlloc(NULL,sizeof(SYSTEM_THREAD_INFORMATION)*pInfo->NumberOfThreads,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(pThrdInfo){
          if(pNumberOfThreads)
            *pNumberOfThreads=pInfo->NumberOfThreads;
          RtlCopyMemory(pThrdInfo,pInfo->Threads,sizeof(SYSTEM_THREAD_INFORMATION)*pInfo->NumberOfThreads);
          for(i=0;i<pInfo->NumberOfThreads;i++){
            HANDLE hThread=OpenThread(THREAD_QUERY_INFORMATION,FALSE,(DWORD)pThrdInfo[i].ClientId.UniqueThread);
            if(hThread){
              PVOID StartAddress=NULL;
              if(NT_SUCCESS(_NtQueryInformationThread(hThread,ThreadQuerySetWin32StartAddress,&StartAddress,sizeof(StartAddress),NULL)))
                pThrdInfo[i].StartAddress=StartAddress;
              CloseHandle(hThread);
            }
          }
        }
        break;
      }
      if(!pInfo->NextEntryOffset)
        break;
      pInfo=(PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pInfo+pInfo->NextEntryOffset);
    }
    FreeSystemProcessInformation(pProcThrdInfo);
  }
  return pThrdInfo;
}

VOID WINAPI FreeProcessThreadInformation(PSYSTEM_THREAD_INFORMATION pProcThrdInfo){
  if(pProcThrdInfo)
    VirtualFree(pProcThrdInfo,0,MEM_RELEASE);
}

HINSTANCE WINAPI QueryRemoteModuleHandleAndSize(HANDLE hProcess,LPCSTR sModuleName,PDWORD pSize){
  MEMORY_BASIC_INFORMATION basicInfo;PVOID baseAddress=(PVOID)0;BOOL bFound=FALSE;
  HINSTANCE hBase=NULL;DWORD dwSize=0;
  if(sModuleName){
    while(NT_SUCCESS(_NtQueryVirtualMemory(hProcess,baseAddress,MemoryBasicInformation,&basicInfo,sizeof(MEMORY_BASIC_INFORMATION),NULL))){
      if(basicInfo.Type&(MEM_MAPPED|MEM_IMAGE)){
        NTSTATUS status;PVOID buffer;
        SIZE_T bufferSize,returnLength;
        bufferSize=MAX_PATH*sizeof(WCHAR);
        buffer=RtlAllocateHeap(RtlGetProcessHeap(),0,bufferSize);
        status=_NtQueryVirtualMemory(hProcess,basicInfo.BaseAddress,MemorySectionName,buffer,bufferSize,&returnLength);
        if(status==STATUS_BUFFER_OVERFLOW){
          RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
          bufferSize=returnLength;
          buffer=RtlAllocateHeap(RtlGetProcessHeap(),0,bufferSize);
          status=_NtQueryVirtualMemory(hProcess,basicInfo.BaseAddress,MemorySectionName,buffer,bufferSize,&returnLength);
        }
        if(NT_SUCCESS(status)){
          CHAR filePath[MAX_PATH],*fileName;
          PUNICODE_STRING unicodeString=(PUNICODE_STRING)buffer;
          RtlUnicodeToMultiByte(filePath,MAX_PATH,unicodeString->Buffer,unicodeString->Length+sizeof(WCHAR));
          fileName=strrchr(filePath,'\\');
          if(!fileName){
            fileName=filePath;
          }else{
            fileName++;
          }
          if(!stricmp(fileName,sModuleName)){
            if(!pSize){
              RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
              return (HINSTANCE)basicInfo.BaseAddress;
            }
            if(!bFound){
              hBase=(HINSTANCE)basicInfo.BaseAddress;
              bFound=TRUE;
            }
            dwSize+=basicInfo.RegionSize;
          }else if(bFound){
            if(pSize)
              *pSize=dwSize;
            RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
            return hBase;
          }
        }
        RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
      }
      baseAddress=PTR_ADD_OFFSET(baseAddress,basicInfo.RegionSize);
    }
  }
  return NULL;
}

HINSTANCE WINAPI QueryRemoteModuleHandleAndSizeByAddress(HANDLE hProcess,PVOID dwAddress,PDWORD pSize){
  MEMORY_BASIC_INFORMATION basicInfo;PVOID baseAddress=(PVOID)0;BOOL bFound=FALSE;
  HINSTANCE hBase=NULL;DWORD dwSize=0;CHAR sModuleName[MAX_PATH];sModuleName[0]=0;
  while(NT_SUCCESS(_NtQueryVirtualMemory(hProcess,baseAddress,MemoryBasicInformation,&basicInfo,sizeof(MEMORY_BASIC_INFORMATION),NULL))){
    if(basicInfo.Type&(MEM_MAPPED|MEM_IMAGE)){
      NTSTATUS status;PVOID buffer;
      SIZE_T bufferSize,returnLength;
      bufferSize=MAX_PATH*sizeof(WCHAR);
      buffer=RtlAllocateHeap(RtlGetProcessHeap(),0,bufferSize);
      status=_NtQueryVirtualMemory(hProcess,basicInfo.BaseAddress,MemorySectionName,buffer,bufferSize,&returnLength);
      if(status==STATUS_BUFFER_OVERFLOW){
        RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
        bufferSize=returnLength;
        buffer=RtlAllocateHeap(RtlGetProcessHeap(),0,bufferSize);
        status=_NtQueryVirtualMemory(hProcess,basicInfo.BaseAddress,MemorySectionName,buffer,bufferSize,&returnLength);
      }
      if(NT_SUCCESS(status)){
        CHAR fileName[MAX_PATH];
        PUNICODE_STRING unicodeString=(PUNICODE_STRING)buffer;
        RtlUnicodeToMultiByte(fileName,MAX_PATH,unicodeString->Buffer,unicodeString->Length+sizeof(WCHAR));
        if(strcmp(sModuleName,fileName)){
          if(bFound){
            if(pSize)
              *pSize=dwSize;
            RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
            return hBase;
          }
          strcpy(sModuleName,fileName);
          hBase=(HINSTANCE)basicInfo.BaseAddress;
          dwSize=0;
        }else{
          dwSize+=basicInfo.RegionSize;
        }
        if(baseAddress<=dwAddress&&(PVOID)((ULONG)baseAddress+basicInfo.RegionSize)>=dwAddress)
          bFound=TRUE;
      }
      RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
    }
    baseAddress=PTR_ADD_OFFSET(baseAddress,basicInfo.RegionSize);
  }
  return NULL;
}

DWORD WINAPI QueryRemoteModuleByAddress(HANDLE hProcess,PVOID dwAddress,LPSTR sModuleName,DWORD dwSize){
  MEMORY_BASIC_INFORMATION basicInfo;PVOID baseAddress=(PVOID)0;
  while(NT_SUCCESS(_NtQueryVirtualMemory(hProcess,baseAddress,MemoryBasicInformation,&basicInfo,sizeof(MEMORY_BASIC_INFORMATION),NULL))){
    if(basicInfo.Type&(MEM_MAPPED|MEM_IMAGE)){
      NTSTATUS status;PVOID buffer;
      SIZE_T bufferSize,returnLength;
      bufferSize=MAX_PATH*sizeof(WCHAR);
      buffer=RtlAllocateHeap(RtlGetProcessHeap(),0,bufferSize);
      status=_NtQueryVirtualMemory(hProcess,basicInfo.BaseAddress,MemorySectionName,buffer,bufferSize,&returnLength);
      if(status==STATUS_BUFFER_OVERFLOW){
        RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
        bufferSize=returnLength;
        buffer=RtlAllocateHeap(RtlGetProcessHeap(),0,bufferSize);
        status=_NtQueryVirtualMemory(hProcess,basicInfo.BaseAddress,MemorySectionName,buffer,bufferSize,&returnLength);
      }
      if(NT_SUCCESS(status)&&baseAddress<=dwAddress&&(PVOID)((ULONG)baseAddress+basicInfo.RegionSize)>=dwAddress){
        PUNICODE_STRING uName=(PUNICODE_STRING)buffer;
        DWORD len=RtlUnicodeToMultiByte(sModuleName,dwSize,uName->Buffer,uName->Length);
        sModuleName[len]=0;
        RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
        return len;
      }
      RtlFreeHeap(RtlGetProcessHeap(),0,buffer);
    }
    baseAddress=PTR_ADD_OFFSET(baseAddress,basicInfo.RegionSize);
  }
  return 0;
}

// *******************************************************************************
// LdrLoadDll
// *******************************************************************************

BOOL WINAPI ZeroProcessMemory(HANDLE hProcess,LPVOID lpAddress,DWORD dwSize){
  BOOL bRet=FALSE;
  PVOID pBuffer=RtlAllocateHeap(RtlGetProcessHeap(),0,dwSize);
  if(!pBuffer)
    return bRet;
  memset(pBuffer,0,dwSize);
  bRet=WriteProcessMemory(hProcess,(PBYTE)lpAddress,pBuffer,dwSize,0);
  RtlFreeHeap(RtlGetProcessHeap(),0,pBuffer);
  return bRet;
}

NTSTATUS WINAPI LdrpSetProtection(HANDLE hProcess,PIMAGE_NT_HEADERS NtHeaders,PVOID ViewBase,BOOL Restore){
  NTSTATUS Status;
  // Get the NT headers
  if(!NtHeaders)return STATUS_INVALID_IMAGE_FORMAT;
  // Compute address of the first section header
  PIMAGE_SECTION_HEADER Section=IMAGE_FIRST_SECTION(NtHeaders);
  // Go through all sections
  for(ULONG i=0;i<NtHeaders->FileHeader.NumberOfSections;i++){
    // Check for read-only non-zero section
    if(Section->SizeOfRawData&&!(Section->Characteristics&IMAGE_SCN_MEM_WRITE)){
      ULONG NewProtection,OldProtection;
      // Check if we are setting or restoring protection
      if(Restore){
        // Set it to either EXECUTE or READONLY
        if(Section->Characteristics&IMAGE_SCN_MEM_EXECUTE)
          NewProtection=PAGE_EXECUTE_READ;
        else
          NewProtection=PAGE_READONLY;
        // Add PAGE_NOCACHE if needed
        if(Section->Characteristics&IMAGE_SCN_MEM_NOT_CACHED)
          NewProtection|=PAGE_NOCACHE;
      }else
        // Enable write access
        NewProtection=PAGE_EXECUTE_READWRITE;
      // Get the section VA
      PVOID SectionBase=(PVOID)((ULONG_PTR)ViewBase+Section->VirtualAddress);
      SIZE_T SectionSize=Section->SizeOfRawData;
      if(SectionSize){
        // Set protection
        Status=_NtProtectVirtualMemory(hProcess,&SectionBase,&SectionSize,NewProtection,&OldProtection);
        if(!NT_SUCCESS(Status)){
          return Status;
        }
      }
    }
    // Move to the next section
    Section++;
  }
  // Flush instruction cache if necessary
  if(Restore)_NtFlushInstructionCache(hProcess,NULL,0);
  return STATUS_SUCCESS;
}

NTSTATUS WINAPI MapViewOfImage(HANDLE hProcess,HANDLE hFile,PVOID *BaseAddress,PSIZE_T ViewSize){
  NTSTATUS Status=STATUS_SUCCESS;
  DWORD FileSize=GetFileSize(hFile,NULL);
  static int ProtectionFlags[2][2][2]={{
    // not executable
    {PAGE_NOACCESS, PAGE_WRITECOPY},
    {PAGE_READONLY, PAGE_READWRITE},
  }, {
    // executable
    {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
    {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
  }};
  if(FileSize!=(DWORD)-1){
    LPVOID lpBuffer=VirtualAlloc(NULL,FileSize,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(lpBuffer){
      if(ReadFile(hFile,lpBuffer,FileSize,NULL,NULL)){
        // Get the NT Header
        PIMAGE_NT_HEADERS NtHeaders;
        if((NtHeaders=RtlImageNtHeader(lpBuffer))){
          BOOL bValidImageBase=(NtHeaders->OptionalHeader.ImageBase > 0x10000);
          LPVOID intBuffer=bValidImageBase ? VirtualAllocEx(hProcess,(LPVOID)(NtHeaders->OptionalHeader.ImageBase),
            NtHeaders->OptionalHeader.SizeOfImage,MEM_RESERVE,PAGE_READWRITE) : NULL;
          if(!intBuffer){
            intBuffer=VirtualAllocEx(hProcess,NULL,NtHeaders->OptionalHeader.SizeOfImage,MEM_RESERVE,PAGE_READWRITE);
            Status=STATUS_IMAGE_NOT_AT_BASE;
          }
          if(intBuffer){
            ULONG OldProtection;
            //copy header...
            VirtualAllocEx(hProcess,intBuffer,NtHeaders->OptionalHeader.SizeOfHeaders,MEM_COMMIT,PAGE_READWRITE);
            WriteProcessMemory(hProcess,intBuffer,lpBuffer,NtHeaders->OptionalHeader.SizeOfHeaders,0);
            // Set protection
            VirtualProtectEx(hProcess,intBuffer,NtHeaders->OptionalHeader.SizeOfHeaders,PAGE_READONLY,&OldProtection);
            //map data...
            for(INT i=0;i<NtHeaders->FileHeader.NumberOfSections;i++){
              PIMAGE_SECTION_HEADER pISH=RtlGetSectionHeader(NtHeaders,i);
              if(pISH&&!(pISH->Characteristics&IMAGE_SCN_TYPE_NOLOAD)){
                ULONG VirtualSize=pISH->Misc.VirtualSize;
                ULONG SizeOfRawData=pISH->SizeOfRawData;
                PVOID SectionBase=(PVOID)((ULONG_PTR)intBuffer+pISH->VirtualAddress);
                if(VirtualSize==0)
                  VirtualSize=SizeOfRawData;
                if(pISH->PointerToRawData==0)
                  SizeOfRawData=0;
                else if(SizeOfRawData>VirtualSize)
                  SizeOfRawData=VirtualSize;
                if(SizeOfRawData!=0){
                  VirtualAllocEx(hProcess,SectionBase,VirtualSize,MEM_COMMIT,PAGE_READWRITE);//SizeOfRawData
                  WriteProcessMemory(hProcess,SectionBase,&((PBYTE)lpBuffer)[pISH->PointerToRawData],SizeOfRawData,0);
                }
                if(SizeOfRawData<VirtualSize){
                  VirtualAllocEx(hProcess,(PBYTE)SectionBase+SizeOfRawData,VirtualSize-SizeOfRawData,MEM_COMMIT,PAGE_READWRITE);
                  ZeroProcessMemory(hProcess,(PBYTE)SectionBase+SizeOfRawData,VirtualSize-SizeOfRawData);
                }
                // Change Memory Protection
                if(VirtualSize){
                  UINT executable=(pISH->Characteristics&IMAGE_SCN_MEM_EXECUTE)!=0;
                  UINT readable=(pISH->Characteristics&IMAGE_SCN_MEM_READ)!=0;
                  UINT writeable=(pISH->Characteristics&IMAGE_SCN_MEM_WRITE)!=0;
                  ULONG NewProtection=ProtectionFlags[executable][readable][writeable];
                  if(pISH->Characteristics&IMAGE_SCN_MEM_NOT_CACHED){
                    NewProtection|=PAGE_NOCACHE;
                  }
                  VirtualProtectEx(hProcess,SectionBase,VirtualSize,NewProtection,&OldProtection);
                }
              }
            }
            //Set Protections (VM Protect 3 needs a better protection :S)
            //LdrpSetProtection(hProcess,NtHeaders,intBuffer,TRUE);
            //return data...
            *BaseAddress=intBuffer;
            *ViewSize=NtHeaders->OptionalHeader.SizeOfImage;
            return Status;
          }
        }
      }
      VirtualFree(lpBuffer,0,MEM_RELEASE);
    }
  }
  return STATUS_FAILURE;
}

VOID WINAPI UnmapViewOfFile(HANDLE hProcess,LPVOID ViewBase){
  VirtualFreeEx(hProcess,ViewBase,0,MEM_RELEASE);
}

HMODULE WINAPI RemoteLoadLibraryInject(HANDLE hProcess,LPSTR dllName){
  LPVOID lpRemoteMem,lpLoadLibrary;HMODULE hMod=NULL;
  HANDLE hThread;UINT uMemLen=strlen(dllName)+1;CHAR sBuffer[MAX_PATH];
  if((lpRemoteMem=VirtualAllocEx(hProcess,NULL,uMemLen,MEM_COMMIT,PAGE_READWRITE))!=NULL){
    if(WriteProcessMemory(hProcess,lpRemoteMem,(LPCVOID)dllName,uMemLen,NULL)){
      HMODULE hRemKernel32=GetRemoteModuleHandle(hProcess,"kernel32.dll");
      //HMODULE hKernel32=GetModuleHandleA("kernel32.dll");
      lpLoadLibrary=(LPVOID)GetProcAddress(hKernel32,"LoadLibraryA");
      lpLoadLibrary=(LPVOID)((DWORD)lpLoadLibrary+(DWORD)hRemKernel32-(DWORD)hKernel32);
      if((hThread=CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)lpLoadLibrary,lpRemoteMem,0,NULL))!=NULL){
        WaitForSingleObject(hThread,INFINITE);
        GetExitCodeThread(hThread,(PDWORD)&hMod);
        CloseHandle(hThread);
      }
    }
    VirtualFreeEx(hProcess,lpRemoteMem,uMemLen,MEM_RELEASE);
  }
  return hMod;
}

HMODULE WINAPI LocalLoadLibrary(LPSTR dllName){
  typedef HMODULE (WINAPI *tLoadLibrary)(LPCTSTR lpFileName);
  static tLoadLibrary pLoadLibrary=NULL;CHAR sBuffer[MAX_PATH];
  if(!pLoadLibrary){
    //HMODULE hKernel32=GetModuleHandleA("kernel32.dll");
    pLoadLibrary=(tLoadLibrary)GetProcAddress(hKernel32,"LoadLibraryA");
  }
  if(pLoadLibrary){
    HMODULE hMod=pLoadLibrary(dllName);
    return hMod;
  }
  return NULL;
}

BOOL WINAPI LocalFreeLibrary(HMODULE hLibModule){
  typedef BOOL (WINAPI *tFreeLibrary)(HMODULE hLibModule);
  static tFreeLibrary pFreeLibrary=NULL;CHAR sBuffer[MAX_PATH];
  if(!pFreeLibrary){
    //HMODULE hKernel32=GetModuleHandleA("kernel32.dll");
    pFreeLibrary=(tFreeLibrary)GetProcAddress(hKernel32,"FreeLibrary");
  }
  if(pFreeLibrary)
    return pFreeLibrary(hLibModule);
  return FALSE;
}

LPSTR ResolveApiSchemaLibrary(LPSTR dllName,LPSTR ndllname){
  LPSTR sRet=dllName;
  static HMODULE hApiSchema=NULL;CHAR sBuffer[MAX_PATH];
  static CHAR realdll[MAX_PATH];
  if(!strnicmp(dllName,"API-MS-Win",10)){
    if(!hApiSchema){
      RtlWow64EnableFsRedirection(FALSE);
      hApiSchema=LoadLibrary("apisetschema.dll");
      RtlWow64EnableFsRedirection(TRUE);
    }
    if(hApiSchema){
      PIMAGE_NT_HEADERS NtHeaders;
      if((NtHeaders=RtlImageNtHeader(hApiSchema))){
        PIMAGE_SECTION_HEADER pISH=RtlGetSectionHeader(NtHeaders,0);
        if(pISH){
          PAPISETMAP pMap=(PAPISETMAP)((PBYTE)hApiSchema+pISH->VirtualAddress);
          if(pMap->Version==2){
            for(DWORD i=0;i<pMap->NumberOfHosts;i++){
              CHAR AnsiName[MAX_PATH];
              PDLLHOSTDESCRIPTOR descriptor=&pMap->descriptors[i];
              RtlUnicodeToMultiByte(AnsiName,MAX_PATH,(PWSTR)((PBYTE)pMap+descriptor->OffsetDllString),descriptor->StringLength);
              if(!strnicmp(&dllName[4],AnsiName,descriptor->StringLength/sizeof(WCHAR)-4)){
                PDLLREDIRECTOR pRed=(PDLLREDIRECTOR)((PBYTE)pMap+descriptor->OffsetDllRedirector);
                RtlUnicodeToMultiByte(realdll,MAX_PATH,(PWSTR)((PBYTE)pMap+pRed->Redirection[0].OffsetRedirection2),pRed->Redirection[0].RedirectionLength2);
                realdll[pRed->Redirection[0].RedirectionLength2/sizeof(WCHAR)]=0;
                sRet=realdll;
              }
            }
          }else if(pMap->Version==4){//8.1
            PAPISETMAP4 pMap4=(PAPISETMAP4)((PBYTE)hApiSchema+pISH->VirtualAddress);
            for(DWORD i=0;i<pMap4->NumberOfHosts;i++){
              CHAR AnsiName[MAX_PATH];
              PDLLHOSTDESCRIPTOR4 descriptor=&pMap4->descriptors[i];
              RtlUnicodeToMultiByte(AnsiName,MAX_PATH,(PWSTR)((PBYTE)pMap4+descriptor->OffsetDllString),descriptor->StringLength);
              if(!strnicmp(&dllName[4],AnsiName,descriptor->StringLength/sizeof(WCHAR)-4)){
                PDLLREDIRECTOR4 pRed=(PDLLREDIRECTOR4)((PBYTE)pMap4+descriptor->OffsetDllRedirector);
                RtlUnicodeToMultiByte(realdll,MAX_PATH,(PWSTR)((PBYTE)pMap4+pRed->Redirection[0].OffsetOfHostName),pRed->Redirection[0].HostNameSize);
                realdll[pRed->Redirection[0].HostNameSize/sizeof(WCHAR)]=0;
                sRet=realdll;
              }
            }
          }else if(pMap->Version==6){//10
            PAPISETMAP6 pMap6=(PAPISETMAP6)((PBYTE)hApiSchema+pISH->VirtualAddress);
            for(DWORD i=0;i<pMap6->NumberOfHosts;i++){
              CHAR AnsiName[MAX_PATH];
              PDLLHOSTDESCRIPTOR6 descriptor=&pMap6->descriptors[i];
              RtlUnicodeToMultiByte(AnsiName,MAX_PATH,(PWSTR)((PBYTE)pMap6+descriptor->OffsetDllString),descriptor->StringLength);
              if(!strnicmp(&dllName[4],AnsiName,descriptor->StringLength/sizeof(WCHAR)-4)){
                PDLLREDIRECTOR6 pRed=(PDLLREDIRECTOR6)((PBYTE)pMap6+descriptor->OffsetDllRedirector);
                RtlUnicodeToMultiByte(realdll,MAX_PATH,(PWSTR)((PBYTE)pMap6+pRed->OffsetOfHostName),pRed->HostNameSize);
                realdll[pRed->HostNameSize/sizeof(WCHAR)]=0;
                sRet=realdll;
              }
            }
          }
        }
      }
    }
    if(sRet!=dllName&&ndllname)
      strcpy(ndllname,sRet);
  }
  return sRet;
}

NTSTATUS WINAPI LdrLoadDllEx(HANDLE hProcess,PWSTR DllPath,PULONG DllCharacteristics,PUNICODE_STRING DllName,PVOID *BaseAddress){
  UNICODE_STRING FullDllName,NtPathDllName;
  NTSTATUS Status=STATUS_SUCCESS;
  CHAR AnsiName[MAX_PATH];
  PVOID hModule=NULL;
  // Valid Args?
  if(DllName&&DllName->Buffer){
    // Check if this is an absolute path
    for(UINT i=0;i<DllName->Length/sizeof(WCHAR);i++){
      if(DllName->Buffer[i]==L'\\'){
        Status=STATUS_INVALID_PARAMETER;
        goto LdrExit;
      }
    }
    // Find Module
    RtlUnicodeToMultiByte(AnsiName,MAX_PATH,DllName->Buffer,DllName->Length+sizeof(WCHAR));
    // Find module in remote/local process
    if(hProcess!=NtCurrentProcess())
      hModule=GetRemoteModuleHandle(hProcess,AnsiName);
    else
      hModule=GetModuleHandle(AnsiName);
    if(hModule){
      Status=STATUS_SUCCESS;
      goto LdrExit;
    }
    // Get local enviroment path if not defined
    if(!DllPath)DllPath=NtCurrentPeb()->ProcessParameters->DllPath.Buffer;
    if(!DllPath)DllPath=RtlGetModuleLoadPath();
    if(!DllPath){
      Status=STATUS_NO_MEMORY;
      goto LdrExit;
    }
    // Allocate space for full DLL name
    FullDllName.Buffer=(PWCHAR)RtlAllocateHeap(RtlGetProcessHeap(),0,MAX_PATH*sizeof(WCHAR));
    if(!FullDllName.Buffer){
      Status=STATUS_NO_MEMORY;
      goto LdrExit;
    }
    // Find DLL
    BOOL bFound=FALSE;
    PWCHAR pathstart=DllPath,patchend=DllPath,p=DllPath;
    while(*p){
      // Loop as long as there's no semicolon
      while(*p&&*p!=L';')p++;
      patchend=p;
      if(*p==L';')++p;
      // Copy Path
      ULONG Length=patchend-pathstart;
      RtlCopyMemory(FullDllName.Buffer,pathstart,Length*sizeof(WCHAR));
      // Add a terminating slash if needed
      if(FullDllName.Buffer[Length-1]!=L'\\'){
        FullDllName.Buffer[Length]=L'\\';
        Length++;
      }
      // Copy the file name
      RtlCopyMemory(&FullDllName.Buffer[Length],DllName->Buffer,DllName->Length);
      Length+=DllName->Length/sizeof(WCHAR);
      // Just NULL-terminate
      FullDllName.Buffer[Length]=UNICODE_NULL;
      FullDllName.Length=Length*sizeof(WCHAR);
      FullDllName.MaximumLength=FullDllName.Length+sizeof(UNICODE_NULL);
      // Check if File Exist
      if(RtlDoesFileExists(&FullDllName,FALSE)){
        // Call the full-path API to get the length
        bFound=NT_SUCCESS(RtlDosPathNameToNtPathName(&FullDllName,&NtPathDllName,NULL));
        break;
      }
      pathstart=p;
    }
    // DLL Found?
    if(bFound){
      OBJECT_ATTRIBUTES ObjectAttributes;
      HANDLE hFile;//,hSection;//using windows api mapper
      IO_STATUS_BLOCK IoStatusBlock;
      // Create the object attributes
      InitializeObjectAttributes(&ObjectAttributes,&NtPathDllName,OBJ_CASE_INSENSITIVE,NULL,NULL);
      // Open the DLL
      Status=_NtOpenFile(&hFile,SYNCHRONIZE|FILE_EXECUTE|FILE_READ_DATA,
        &ObjectAttributes,&IoStatusBlock,FILE_SHARE_READ|FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
      // Check if we failed
      if(!NT_SUCCESS(Status)){
        // Attempt to open for execute only
        Status=_NtOpenFile(&hFile,SYNCHRONIZE|FILE_EXECUTE,
          &ObjectAttributes,&IoStatusBlock,FILE_SHARE_READ|FILE_SHARE_DELETE,
          FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
        // Check if this failed too
        if(Status==STATUS_OBJECT_NAME_NOT_FOUND){
          Status=STATUS_DLL_NOT_FOUND;// Callers expect this instead
        }
      }
      // Try Create Section
      if(NT_SUCCESS(Status)){
        PVOID ViewBase=NULL,Buffer=NULL,ViewBuffer=NULL;SIZE_T ViewSize=0;
        //Manual Map of Section/ViewofSection!
        Status=MapViewOfImage(hProcess,hFile,&ViewBase,&ViewSize);
        if(NT_SUCCESS(Status)){

        //using winapi functions... the other is manual!
        //Status=_NtCreateSection(&hSection,SECTION_MAP_READ|SECTION_MAP_EXECUTE|
          //SECTION_MAP_WRITE|SECTION_QUERY,NULL,NULL,PAGE_EXECUTE,SEC_IMAGE,hFile);
        // Create Section OK map it!
        //if(NT_SUCCESS(Status)){
          //PVOID ViewBase=NULL,Buffer=NULL,ViewBuffer=NULL;SIZE_T ViewSize=0;
          // Map the DLL
          //Status=_NtMapViewOfSection(hSection,hProcess,&ViewBase,0,0,NULL,&ViewSize,ViewShare,0,PAGE_READWRITE);
          // We could map it
          //if(NT_SUCCESS(Status)){
            // If the process is other we must use a buffer...
            if(hProcess!=NtCurrentProcess()){
              Buffer=VirtualAlloc(ViewBase,ViewSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
              if(!Buffer)
                Buffer=VirtualAlloc(NULL,ViewSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
              if(Buffer&&NT_SUCCESS(_NtReadVirtualMemory(hProcess,ViewBase,Buffer,ViewSize,NULL)))
                ViewBuffer=Buffer;
            }else
              ViewBuffer=ViewBase;
            // We can allocate?
            if(ViewBuffer){
              // Get the NT Header
              PIMAGE_NT_HEADERS NtHeaders;
              if((NtHeaders=RtlImageNtHeader(ViewBuffer))){
                // Change the protection to prepare for modifications
                // Make sure we changed the protection
                if(NT_SUCCESS(LdrpSetProtection(hProcess,NtHeaders,ViewBase,FALSE))){
                  // ******************************************************
                  // Relocation part start
                  // ******************************************************
                  // Check if we loaded somewhere else
                  if(Status==STATUS_IMAGE_NOT_AT_BASE){
                    if(!(NtHeaders->FileHeader.Characteristics&IMAGE_FILE_RELOCS_STRIPPED)){
                      // Do the relocation
                      PIMAGE_DATA_DIRECTORY RelocationDDir=&NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                      if(RelocationDDir->VirtualAddress!=0&&RelocationDDir->Size!=0){
                        LONGLONG Delta=(ULONG_PTR)ViewBase-NtHeaders->OptionalHeader.ImageBase;
                        PIMAGE_BASE_RELOCATION RelocationDir=(PIMAGE_BASE_RELOCATION)((ULONG_PTR)ViewBuffer+RelocationDDir->VirtualAddress);
                        PIMAGE_BASE_RELOCATION RelocationEnd=(PIMAGE_BASE_RELOCATION)((ULONG_PTR)RelocationDir+RelocationDDir->Size);
                        while(RelocationDir<RelocationEnd&&RelocationDir->SizeOfBlock>0){
                          ULONG Count=(RelocationDir->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(USHORT);
                          ULONG_PTR Address=RVAPTR(ULONG_PTR,ViewBuffer,RelocationDir->VirtualAddress);
                          PUSHORT TypeOffset=(PUSHORT)(RelocationDir+1);
                          for(USHORT i=0;i<Count;i++){
                            SHORT Offset=*TypeOffset&0xFFF;
                            USHORT Type=*TypeOffset>>12;
                            PUSHORT ShortPtr=RVAPTR(PUSHORT,Address,Offset);
                            PULONG LongPtr=RVAPTR(PULONG,Address,Offset);
                            switch(Type){
                              case IMAGE_REL_BASED_HIGH:
                                *ShortPtr=HIWORD(MAKELONG(0,*ShortPtr)+(LONG)Delta);
                              break;
                              case IMAGE_REL_BASED_LOW:
                                *ShortPtr=*ShortPtr+LOWORD(Delta);
                              break;
                              case IMAGE_REL_BASED_HIGHLOW:
                                *LongPtr=*LongPtr+(ULONG)Delta;
                              break;
                              case IMAGE_REL_BASED_ABSOLUTE:break;
                              //case IMAGE_REL_BASED_SECTION:case IMAGE_REL_BASED_REL32:IMAGE_REL_BASED_MIPS_JMPADDR16:
                              //case IMAGE_REL_BASED_DIR64:case IMAGE_REL_BASED_HIGHADJ:case IMAGE_REL_BASED_MIPS_JMPADDR:
                              default:
                                TypeOffset=NULL;
                              break;
                            }
                            if(!TypeOffset)
                              break;
                            TypeOffset++;
                          }
                          RelocationDir=(PIMAGE_BASE_RELOCATION)TypeOffset;
                          if(RelocationDir==NULL){
                            Status=STATUS_INVALID_IMAGE_FORMAT;
                            break;
                          }
                        }
                      }
                    }
                  }
                  // ******************************************************
                  // Relocation part end - Imports start
                  // ******************************************************
                  if(NT_SUCCESS(Status)){
                    ULONG IatSize;
                    // Get the regular IAT, for fallback
                    PIMAGE_IMPORT_DESCRIPTOR ImportEntry=(PIMAGE_IMPORT_DESCRIPTOR)
                    RtlImageDirectoryEntryToData(ViewBuffer,TRUE,IMAGE_DIRECTORY_ENTRY_IMPORT,&IatSize);
                    if(ImportEntry){
                      // This loader only load "main" dll, not dependencies
                      // so check client has all needed dll's
                      PIMAGE_IMPORT_DESCRIPTOR ImportCheck=ImportEntry;
                      while((ImportCheck->Name)&&(ImportCheck->FirstThunk)){
                        // Get the import name's VA
                        LPSTR ImportName=(LPSTR)((ULONG_PTR)ViewBuffer+ImportCheck->Name);
                        ImportName=ResolveApiSchemaLibrary(ImportName,NULL);
                        if(hProcess!=NtCurrentProcess()){
                          // Find module in remote process
                          if(!GetRemoteModuleHandle(hProcess,ImportName))
                            RemoteLoadLibraryInject(hProcess,ImportName);
                          if(!GetRemoteModuleHandle(hProcess,ImportName)){
                            Status=STATUS_DLL_NOT_FOUND;
                            break;
                          }
                        }
                        // Find module in local process
                        if(!GetModuleHandle(ImportName)){
                          //need to be localy loaded for linked list!
                          if(!LocalLoadLibrary(ImportName)){
                            Status=STATUS_DLL_NOT_FOUND;
                            break;
                          }
                        }
                        // Move on
                        ImportCheck++;
                      }
                      //DbgPrint("*** LdrLoadDllEx 4!");
                      // Dll dependencies Ok
                      if(NT_SUCCESS(Status)){
                        // Link them!
                        while((ImportEntry->Name)&&(ImportEntry->FirstThunk)){
                          // Get the import name's VA
                          LPSTR ImportName=(LPSTR)((ULONG_PTR)ViewBuffer+ImportEntry->Name);
                          ImportName=ResolveApiSchemaLibrary(ImportName,NULL);
                          // Get the first thunk
                          PIMAGE_THUNK_DATA FirstThunk=(PIMAGE_THUNK_DATA)((ULONG_PTR)ViewBuffer+ImportEntry->FirstThunk);
                          // Make sure it's valid
                          if(FirstThunk->u1.Function){
                            PIMAGE_THUNK_DATA OriginalThunk;
                            HMODULE hRemoteImport=NULL;
                            // Find the module associated to it
                            if(hProcess!=NtCurrentProcess()){
                              hRemoteImport=GetRemoteModuleHandle(hProcess,ImportName);
                              if(!hRemoteImport){
                                Status=STATUS_DLL_NOT_FOUND;
                                break;
                              }
                            }else
                              hRemoteImport=GetModuleHandle(ImportName);
                            // Get local module to get addresses
                            HMODULE hImport=GetModuleHandle(ImportName);
                            if(!hImport){
                              Status=STATUS_DLL_NOT_FOUND;
                              break;
                            }
                            // Get export directory
                            ULONG ExportSize;
                            PIMAGE_EXPORT_DIRECTORY ExportDirectory=(PIMAGE_EXPORT_DIRECTORY)
                              RtlImageDirectoryEntryToData(hImport,TRUE,IMAGE_DIRECTORY_ENTRY_EXPORT,&ExportSize);
                            // Make sure it has one
                            if(!ExportDirectory){
                              Status=STATUS_INVALID_IMAGE_FORMAT;
                              break;
                            }
                            // Get the Original thunk VA, watch out for weird images
                            if((ImportEntry->Characteristics<NtHeaders->OptionalHeader.SizeOfHeaders)||
                              (ImportEntry->Characteristics>=NtHeaders->OptionalHeader.SizeOfImage))
                              // Refuse it, this is a strange linked file
                              OriginalThunk=FirstThunk;
                            else
                              // Get the address from the field and convert to VA
                              OriginalThunk=(PIMAGE_THUNK_DATA)
                                ((ULONG_PTR)ViewBuffer+ImportEntry->OriginalFirstThunk);
                            // Loop while it's valid
                            while(OriginalThunk->u1.AddressOfData){
                              BOOL IsOrdinal;USHORT Ordinal;//LPSTR ImportName=NULL;
                              // Check if the snap is by ordinal
                              if((IsOrdinal=IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal))){
                                // Get the ordinal number, and its normalized version
                                ULONG OriginalOrdinal=IMAGE_ORDINAL(OriginalThunk->u1.Ordinal);
                                Ordinal=(USHORT)(OriginalOrdinal-ExportDirectory->Base);
                              }else{
                                // First get the data VA
                                PIMAGE_IMPORT_BY_NAME AddressOfData=(PIMAGE_IMPORT_BY_NAME)
                                  ((ULONG_PTR)ViewBuffer+((ULONG_PTR)OriginalThunk->u1.AddressOfData));
                                // Get the name
                                LPSTR ImportName=(LPSTR)AddressOfData->Name;
                                // Now get the VA of the Name and Ordinal Tables
                                PULONG NameTable=(PULONG)((ULONG_PTR)hImport+
                                  (ULONG_PTR)ExportDirectory->AddressOfNames);
                                PUSHORT OrdinalTable=(PUSHORT)((ULONG_PTR)hImport+
                                  (ULONG_PTR)ExportDirectory->AddressOfNameOrdinals);
                                // Get the hint
                                USHORT Hint=AddressOfData->Hint;
                                // Try to get a match by using the hint
                                if(((ULONG)Hint<ExportDirectory->NumberOfNames)&&
                                  (!strcmp(ImportName,((LPSTR)((ULONG_PTR)hImport+NameTable[Hint])))))
                                  // We got a match, get the Ordinal from the hint
                                  Ordinal=OrdinalTable[Hint];
                                else{
                                  // Well bummer, hint didn't work, do it the long way
                                  LONG Start=0,End=0,Next=0,CmpResult=0;
                                  // Use classical binary search to find the ordinal
                                  End=ExportDirectory->NumberOfNames-1;
                                  while(End>=Start){
                                    // Next will be exactly between Start and End
                                    Next=(Start+End)>>1;
                                    // Compare this name with the one we need to find
                                    CmpResult=strcmp(ImportName,(PCHAR)((ULONG_PTR)hImport+NameTable[Next]));
                                    // We found our entry if result is 0
                                    if(!CmpResult)break;
                                    // We didn't find, update our range then
                                    if(CmpResult<0)
                                      End=Next-1;
                                    else if(CmpResult>0)
                                      Start=Next+1;
                                  }
                                  // If end is before start, then the search failed
                                  if(End<Start)Ordinal=(USHORT)-1;
                                  // Return found name
                                  else Ordinal=OrdinalTable[Next];
                                }
                              }
                              // Check if the ordinal is invalid
                              if((ULONG)Ordinal<ExportDirectory->NumberOfFunctions){
                                // The ordinal seems correct, get the AddressOfFunctions VA
                                PULONG AddressOfFunctions=(PULONG)((ULONG_PTR)hImport+(ULONG_PTR)ExportDirectory->AddressOfFunctions);
                                // Write the function pointer
                                FirstThunk->u1.Function=(ULONG_PTR)hRemoteImport+AddressOfFunctions[Ordinal];
                                // Make sure it's within the exports
                                if((FirstThunk->u1.Function>(ULONG_PTR)ExportDirectory)&&
                                  (FirstThunk->u1.Function<((ULONG_PTR)ExportDirectory+ExportSize))){
                                  CHAR ForwarderName[MAX_PATH],*ForwardImportName=NULL;
                                  ULONG ForwardOrdinal=0;
                                  // Get the Import and Forwarder Names
                                  LPSTR ForwarderImportName=(LPSTR)FirstThunk->u1.Function;
                                  ForwardImportName=strchr(ForwarderImportName,'.');
                                  USHORT len=ForwardImportName++-ForwarderImportName;
                                  strncpy(ForwarderName,ForwarderImportName,len);
                                  strcpy(&ForwarderName[len],".dll");
                                  ResolveApiSchemaLibrary(ForwarderName,ForwarderName);
                                  // Find the module associated to it
                                  HMODULE hRemoteForwarderImport=GetRemoteModuleHandle(hProcess,ForwarderName);
                                  if(!hRemoteForwarderImport){
                                    Status=STATUS_DLL_NOT_FOUND;
                                    break;
                                  }
                                  // Get local module to get addresses
                                  HMODULE hForwarderImport=GetModuleHandle(ForwarderName);
                                  if(!hForwarderImport){
                                    Status=STATUS_DLL_NOT_FOUND;
                                    break;
                                  }
                                  // Check if it's an ordinal forward
                                  if((strlen(ForwardImportName)>1)&&(*ForwardImportName=='#')){
                                    // Convert the string into an ordinal
                                    RtlCharToInteger(ForwardImportName+sizeof(CHAR),0,&ForwardOrdinal);
                                    // We don't have an actual function name
                                    ForwardImportName=NULL;
                                  }
                                  // Get export directory
                                  ULONG ForwardExportSize;
                                  PIMAGE_EXPORT_DIRECTORY ForwardExportDirectory=(PIMAGE_EXPORT_DIRECTORY)
                                    RtlImageDirectoryEntryToData(hForwarderImport,TRUE,IMAGE_DIRECTORY_ENTRY_EXPORT,&ForwardExportSize);
                                  // Make sure it has one
                                  if(!ForwardExportDirectory){
                                    Status=STATUS_INVALID_IMAGE_FORMAT;
                                    break;
                                  }
                                  // Check if we got a name
                                  if(ForwardImportName){
                                    // Now get the VA of the Name and Ordinal Tables
                                    PULONG NameTable=(PULONG)((ULONG_PTR)hForwarderImport+
                                      (ULONG_PTR)ForwardExportDirectory->AddressOfNames);
                                    PUSHORT OrdinalTable=(PUSHORT)((ULONG_PTR)hForwarderImport+
                                      (ULONG_PTR)ForwardExportDirectory->AddressOfNameOrdinals);
                                    // Well bummer, hint didn't work, do it the long way
                                    LONG Start=0,End=0,Next=0,CmpResult=0;
                                    // Use classical binary search to find the ordinal
                                    End=ForwardExportDirectory->NumberOfNames-1;
                                    while(End>=Start){
                                        // Next will be exactly between Start and End
                                        Next=(Start+End)>>1;
                                        // Compare this name with the one we need to find
                                        CmpResult=strcmp(ForwardImportName,(PCHAR)((ULONG_PTR)hForwarderImport+NameTable[Next]));
                                        // We found our entry if result is 0
                                        if(!CmpResult)break;
                                        // We didn't find, update our range then
                                        if(CmpResult<0)
                                          End=Next-1;
                                        else if(CmpResult>0)
                                          Start=Next+1;
                                      }
                                      // If end is before start, then the search failed
                                      if(End<Start)ForwardOrdinal=(ULONG)-1;
                                      // Return found name
                                      else ForwardOrdinal=OrdinalTable[Next];
                                  }else{
                                    // Make sure an ordinal was given
                                    if(!ForwardOrdinal){
                                      Status=STATUS_INVALID_PARAMETER;
                                      break;
                                    }
                                    ForwardOrdinal=(USHORT)(ForwardOrdinal-ForwardExportDirectory->Base);
                                  }
                                  // Check if the ordinal is invalid
                                  if((ULONG)ForwardOrdinal<ForwardExportDirectory->NumberOfFunctions){
                                    // The ordinal seems correct, get the AddressOfForwarderFunctions VA
                                    PULONG AddressOfForwarderFunctions=(PULONG)((ULONG_PTR)hForwarderImport+(ULONG_PTR)ForwardExportDirectory->AddressOfFunctions);
                                    // Write the function pointer
                                    FirstThunk->u1.Function=(ULONG_PTR)hRemoteForwarderImport+AddressOfForwarderFunctions[ForwardOrdinal];
                                    // It's not within the exports, let's hope it's valid
                                    if(!AddressOfForwarderFunctions[ForwardOrdinal]){
                                      Status=STATUS_ENTRYPOINT_NOT_FOUND;
                                    }
                                  }else{
                                    Status=STATUS_ENTRYPOINT_NOT_FOUND;
                                  }
                                }else
                                  // It's not within the exports, let's hope it's valid
                                  if(!AddressOfFunctions[Ordinal]){
                                    Status=IsOrdinal?STATUS_ORDINAL_NOT_FOUND:STATUS_ENTRYPOINT_NOT_FOUND;
                                  }
                              }else{// Return the right error code
                                Status=IsOrdinal?STATUS_ORDINAL_NOT_FOUND:STATUS_ENTRYPOINT_NOT_FOUND;
                              }
                              // If we failed the snap, break out
                              if(!NT_SUCCESS(Status))
                                break;
                              // Next thunks
                              OriginalThunk++;
                              FirstThunk++;
                            }
                            if(!NT_SUCCESS(Status))
                              break;
                          }
                          if(!NT_SUCCESS(Status))
                            break;
                          // Move on
                          ImportEntry++;
                        }
                      }
                    }
                  }
                  // *****************************************************
                  // Imports end
                  // *****************************************************
                  if(NT_SUCCESS(Status)){
                    // Update DLL
                    if(Buffer){
                      PIMAGE_SECTION_HEADER Section=IMAGE_FIRST_SECTION(NtHeaders);
                      // Go through all sections
                      for(ULONG i=0;i<NtHeaders->FileHeader.NumberOfSections;i++){
                        // Check for non-zero section
                        if(Section->SizeOfRawData){
                          // Get the section VA
                          PVOID SectionBase=(PVOID)((ULONG_PTR)ViewBase+Section->VirtualAddress);
                          PVOID SectionCode=(PVOID)((ULONG_PTR)Buffer+Section->VirtualAddress);
                          SIZE_T SectionSize=Section->SizeOfRawData;
                          // Write code
                          Status=_NtWriteVirtualMemory(hProcess,SectionBase,SectionCode,SectionSize,NULL);
                          if(!NT_SUCCESS(Status)){
                            break;
                          }
                        }
                        // Move to the next section
                        Section++;
                      }
                      if(NT_SUCCESS(Status))
                        _NtFlushInstructionCache(hProcess,ViewBase,ViewSize);
                    }
                    if(NT_SUCCESS(Status))// Return the protection
                      Status=LdrpSetProtection(hProcess,NtHeaders,ViewBase,TRUE);
                  }
                  if(NT_SUCCESS(Status)){// Run the init routine
                    // Get its entrypoint
                    ULONG_PTR EntryPoint=NtHeaders->OptionalHeader.AddressOfEntryPoint;
                    // Make sure we have an entrypoint
                    if(EntryPoint){
                      EntryPoint+=(ULONG_PTR)ViewBase;
                      // Call the Entrypoint
                      if(hProcess!=NtCurrentProcess()){
                        HANDLE hThread=NULL;
                        BYTE EntryPointCode[]={
                          0x68,0x00,0x00,0x00,0x00,//push reserved
                          0x68,0x00,0x00,0x00,0x00,//push reason
                          0x68,0x00,0x00,0x00,0x00,//push hInstance
                          0xB8,0x00,0x00,0x00,0x00,//mov eax, EntryPoint
                          0xFF,0xD0,//call eax
                          0xC3//ret
                        };
                        INJECTION_ARGS args={{0},ViewSize};
                        PBYTE pBuff=(PBYTE)VirtualAllocEx(hProcess,NULL,sizeof(EntryPointCode)+sizeof(args),MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
                        if(pBuff){
                          // Because this dll is not in list, it can't get it name by
                          // GetModuleFileName, so we send it name in the reserved param
                          RtlUnicodeToMultiByte(args.path,MAX_PATH,FullDllName.Buffer,(ULONG)-1);
                          *((PDWORD)&EntryPointCode[0x1])=(DWORD_PTR)pBuff+sizeof(EntryPointCode);//reserved
                          *((PDWORD)&EntryPointCode[0x6])=DLL_PROCESS_ATTACH;//reason
                          *((PDWORD)&EntryPointCode[0xB])=(DWORD)ViewBase;//hInstance
                          *((PDWORD)&EntryPointCode[0x10])=EntryPoint;//EntryPoint
                          if(WriteProcessMemory(hProcess,pBuff,EntryPointCode,sizeof(EntryPointCode),NULL)){
                            WriteProcessMemory(hProcess,pBuff+sizeof(EntryPointCode),&args,sizeof(args),NULL);
                            FlushInstructionCache(hProcess,pBuff,sizeof(EntryPointCode)+sizeof(args));
                            hThread=CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)pBuff,NULL,0,NULL);
                            if(hThread){
                              BOOL bRet=FALSE;
                              WaitForSingleObject(hThread,INFINITE);
                              GetExitCodeThread(hThread,(PDWORD)&bRet);
                              if(bRet){
                                hModule=ViewBase;//set handle
                              }else{//init fail
                                Status=STATUS_DLL_INIT_FAILED;
                              }
                              CloseHandle(hThread);
                            }else{
                              Status=STATUS_DLL_INIT_FAILED;
                            }
                            VirtualFreeEx(hProcess,pBuff,sizeof(EntryPointCode),MEM_DECOMMIT);
                          }else{
                            Status=STATUS_ACCESS_DENIED;
                          }
                        }else{
                          Status=STATUS_MEMORY_NOT_ALLOCATED;
                        }
                      }else{
                        if(((PDLL_INIT_ROUTINE)EntryPoint)(ViewBase,DLL_PROCESS_ATTACH,NULL)){
                          hModule=ViewBase;//set handle
                        }else{//init fail
                          Status=STATUS_DLL_INIT_FAILED;
                        }
                      }
                    }else{
                      hModule=ViewBase;//set handle
                    }
                    if(!NT_SUCCESS(Status)){
                      // Failed, unload the DLL
                      //_NtUnmapViewOfSection(hProcess,ViewBase);
                      UnmapViewOfFile(hProcess,ViewBase);
                    }
                  }else{
                    // Cancel the load
                    //_NtUnmapViewOfSection(hProcess,ViewBase);
                    UnmapViewOfFile(hProcess,ViewBase);
                  }
                }else{
                  //_NtUnmapViewOfSection(hProcess,ViewBase);
                  UnmapViewOfFile(hProcess,ViewBase);
                  Status=STATUS_ACCESS_DENIED;
                }
              }else{
                // Invalid image, unmap, close handle and fail
                //_NtUnmapViewOfSection(hProcess,ViewBase);
                UnmapViewOfFile(hProcess,ViewBase);
                Status=STATUS_INVALID_IMAGE_FORMAT;
              }
            //using windows api mapper
            //}else{
              // Can't Allocate/Read ViewBuffer, close handle and fail
              //_NtUnmapViewOfSection(hProcess,ViewBase);
              //Status=STATUS_NOT_MAPPED_VIEW;
            //}
          }else{
            Status=STATUS_MEMORY_NOT_ALLOCATED;
          }
          if(Buffer)
            VirtualFree(Buffer,0,MEM_RELEASE);
          //using windows api mapper
          //_NtClose(hSection);
        }
        _NtClose(hFile);
      }
    }else{// Return failure
      Status=STATUS_DLL_NOT_FOUND;
    }
    // Free buffer, we don't need anymore...
    RtlFreeUnicodeString(&NtPathDllName);
    RtlFreeUnicodeString(&FullDllName);
  }else{// Return failure
    Status=STATUS_INVALID_PARAMETER;
  }
LdrExit:
    if(NT_SUCCESS(Status))
      *BaseAddress=hModule;
    else
      *BaseAddress=NULL;
  //DbgPrint("*** LdrLoadDllEx end!");
  return Status;
}

NTSTATUS WINAPI LdrLoadDll(PWSTR DllPath,PULONG DllCharacteristics,PUNICODE_STRING DllName,PVOID *BaseAddress){
  return LdrLoadDllEx(NtCurrentProcess(),DllPath,DllCharacteristics,DllName,BaseAddress);
}

HMODULE WINAPI RemoteLoadLibraryExW(HANDLE hProcess,LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags){
  PWCHAR wfp,wfn;UNICODE_STRING usLibFileName;
  HMODULE hModule=NULL;ULONG ulLdrFlags=0;
  if(lpLibFileName){
    WCHAR buffer[MAX_PATH],*p;
    wcscpy(buffer,lpLibFileName);
    if((p=wcsrchr(buffer,L'\\'))!=NULL){
      *p=0;wfn=p+1;wfp=buffer;
    }else{
      wfn=buffer;wfp=NULL;
    }
    RtlInitUnicodeString(&usLibFileName,wfn);
    if(dwFlags&DONT_RESOLVE_DLL_REFERENCES)
      ulLdrFlags=IMAGE_FILE_EXECUTABLE_IMAGE;
    if(NT_SUCCESS(LdrLoadDllEx(hProcess,wfp,&ulLdrFlags,&usLibFileName,(PVOID*)&hModule)))
      return hModule;
  }
  return NULL;
}

HMODULE WINAPI RemoteLoadLibraryExA(HANDLE hProcess,LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags){
  WCHAR wLibFileName[MAX_PATH];
  if(lpLibFileName!=NULL){
    RtlMultiByteToUnicode(wLibFileName,MAX_PATH,lpLibFileName,(ULONG)-1);
    return RemoteLoadLibraryExW(hProcess,wLibFileName,hFile,dwFlags);
  }
  return NULL;
}

HMODULE WINAPI RemoteLoadLibraryA(HANDLE hProcess,LPCSTR lpLibFileName){
  return RemoteLoadLibraryExA(hProcess,lpLibFileName,NULL,0);
}

HMODULE WINAPI RemoteLoadLibraryW(HANDLE hProcess,LPCWSTR lpLibFileName){
  return RemoteLoadLibraryExW(hProcess,lpLibFileName,NULL,0);
}

HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags){
  return RemoteLoadLibraryExW(NtCurrentProcess(),lpLibFileName,hFile,dwFlags);
}

HMODULE WINAPI LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags){
  return RemoteLoadLibraryExA(NtCurrentProcess(),lpLibFileName,hFile,dwFlags);
}

HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName){
  return LoadLibraryExA(lpLibFileName,NULL,0);
}

HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName){
  return LoadLibraryExW(lpLibFileName,NULL,0);
}

NTSTATUS WINAPI LdrUnloadDllEx(HANDLE hProcess,PVOID BaseAddress){
  return _NtUnmapViewOfSection(hProcess,BaseAddress);
}

NTSTATUS WINAPI LdrUnloadDll(PVOID BaseAddress){
  return LdrUnloadDllEx(NtCurrentProcess(),BaseAddress);
}

BOOL WINAPI FreeLibrary(HMODULE hLibModule){
  return NT_SUCCESS(LdrUnloadDll(hLibModule));
}

// *******************************************************************************
// Win32k
// *******************************************************************************

HDC WINAPI GetDC(HWND hWnd){
  return (HDC)_NtUserGetDC(hWnd);
}

HDC WINAPI GetWindowDC(HWND hWnd){
  return (HDC)_NtUserGetWindowDC(hWnd);
}

INT WINAPI ReleaseDC(HWND hWnd,HDC hDC){
  if(!hDC)return FALSE;
  //_NtGdiDdReleaseDC( hSurface )//???
  return (INT)_NtUserCallOneParam((DWORD_PTR)hDC,(wversion<WINVISTA)?0x39:0x3A);//ONEPARAM_ROUTINE_RELEASEDC (57/58)
}

BOOL WINAPI IsWindow(HWND hWnd){
  if(!(BOOL)_NtUserValidateHandleSecure(hWnd,FALSE)){
    return TRUE;
  }
  return TRUE;
}

SHORT WINAPI GetAsyncKeyState(INT	vKey){
  if(vKey<0||vKey>256)
    return 0;
  return (SHORT)_NtUserGetAsyncKeyState((DWORD)vKey);
}

DWORD WINAPI GetWindowThreadProcessId(HWND hWnd,LPDWORD lpdwProcessId){
  if(!hWnd)
    return 0;
  if(lpdwProcessId)
    *lpdwProcessId=_NtUserQueryWindow(hWnd,QUERY_WINDOW_UNIQUE_PROCESS_ID);
  return _NtUserQueryWindow(hWnd,(wversion<WIN7)?1:2);//QUERY_WINDOW_UNIQUE_THREAD_ID
}

BOOL WINAPI GetMainWindowInfoByProcID(DWORD dwProcId,PMAIN_HWND_INFO data){
  DWORD i,dwCount=512;
  HWND* pHwnd=(HWND*)RtlAllocateHeap(RtlGetProcessHeap(),0,sizeof(HWND)*dwCount);
  if(pHwnd){
    NTSTATUS Status=STATUS_INVALID_PARAMETER;
    if(wversion<WIN8)
      Status=_NtUserBuildHwndList(NULL,NULL,FALSE,0,dwCount,pHwnd,&dwCount);
    else
      Status=_NtUserBuildHwndListEx(NULL,NULL,NULL,FALSE,0,dwCount,pHwnd,&dwCount);
    while(Status==STATUS_BUFFER_TOO_SMALL){
      RtlFreeHeap(RtlGetProcessHeap(),0,pHwnd);
      pHwnd=(HWND*)RtlAllocateHeap(RtlGetProcessHeap(),0,sizeof(HWND)*dwCount);
      if(!pHwnd)return FALSE;
      if(wversion<WIN8)
        Status=_NtUserBuildHwndList(NULL,NULL,FALSE,0,dwCount,pHwnd,&dwCount);
      else
        Status=_NtUserBuildHwndListEx(NULL,NULL,NULL,FALSE,0,dwCount,pHwnd,&dwCount);
    }
    if(NT_SUCCESS(Status)&&dwCount>1){
      for(i=0;i<dwCount;i++){
        if(!pHwnd[i])
          continue;
        DWORD dwProcessID,dwThreadID;
        dwThreadID=GetWindowThreadProcessId(pHwnd[i],&dwProcessID);
        if(dwProcessID==dwProcId){
          //DbgPrint("GetWindowThreadProcessId %X %d %d",pHwnd[i],dwProcessID,dwThreadID);
          GUITHREADINFO guiti;guiti.cbSize=sizeof(guiti);
          if(_NtUserGetGUIThreadInfo(dwThreadID,&guiti)){
            //DbgPrint("GUIThreadInfo %X %X %X %X %X %X",guiti.hwndActive,guiti.hwndCapture,guiti.hwndCaret,guiti.hwndFocus,guiti.hwndMenuOwner,guiti.hwndMoveSize);
            if(guiti.hwndActive==pHwnd[i]){
              //DbgPrint("GetWindowThreadProcessId2 %X %d %d",pHwnd[i],dwProcessID,dwThreadID);
              data->dwProcessID=dwProcessID;
              data->dwThreadID=dwThreadID;
              data->hWnd=pHwnd[i];
              RtlFreeHeap(RtlGetProcessHeap(),0,pHwnd);
              return TRUE;
            }
          }
        }
      }
    }
    RtlFreeHeap(RtlGetProcessHeap(),0,pHwnd);
  }
  return FALSE;
}

LRESULT WINAPI SendMessageA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam){
  return _NtUserMessageCall(hWnd,Msg,wParam,lParam,0,((wversion<WIN8)?FNID_SENDMESSAGE:FNID_SENDMESSAGEW8),TRUE);
}

LRESULT WINAPI SendMessageW(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam){
  return _NtUserMessageCall(hWnd,Msg,wParam,lParam,0,((wversion<WIN8)?FNID_SENDMESSAGE:FNID_SENDMESSAGEW8),FALSE);
}

BOOL WINAPI PostMessageA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam){
  return _NtUserPostMessage(hWnd,Msg,wParam,lParam);
}

BOOL WINAPI PostMessageW(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam){
  return _NtUserPostMessage(hWnd,Msg,wParam,lParam);
}

HDC WINAPI CreateCompatibleDC(HDC hdc){
  return (HDC)_NtGdiCreateCompatibleDC(hdc);
}

BOOL WINAPI DeleteDC(HDC hDC){
  return (BOOL)_NtGdiDeleteObjectApp(hDC);
}

BOOL WINAPI GetWindowPlacement(HWND hWnd,WINDOWPLACEMENT *lpwndpl){
  return (BOOL)_NtUserGetWindowPlacement(hWnd, lpwndpl);
}

BOOL WINAPI PatBlt(HDC hdc,INT nXLeft,INT nYLeft,INT nWidth,INT nHeight,DWORD dwRop){
  return _NtGdiPatBlt(hdc,nXLeft,nYLeft,nWidth,nHeight,dwRop);
}

BOOL WINAPI BitBlt(HDC hdcDest,INT nXOriginDest,INT nYOriginDest,INT nWidthDest,INT nHeightDest,HDC hdcSrc,INT nXSrc,INT nYSrc,DWORD dwRop){
  if(dwRop!=CUSTOM_ROP&&!ROP_USES_SOURCE(dwRop))
    return PatBlt(hdcDest,nXOriginDest,nYOriginDest,nWidthDest,nHeightDest,dwRop);
  return _NtGdiBitBlt(hdcDest,nXOriginDest,nYOriginDest,nWidthDest,nHeightDest,hdcSrc,nXSrc,nYSrc,dwRop,0,0);
}

INT DIB_BitmapInfoSize(const BITMAPINFO *info,WORD coloruse){
  UINT colors,size,masks=0;
  if(info->bmiHeader.biSize==sizeof(BITMAPCOREHEADER)){
    const BITMAPCOREHEADER *core=(const BITMAPCOREHEADER *)info;
    colors=(core->bcBitCount<=8)?1<<core->bcBitCount:0;
    return sizeof(BITMAPCOREHEADER)+colors*((coloruse==DIB_RGB_COLORS)?sizeof(RGBTRIPLE):sizeof(WORD));
  }else{
    colors=info->bmiHeader.biClrUsed;
    if(colors>256)colors=256;
    if(!colors&&(info->bmiHeader.biBitCount<=8))
      colors=1<<info->bmiHeader.biBitCount;
    if(info->bmiHeader.biCompression==BI_BITFIELDS)
      masks=3;
    size=max(info->bmiHeader.biSize,sizeof(BITMAPINFOHEADER)+masks*sizeof(DWORD));
    return (size+colors*((coloruse==DIB_RGB_COLORS)?sizeof(RGBQUAD):sizeof(WORD)));
  }
}

UINT DIB_BitmapMaxBitsSize(PBITMAPINFO Info,UINT ScanLines){
  UINT Ret;
  if(!Info)return 0;
  if(Info->bmiHeader.biSize==sizeof(BITMAPCOREHEADER)){
    PBITMAPCOREHEADER Core=(PBITMAPCOREHEADER)Info;
    Ret=WIDTH_BYTES_ALIGN32(Core->bcWidth*Core->bcPlanes,Core->bcBitCount)*ScanLines;
  }else{
    if(!(Info->bmiHeader.biCompression)||(Info->bmiHeader.biCompression==BI_BITFIELDS))
      Ret=WIDTH_BYTES_ALIGN32(Info->bmiHeader.biWidth*Info->bmiHeader.biPlanes,Info->bmiHeader.biBitCount)*ScanLines;
    else
      Ret=Info->bmiHeader.biSizeImage;
  }
  return Ret;
}

INT WINAPI GetDIBits(HDC hDC,HBITMAP hbmp,UINT uStartScan,UINT cScanLines,LPVOID lpvBits,LPBITMAPINFO lpbmi,UINT uUsage){
  UINT cjBmpScanSize,cjInfoSize;
  if(!hDC||!lpbmi)
     return 0;
  cjBmpScanSize=DIB_BitmapMaxBitsSize(lpbmi,cScanLines);
  cjInfoSize=DIB_BitmapInfoSize(lpbmi,uUsage);
  if(lpvBits&&lpbmi->bmiHeader.biSize>=sizeof(BITMAPINFOHEADER)&&(lpbmi->bmiHeader.biCompression==BI_JPEG||lpbmi->bmiHeader.biCompression==BI_PNG))
    return 0;
  return _NtGdiGetDIBitsInternal(hDC,hbmp,uStartScan,cScanLines,lpvBits,lpbmi,uUsage,cjBmpScanSize,cjInfoSize);
}

HBITMAP WINAPI CreateCompatibleBitmap(HDC hDC,INT Width,INT Height){
  if(!hDC||!Width||!Height)return NULL;
  return (HBITMAP)_NtGdiCreateCompatibleBitmap(hDC,Width,Height);
}

HGDIOBJ WINAPI SelectObject(HDC hDC,HGDIOBJ hGdiObj){
  switch(GDI_HANDLE_GET_TYPE(hGdiObj)){
    case GDI_OBJECT_TYPE_REGION:
      return (HGDIOBJ)_NtGdiExtSelectClipRgn(hDC,hGdiObj,RGN_COPY);
    case GDI_OBJECT_TYPE_BITMAP:
      return (HGDIOBJ)_NtGdiSelectBitmap(hDC,hGdiObj);
    case GDI_OBJECT_TYPE_BRUSH:
      return (HGDIOBJ)_NtGdiSelectBrush(hDC,hGdiObj);
    case GDI_OBJECT_TYPE_PEN:
    case GDI_OBJECT_TYPE_EXTPEN:
      return (HGDIOBJ)_NtGdiSelectPen(hDC,hGdiObj);
    case GDI_OBJECT_TYPE_FONT:
      return (HGDIOBJ)_NtGdiSelectFont(hDC,hGdiObj);
    default:break;
  }
  return NULL;
}

BOOL WINAPI DeleteObject(HGDIOBJ hObject){
  if(!hObject)return FALSE;
  if(0!=((DWORD)hObject&GDI_HANDLE_STOCK_MASK))
    return TRUE;
  return _NtGdiDeleteObjectApp(hObject);
}

HWND WINAPI FindWindowExW(HWND hwndParent,HWND hwndChildAfter,LPCWSTR lpszClass,LPCWSTR lpszWindow){
  UNICODE_STRING ucClassName,ucWindowName;
  if(IS_ATOM(lpszClass)){
    ucClassName.Length=0;
    ucClassName.MaximumLength=0;
    ucClassName.Buffer=(LPWSTR)lpszClass;
  }else if(lpszClass!=NULL)
    RtlInitUnicodeString(&ucClassName,lpszClass);
  RtlInitUnicodeString(&ucWindowName,lpszWindow);
  return (HWND)_NtUserFindWindowEx(hwndParent,hwndChildAfter,&ucClassName,&ucWindowName,0);
}

HWND WINAPI FindWindowExA(HWND hwndParent,HWND hwndChildAfter,LPCSTR lpszClass,LPCSTR lpszWindow){
  WCHAR titleBuf[MAX_PATH],classW[MAX_PATH];
  LPWSTR titleW=NULL;
  if(lpszWindow){
    RtlMultiByteToUnicode(titleBuf,MAX_PATH,lpszWindow,(UINT)-1);
    titleW=titleBuf;
  }
  if(!IS_INTRESOURCE(lpszClass)){
    RtlMultiByteToUnicode(classW,MAX_PATH,lpszClass,(UINT)-1);
    return FindWindowExW(hwndParent,hwndChildAfter,classW,titleW);
  }
  return FindWindowExW(hwndParent,hwndChildAfter,(LPCWSTR)lpszClass,titleW);
}

HWND WINAPI FindWindowW(LPCWSTR lpClassName,LPCWSTR lpWindowName){
  return FindWindowExW(NULL,NULL,lpClassName,lpWindowName);
}

HWND WINAPI FindWindowA(LPCSTR lpClassName,LPCSTR lpWindowName){
  return FindWindowExA(NULL,NULL,lpClassName,lpWindowName);
}

// *******************************************************************************
// Drivers (for testing!!!)
// *******************************************************************************

static PCWSTR swDriverReg=L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
static LIST_ENTRY ServiceListHead={&ServiceListHead,&ServiceListHead};

static GENERIC_MAPPING ScmManagerMapping={
  SC_MANAGER_READ,
  SC_MANAGER_WRITE,
  SC_MANAGER_EXECUTE,
  SC_MANAGER_ALL_ACCESS
};

static GENERIC_MAPPING ScmServiceMapping={
  SERVICE_READ,
  SERVICE_WRITE,
  SERVICE_EXECUTE,
  SERVICE_ALL_ACCESS
};

PSERVICE ScmGetServiceEntryByName(LPCWSTR lpServiceName){
  PLIST_ENTRY ServiceEntry;PSERVICE CurrentService;
  UNICODE_STRING DirName;OBJECT_ATTRIBUTES ObjectAttributes;
  POBJECT_DIRECTORY_INFORMATION DirInfo;HANDLE DirHandle;
  ULONG BufferLength;BOOL bRunning=FALSE;ULONG DataLength;
  ULONG Index;NTSTATUS Status;DWORD dwSize=0;
  DWORD dwServiceType,dwStartType,dwErrorControl,dwFlag;
  LPWSTR lpDisplayName=NULL;HKEY hServicesKey,hServiceKey;
  PSERVICE lpService=NULL;BYTE kBuffer[256];
  UNICODE_STRING KeyName,ValueName;
  PKEY_VALUE_PARTIAL_INFORMATION pKVPI;

  ServiceEntry=ServiceListHead.Flink;
  while(ServiceEntry!=&ServiceListHead){
    CurrentService=CONTAINING_RECORD(ServiceEntry,SERVICE,ServiceListEntry);
    if(!_wcsicmp(CurrentService->lpServiceName,lpServiceName))
      return CurrentService;
    ServiceEntry=ServiceEntry->Flink;
  }

  RtlInitUnicodeString(&KeyName,swDriverReg);
  InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,NULL,NULL);
  Status=_NtOpenKey(&hServicesKey,KEY_READ,&ObjectAttributes);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    return NULL;
  }

  RtlInitUnicodeString(&KeyName,lpServiceName);
  InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,hServicesKey,NULL);
  Status=_NtOpenKey(&hServiceKey,KEY_READ,&ObjectAttributes);
  _NtClose(hServicesKey);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    return NULL;
  }

  dwSize=sizeof(DWORD)+FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data);
  pKVPI=(PKEY_VALUE_PARTIAL_INFORMATION)kBuffer;
  RtlInitUnicodeString(&ValueName,L"Type");
  Status=_NtQueryValueKey(hServiceKey,&ValueName,KeyValuePartialInformation,(PVOID)pKVPI,dwSize,&dwSize);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    _NtClose(hServiceKey);
    return NULL;
  }
  memcpy((PVOID)&dwServiceType,&pKVPI->Data,pKVPI->DataLength);

  if((dwServiceType!=SERVICE_KERNEL_DRIVER)&&(dwServiceType!=SERVICE_FILE_SYSTEM_DRIVER)){
    SetLastError(ERROR_BAD_ARGUMENTS);
    _NtClose(hServiceKey);
    return NULL;
  }

  dwSize=sizeof(DWORD)+FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data);
  pKVPI=(PKEY_VALUE_PARTIAL_INFORMATION)kBuffer;
  RtlInitUnicodeString(&ValueName,L"Start");
  Status=_NtQueryValueKey(hServiceKey,&ValueName,KeyValuePartialInformation,(PVOID)pKVPI,dwSize,&dwSize);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    _NtClose(hServiceKey);
    return NULL;
  }
  memcpy((PVOID)&dwStartType,&pKVPI->Data,pKVPI->DataLength);

  dwSize=sizeof(DWORD)+FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data);
  pKVPI=(PKEY_VALUE_PARTIAL_INFORMATION)kBuffer;
  RtlInitUnicodeString(&ValueName,L"ErrorControl");
  Status=_NtQueryValueKey(hServiceKey,&ValueName,KeyValuePartialInformation,(PVOID)pKVPI,dwSize,&dwSize);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    _NtClose(hServiceKey);
    return NULL;
  }
  memcpy((PVOID)&dwErrorControl,&pKVPI->Data,pKVPI->DataLength);

  dwSize=sizeof(DWORD)+FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data);
  pKVPI=(PKEY_VALUE_PARTIAL_INFORMATION)kBuffer;
  RtlInitUnicodeString(&ValueName,L"DeleteFlag");
  Status=_NtQueryValueKey(hServiceKey,&ValueName,KeyValuePartialInformation,(PVOID)pKVPI,dwSize,&dwSize);
  if(NT_SUCCESS(Status))
    memcpy((PVOID)&dwFlag,&pKVPI->Data,pKVPI->DataLength);
  else
    dwFlag=0;

  dwSize=sizeof(kBuffer);
  pKVPI=(PKEY_VALUE_PARTIAL_INFORMATION)kBuffer;
  RtlInitUnicodeString(&ValueName,L"DisplayName");
  Status=_NtQueryValueKey(hServiceKey,&ValueName,KeyValuePartialInformation,(PVOID)pKVPI,dwSize,&dwSize);
  if(NT_SUCCESS(Status) || Status==STATUS_BUFFER_OVERFLOW){
    if(Status==STATUS_BUFFER_OVERFLOW){
      pKVPI=(PKEY_VALUE_PARTIAL_INFORMATION)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,dwSize);
      if(pKVPI==NULL){
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        _NtClose(hServiceKey);
        return NULL;
      }

      Status=_NtQueryValueKey(hServiceKey,&ValueName,KeyValuePartialInformation,(PVOID)pKVPI,dwSize,&dwSize);
      if(!NT_SUCCESS(Status)){
        RtlFreeHeap(RtlGetProcessHeap(),0,pKVPI);
        SetLastError(RtlNtStatusToDosError(Status));
        _NtClose(hServiceKey);
        return NULL;
      }
    }

    lpDisplayName=(LPWSTR)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,pKVPI->DataLength+1*sizeof(WCHAR));
    if(lpDisplayName==NULL){
      if(pKVPI!=(PKEY_VALUE_PARTIAL_INFORMATION)kBuffer)
        RtlFreeHeap(RtlGetProcessHeap(),0,pKVPI);
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      _NtClose(hServiceKey);
      return NULL;
    }

    memcpy((PVOID)lpDisplayName,&pKVPI->Data,pKVPI->DataLength);
    lpDisplayName[pKVPI->DataLength]=0;
    if(pKVPI!=(PKEY_VALUE_PARTIAL_INFORMATION)kBuffer)
      RtlFreeHeap(RtlGetProcessHeap(),0,pKVPI);
  }

  _NtClose(hServiceKey);

  if(dwServiceType==SERVICE_KERNEL_DRIVER)
    RtlInitUnicodeString(&DirName, L"\\Driver");
  else
    RtlInitUnicodeString(&DirName, L"\\FileSystem");

  InitializeObjectAttributes(&ObjectAttributes,&DirName,0,NULL,NULL);
  Status=_NtOpenDirectoryObject(&DirHandle,DIRECTORY_QUERY|DIRECTORY_TRAVERSE,&ObjectAttributes);
  if(!NT_SUCCESS(Status)){
    if(lpDisplayName!=NULL)
      RtlFreeHeap(RtlGetProcessHeap(),0,lpDisplayName);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  BufferLength=sizeof(OBJECT_DIRECTORY_INFORMATION)+2*MAX_PATH*sizeof(WCHAR);
  DirInfo=(POBJECT_DIRECTORY_INFORMATION)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,BufferLength);
  if(DirInfo==NULL){
    if(lpDisplayName!=NULL)
      RtlFreeHeap(RtlGetProcessHeap(),0,lpDisplayName);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  Index=0;
  while(TRUE){
    Status=_NtQueryDirectoryObject(DirHandle,DirInfo,BufferLength,TRUE,FALSE,&Index,&DataLength);
    if(!NT_SUCCESS(Status)||Status==STATUS_NO_MORE_ENTRIES)
      break;
    if(!_wcsicmp(lpServiceName,DirInfo->Name.Buffer)){
      bRunning=TRUE;
      break;
    }
  }
  RtlFreeHeap(RtlGetProcessHeap(),0,DirInfo);
  _NtClose(DirHandle);

  lpService=(PSERVICE)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,
    FIELD_OFFSET(SERVICE,szServiceName[wcslen(lpServiceName) + 1]));
  if(!lpService){
    if(lpDisplayName!=NULL)
      RtlFreeHeap(RtlGetProcessHeap(),0,lpDisplayName);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  wcscpy(lpService->szServiceName,lpServiceName);
  lpService->lpServiceName=lpService->szServiceName;
  if(lpDisplayName!=NULL)
    lpService->lpDisplayName=lpDisplayName;
  else
    lpService->lpDisplayName=lpService->szServiceName;
  lpService->dwResumeCount=1;
  lpService->Status.dwCurrentState=(bRunning) ? ((dwFlag) ? SERVICE_STOP_PENDING : SERVICE_RUNNING) : SERVICE_STOPPED;
  lpService->Status.dwControlsAccepted=0;
  lpService->Status.dwWin32ExitCode=ERROR_SERVICE_NEVER_STARTED;
  lpService->Status.dwServiceSpecificExitCode=0;
  lpService->Status.dwCheckPoint=0;
  lpService->Status.dwWaitHint=2000;
  lpService->Status.dwServiceType=dwServiceType;
  lpService->dwStartType=dwStartType;
  lpService->dwErrorControl=dwErrorControl;
  lpService->bDeleted=dwFlag;
  InsertTailList(&ServiceListHead,&lpService->ServiceListEntry);
  return lpService;
}

BOOL WINAPI StartServiceA(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR *lpServiceArgVectors){
  PSERVICE_HANDLE hSvc;PSERVICE lpService=NULL;LPWSTR *lpVector=NULL;
  DWORD i,dwLength;NTSTATUS Status=STATUS_SUCCESS;
  BOOLEAN WasPrivilegeEnabled=FALSE;BOOL bRet=FALSE;
  PWSTR pszDriverPath;UNICODE_STRING DriverPath;
  hSvc=(PSERVICE_HANDLE)hService;
  if(hSvc->Handle.Tag!=SERVICE_TAG){
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  if(!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,SERVICE_START)){
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
  }
  lpService=hSvc->ServiceEntry;
  if(lpService == NULL){
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  if(lpService->dwStartType == SERVICE_DISABLED){
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
  }
  if(lpService->bDeleted){
    SetLastError(ERROR_SERVICE_MARKED_FOR_DELETE);
    return FALSE;
  }
  if(dwNumServiceArgs > 0){
    lpVector=(LPWSTR*)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,dwNumServiceArgs * sizeof(LPWSTR));
    if(lpVector==NULL){
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      return FALSE;
    }
    for(i=0;i<dwNumServiceArgs;i++){
      dwLength=RtlMultiByteToUnicode(NULL,0,((LPSTR*)lpServiceArgVectors)[i],-1);
      lpVector[i]=(LPWSTR)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,dwLength*sizeof(WCHAR));
      if(lpVector[i] == NULL){
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto done;
      }
      RtlMultiByteToUnicode(lpVector[i],dwLength,((LPSTR*)lpServiceArgVectors)[i],-1);
    }
  }

  if(lpService->Status.dwCurrentState!=SERVICE_STOPPED){
    SetLastError(ERROR_SERVICE_ALREADY_RUNNING);
    return FALSE;
  }
  if(!(lpService->Status.dwServiceType & SERVICE_DRIVER)){
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  // 52=wcslen(swDriverReg)
  pszDriverPath=(PWSTR)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,
    (52+wcslen(lpService->lpServiceName)+1) * sizeof(WCHAR));
  if(pszDriverPath==NULL){
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }
  wcscpy(pszDriverPath,swDriverReg);
  wcscat(pszDriverPath,lpService->lpServiceName);
  RtlInitUnicodeString(&DriverPath,pszDriverPath);
  Status=RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,TRUE,FALSE,&WasPrivilegeEnabled);
  if(!NT_SUCCESS(Status)){
    RtlFreeHeap(RtlGetProcessHeap(),0,pszDriverPath);
    SetLastError(RtlNtStatusToDosError(Status));
    return FALSE;
  }
  Status=_NtLoadDriver(&DriverPath);
  RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,WasPrivilegeEnabled,FALSE,&WasPrivilegeEnabled);
  RtlFreeHeap(RtlGetProcessHeap(),0,pszDriverPath);

  if(NT_SUCCESS(Status)){
    lpService->Status.dwControlsAccepted=SERVICE_ACCEPT_STOP;
    lpService->Status.dwCurrentState=SERVICE_RUNNING;
    PSERVICE_GROUP Group=lpService->lpGroup;
    if(Group!=NULL)
      Group->ServicesRunning=TRUE;
    bRet=TRUE;
  }else{
    SetLastError(RtlNtStatusToDosError(Status));
  }

done:
  if(lpVector!=NULL){
    for (i=0; i < dwNumServiceArgs; i++)
      if(lpVector[i]!=NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, lpVector[i]);
    RtlFreeHeap(RtlGetProcessHeap(), 0, lpVector);
  }
  return bRet;
}

BOOL WINAPI ControlService(SC_HANDLE hService,DWORD dwControl,LPSERVICE_STATUS lpServiceStatus){
  PSERVICE_HANDLE hSvc;PSERVICE lpService;ACCESS_MASK DesiredAccess;
  OBJECT_ATTRIBUTES ObjectAttributes;UNICODE_STRING DirName;
  HANDLE DirHandle;NTSTATUS Status=STATUS_SUCCESS;
  POBJECT_DIRECTORY_INFORMATION DirInfo;
  ULONG BufferLength,DataLength,Index;BOOLEAN bFound=FALSE;

  BOOLEAN WasPrivilegeEnabled=FALSE;
  PWSTR pszDriverPath;UNICODE_STRING DriverPath;

  hSvc=(PSERVICE_HANDLE)hService;
  if(hSvc->Handle.Tag!=SERVICE_TAG){
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  lpService=hSvc->ServiceEntry;
  if(lpService == NULL){
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  switch(dwControl){
    case SERVICE_CONTROL_STOP:
      DesiredAccess=SERVICE_STOP;
    break;
    case SERVICE_CONTROL_PAUSE:
    case SERVICE_CONTROL_CONTINUE:
      DesiredAccess=SERVICE_PAUSE_CONTINUE;
    break;
    case SERVICE_CONTROL_INTERROGATE:
      DesiredAccess=SERVICE_INTERROGATE;
    break;
    default:
      if(dwControl>=128&&dwControl<=255)
        DesiredAccess=SERVICE_USER_DEFINED_CONTROL;
      else{
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
      }
    break;
  }
  if(!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,DesiredAccess)){
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
  }
  if(!(lpService->Status.dwServiceType & SERVICE_DRIVER)){
    SetLastError(ERROR_BAD_ARGUMENTS);
    return FALSE;
  }
  switch(dwControl){
    case SERVICE_CONTROL_STOP:
      RtlCopyMemory(lpServiceStatus,&lpService->Status,sizeof(SERVICE_STATUS));
      if(lpService->Status.dwCurrentState!=SERVICE_RUNNING){
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
      }
      // 52=wcslen(swDriverReg)
      pszDriverPath=(PWSTR)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,
        (52+wcslen(lpService->lpServiceName)+1) * sizeof(WCHAR));
      if(pszDriverPath==NULL){
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
      }
      wcscpy(pszDriverPath,swDriverReg);
      wcscat(pszDriverPath,lpService->lpServiceName);
      RtlInitUnicodeString(&DriverPath,pszDriverPath);
      Status=RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,TRUE,FALSE,&WasPrivilegeEnabled);
      if(!NT_SUCCESS(Status)){
        RtlFreeHeap(RtlGetProcessHeap(),0,pszDriverPath);
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
      }
      Status=_NtUnloadDriver(&DriverPath);
      RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,WasPrivilegeEnabled,FALSE,&WasPrivilegeEnabled);
      RtlFreeHeap(RtlGetProcessHeap(),0,pszDriverPath);
      if(NT_SUCCESS(Status)){
        lpService->Status.dwControlsAccepted=0;
        lpService->Status.dwCurrentState=SERVICE_STOPPED;
        return TRUE;
      }
    break;
    case SERVICE_CONTROL_INTERROGATE:
      memset(lpServiceStatus, 0, sizeof(SERVICE_STATUS));
      if(lpService->Status.dwServiceType == SERVICE_KERNEL_DRIVER)
        RtlInitUnicodeString(&DirName, L"\\Driver");
      else
        RtlInitUnicodeString(&DirName, L"\\FileSystem");
      InitializeObjectAttributes(&ObjectAttributes,&DirName,0,NULL,NULL);
      Status=_NtOpenDirectoryObject(&DirHandle,DIRECTORY_QUERY|DIRECTORY_TRAVERSE,&ObjectAttributes);
      if(!NT_SUCCESS(Status)){
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
      }
      BufferLength=sizeof(OBJECT_DIRECTORY_INFORMATION)+2*MAX_PATH*sizeof(WCHAR);
      DirInfo=(OBJECT_DIRECTORY_INFORMATION*) RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,BufferLength);
      Index=0;
      while(TRUE){
        Status=_NtQueryDirectoryObject(DirHandle,DirInfo,BufferLength,TRUE,FALSE,&Index,&DataLength);
        if(Status==STATUS_NO_MORE_ENTRIES)
          break;
        if(!NT_SUCCESS(Status))
          break;
        if(_wcsicmp(lpService->lpServiceName, DirInfo->Name.Buffer) == 0){
          bFound=TRUE;
          break;
        }
      }
      RtlFreeHeap(RtlGetProcessHeap(),0,DirInfo);
      _NtClose(DirHandle);
      if(!NT_SUCCESS(Status)){
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
      }
      if((bFound==TRUE)&&(lpService->Status.dwCurrentState!=SERVICE_STOP_PENDING)){
        if(lpService->Status.dwCurrentState == SERVICE_STOPPED){
          lpService->Status.dwWin32ExitCode=ERROR_SUCCESS;
          lpService->Status.dwServiceSpecificExitCode=ERROR_SUCCESS;
          lpService->Status.dwCheckPoint=0;
          lpService->Status.dwWaitHint=0;
          lpService->Status.dwControlsAccepted=0;
        }else{
          lpService->Status.dwCurrentState=SERVICE_RUNNING;
          lpService->Status.dwControlsAccepted=SERVICE_ACCEPT_STOP;
          if(lpService->Status.dwWin32ExitCode == ERROR_SERVICE_NEVER_STARTED)
            lpService->Status.dwWin32ExitCode=ERROR_SUCCESS;
        }
      }else{
        lpService->Status.dwCurrentState=SERVICE_STOPPED;
        lpService->Status.dwControlsAccepted=0;
        lpService->Status.dwCheckPoint=0;
        lpService->Status.dwWaitHint=0;
        if(lpService->Status.dwCurrentState==SERVICE_STOP_PENDING)
          lpService->Status.dwWin32ExitCode=ERROR_SUCCESS;
        else
          lpService->Status.dwWin32ExitCode=ERROR_GEN_FAILURE;
      }
      if(lpServiceStatus!=NULL)
        memcpy(lpServiceStatus,&lpService->Status,sizeof(SERVICE_STATUS));
      return TRUE;
    default:
      SetLastError(ERROR_BAD_ARGUMENTS);
      return FALSE;
  }
  return FALSE;
}

BOOL WINAPI QueryServiceStatusEx(SC_HANDLE hService,SC_STATUS_TYPE InfoLevel,
  LPBYTE lpBuffer,DWORD cbBufSize,LPDWORD pcbBytesNeeded){
  LPSERVICE_STATUS_PROCESS lpStatus;
  PSERVICE_HANDLE hSvc;PSERVICE lpService;
  if(InfoLevel!=SC_STATUS_PROCESS_INFO)
    return FALSE;
  *pcbBytesNeeded=sizeof(SERVICE_STATUS_PROCESS);
  if(cbBufSize < sizeof(SERVICE_STATUS_PROCESS))
    return FALSE;
  hSvc=(PSERVICE_HANDLE)hService;
  if(hSvc->Handle.Tag!=SERVICE_TAG)
    return FALSE;
  if(!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,SERVICE_QUERY_STATUS))
    return FALSE;
  lpService=hSvc->ServiceEntry;
  if(lpService == NULL)
    return FALSE;
  lpStatus=(LPSERVICE_STATUS_PROCESS)lpBuffer;
  RtlCopyMemory(lpStatus,&lpService->Status,sizeof(SERVICE_STATUS));
  lpStatus->dwProcessId=(lpService->lpImage!=NULL) ? lpService->lpImage->dwProcessId : 0;
  lpStatus->dwServiceFlags=0;
  return TRUE;
}

SC_HANDLE WINAPI OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess){
  SC_HANDLE hScm=NULL;
  if(lpMachineName!=NULL)
    return NULL;
  if(lpDatabaseName!=NULL)
    return NULL;
  PMANAGER_HANDLE Ptr=(PMANAGER_HANDLE)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,
    FIELD_OFFSET(MANAGER_HANDLE,DatabaseName[wcslen(SERVICES_ACTIVE_DATABASEW)+1]));
  if(Ptr!=NULL){
    Ptr->Handle.Tag=MANAGER_TAG;
    wcscpy(Ptr->DatabaseName,SERVICES_ACTIVE_DATABASEW);
    RtlMapGenericMask(&dwDesiredAccess,&ScmManagerMapping);
    Ptr->Handle.DesiredAccess=dwDesiredAccess|SC_MANAGER_CONNECT;
    hScm=(SC_HANDLE)Ptr;
  }
  return hScm;
}

BOOL WINAPI CloseServiceHandle(SC_HANDLE hSCObject){
  HKEY hServicesKey,hSubKey,hDelKey;NTSTATUS Status;
  UNICODE_STRING KeyName;OBJECT_ATTRIBUTES ObjectAttributes;
  PKEY_BASIC_INFORMATION KeyInfo;

  if(!hSCObject)
    return FALSE;
  if(((PMANAGER_HANDLE)hSCObject)->Handle.Tag==MANAGER_TAG){
    RtlFreeHeap(RtlGetProcessHeap(),0,hSCObject);
    return TRUE;
  }
  if(((PSERVICE_HANDLE)hSCObject)->Handle.Tag==SERVICE_TAG){
    PSERVICE lpService=((PSERVICE_HANDLE)hSCObject)->ServiceEntry;
    RtlFreeHeap(RtlGetProcessHeap(),0,hSCObject);
    lpService->dwRefCount--;
    if(lpService->dwRefCount == 0){
      if(lpService->bDeleted){

        RtlInitUnicodeString(&KeyName,swDriverReg);
        InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,NULL,NULL);
        Status=_NtOpenKey(&hServicesKey,KEY_SET_VALUE|KEY_READ|KEY_ENUMERATE_SUB_KEYS|KEY_QUERY_VALUE,&ObjectAttributes);
        if(!NT_SUCCESS(Status)){
          SetLastError(RtlNtStatusToDosError(Status));
          return FALSE;
        }

        RtlInitUnicodeString(&KeyName,lpService->lpServiceName);
        InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,hServicesKey,NULL);
        Status=_NtOpenKey(&hDelKey,DELETE,&ObjectAttributes);
        if(NT_SUCCESS(Status)){
          Status=_NtDeleteKey(hDelKey);
          _NtClose(hDelKey);
        }

        if(!NT_SUCCESS(Status)){
          RtlInitUnicodeString(&KeyName,lpService->lpServiceName);
          InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,hServicesKey,NULL);
          Status=_NtOpenKey(&hSubKey,KEY_READ,&ObjectAttributes);
          if(!NT_SUCCESS(Status)){
            SetLastError(RtlNtStatusToDosError(Status));
            _NtClose(hServicesKey);
            return FALSE;
          }

          DWORD dwSize=sizeof(KEY_BASIC_INFORMATION)+MAX_PATH*sizeof(WCHAR);
          CHAR szBuffer[sizeof(KEY_BASIC_INFORMATION)+MAX_PATH*sizeof(WCHAR)];
          KeyInfo=(PKEY_BASIC_INFORMATION)szBuffer;
          Status=_NtEnumerateKey(hSubKey,0,KeyBasicInformation,KeyInfo,dwSize,&dwSize);
          if(NT_SUCCESS(Status)){
            do{
              KeyInfo->Name[KeyInfo->NameLength/sizeof(WCHAR)]=0;
              RtlInitUnicodeString(&KeyName,KeyInfo->Name);
              InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,hSubKey,NULL);
              Status=_NtOpenKey(&hDelKey,DELETE,&ObjectAttributes);
              if(!NT_SUCCESS(Status))
                break;
              Status=_NtDeleteKey(hDelKey);
              _NtClose(hDelKey);
              if(!NT_SUCCESS(Status))
                break;

              dwSize=sizeof(KEY_BASIC_INFORMATION)+MAX_PATH;
              Status=_NtEnumerateKey(hSubKey,0,KeyBasicInformation,KeyInfo,dwSize,&dwSize);
            }while(NT_SUCCESS(Status));
          }
          _NtClose(hSubKey);

          RtlInitUnicodeString(&KeyName,lpService->lpServiceName);
          InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,hServicesKey,NULL);
          Status=_NtOpenKey(&hDelKey,DELETE,&ObjectAttributes);
          if(!NT_SUCCESS(Status)){
            _NtClose(hServicesKey);
            return FALSE;
          }
          Status=_NtDeleteKey(hDelKey);
          _NtClose(hDelKey);
          if(!NT_SUCCESS(Status)){
            _NtClose(hServicesKey);
            return FALSE;
          }
        }
        _NtClose(hServicesKey);

        if(lpService->lpDisplayName!=NULL&&lpService->lpDisplayName!=lpService->lpServiceName)
          RtlFreeHeap(RtlGetProcessHeap(),0,lpService->lpDisplayName);
        if(lpService->lpImage){
          lpService->lpImage->dwImageRunCount--;
          if(lpService->lpImage->dwImageRunCount==0){
            RemoveEntryList(&lpService->lpImage->ImageListEntry);
            if(lpService->lpImage->hControlPipe!=INVALID_HANDLE_VALUE)
              CloseHandle(lpService->lpImage->hControlPipe);
            RtlFreeHeap(RtlGetProcessHeap(),0,lpService->lpImage);
          }
        }
        if(lpService->lpGroup)
          lpService->lpGroup->dwRefCount--;
        RemoveEntryList(&lpService->ServiceListEntry);
        RtlFreeHeap(RtlGetProcessHeap(),0,lpService);
      }
    }
    return TRUE;
  }
  return FALSE;
}

SC_HANDLE WINAPI OpenServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess){
  PSERVICE_HANDLE hService=NULL;UNICODE_STRING ServiceName;
  PSERVICE lpService;

  if(!hSCManager||!lpServiceName)
    return NULL;

  if(((PMANAGER_HANDLE)hSCManager)->Handle.Tag!=MANAGER_TAG){
    SetLastError(ERROR_INVALID_HANDLE);
    return NULL;
  }

  RtlCreateUnicodeStringFromAsciiz(&ServiceName,lpServiceName);
  lpService=ScmGetServiceEntryByName(ServiceName.Buffer);
  if(lpService==NULL){
    SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
    return NULL;
  }

  hService=(PSERVICE_HANDLE)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(SERVICE_HANDLE));
  if(hService == NULL){
    if(lpService->lpDisplayName!=NULL)
      RtlFreeHeap(RtlGetProcessHeap(),0,lpService->lpDisplayName);
    RtlFreeHeap(RtlGetProcessHeap(),0,lpService);
    RtlFreeUnicodeString(&ServiceName);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  hService->Handle.Tag=SERVICE_TAG;
  hService->ServiceEntry=lpService;
  RtlMapGenericMask(&dwDesiredAccess,&ScmServiceMapping);
  hService->Handle.DesiredAccess=dwDesiredAccess;

  RtlFreeUnicodeString(&ServiceName);

  lpService->dwRefCount++;
  return (SC_HANDLE)hService;
}

SC_HANDLE WINAPI CreateServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,
  DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,
  LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,
  LPCSTR lpServiceStartName,LPCSTR lpPassword){

  UNICODE_STRING ServiceName,DisplayName,BinaryPathName;
  DWORD dwError=ERROR_SUCCESS;PMANAGER_HANDLE hManager;LPWSTR lpImagePath=NULL;
  PSERVICE lpService=NULL;PSERVICE_HANDLE hServiceHandle=NULL;
  HKEY hServicesKey=NULL,hServiceKey=NULL;NTSTATUS Status;
  UNICODE_STRING KeyName,ValueName;OBJECT_ATTRIBUTES ObjectAttributes;
  const WCHAR *SourceName;UINT ServiceNameLen;

  if(!hSCManager)
    return NULL;
  if(lpDependencies!=NULL||lpLoadOrderGroup!=NULL||lpdwTagId!=NULL||lpServiceStartName!=NULL||lpPassword!=NULL){
    SetLastError(ERROR_BAD_ARGUMENTS);
    return NULL;
  }
  if(!(dwServiceType & SERVICE_DRIVER)){
    SetLastError(ERROR_BAD_ARGUMENTS);
    return NULL;
  }
  if (dwStartType == SERVICE_BOOT_START){
    SetLastError(ERROR_BAD_ARGUMENTS);
    return NULL;
  }
  if(!lpServiceName||!lpBinaryPathName){
    SetLastError(ERROR_BAD_ARGUMENTS);
    return NULL;
  }

  if((dwServiceType!=SERVICE_KERNEL_DRIVER) &&
    (dwServiceType!=SERVICE_FILE_SYSTEM_DRIVER) &&
    ((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS)!=SERVICE_WIN32_OWN_PROCESS) &&
    ((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS)!=SERVICE_WIN32_SHARE_PROCESS)){
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
  }

  if((dwStartType!=SERVICE_BOOT_START) &&
    (dwStartType!=SERVICE_SYSTEM_START) &&
    (dwStartType!=SERVICE_AUTO_START) &&
    (dwStartType!=SERVICE_DEMAND_START) &&
    (dwStartType!=SERVICE_DISABLED)){
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
  }

  if(((dwStartType==SERVICE_BOOT_START) || (dwStartType==SERVICE_SYSTEM_START)) &&
    ((dwServiceType!=SERVICE_KERNEL_DRIVER) && (dwServiceType!=SERVICE_FILE_SYSTEM_DRIVER))){
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
  }

  if((dwErrorControl!=SERVICE_ERROR_IGNORE) &&
    (dwErrorControl!=SERVICE_ERROR_NORMAL) &&
    (dwErrorControl!=SERVICE_ERROR_SEVERE) &&
    (dwErrorControl!=SERVICE_ERROR_CRITICAL)){
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
  }

  if((dwServiceType == (SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS)) && (lpServiceStartName)){
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
  }

  RtlCreateUnicodeStringFromAsciiz(&ServiceName,lpServiceName);
  RtlCreateUnicodeStringFromAsciiz(&BinaryPathName,lpBinaryPathName);
  if(lpDisplayName)
    RtlCreateUnicodeStringFromAsciiz(&DisplayName,lpDisplayName);

  if(((PMANAGER_HANDLE)hSCManager)->Handle.Tag!=MANAGER_TAG){
    SetLastError(ERROR_INVALID_HANDLE);
    goto cleanup;
  }

  hManager=(PMANAGER_HANDLE)hSCManager;
  if(!RtlAreAllAccessesGranted(hManager->Handle.DesiredAccess,SC_MANAGER_CREATE_SERVICE)){
    SetLastError(ERROR_ACCESS_DENIED);
    goto cleanup;
  }

  lpService=ScmGetServiceEntryByName(ServiceName.Buffer);
  if(lpService){
    if(lpService->bDeleted){
      SetLastError(ERROR_SERVICE_MARKED_FOR_DELETE);
      goto cleanup;
    }
    SetLastError(ERROR_SERVICE_EXISTS);
    goto cleanup;
  }

  SourceName=BinaryPathName.Buffer;
  ServiceNameLen=wcslen(BinaryPathName.Buffer);
  if (ServiceNameLen > 12 && !_wcsnicmp(L"\\SystemRoot\\", SourceName, 12)){
    lpImagePath=(WCHAR*)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,(ServiceNameLen + 1) * sizeof(WCHAR));
    if (lpImagePath == NULL){
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      goto cleanup;
    }
    if (dwStartType == SERVICE_BOOT_START)
      SourceName += 12;
    wcscpy(lpImagePath, SourceName);
  }else
  if (ServiceNameLen > 13 &&!_wcsnicmp(L"%SystemRoot%\\", SourceName, 13)){
    lpImagePath=(WCHAR*)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,(ServiceNameLen + 1) * sizeof(WCHAR));
    if (lpImagePath == NULL){
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      goto cleanup;
    }
    if (dwStartType == SERVICE_BOOT_START)
      wcscpy(lpImagePath, L"\\SystemRoot\\");
    wcscat(lpImagePath, SourceName + 13);
  }else if (SourceName[0] != L'\\' && SourceName[1] != L':'){
    lpImagePath=(WCHAR*)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,(ServiceNameLen + 1) * sizeof(WCHAR));
    if (lpImagePath == NULL){
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      goto cleanup;
    }
    wcscpy(lpImagePath,SourceName);
  }else{
    UNICODE_STRING NtServiceName, Tmp;
    RtlInitUnicodeString(&Tmp,SourceName);
    if(!NT_SUCCESS(RtlDosPathNameToNtPathName(&Tmp, &NtServiceName, NULL))){
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      goto cleanup;
    }
    lpImagePath=NtServiceName.Buffer;
  }

  lpService=(PSERVICE)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,
    FIELD_OFFSET(SERVICE,szServiceName[wcslen(ServiceName.Buffer) + 1]));
  if(!lpService){
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    goto cleanup;
  }

  wcscpy(lpService->szServiceName,ServiceName.Buffer);
  lpService->lpServiceName=lpService->szServiceName;
  if(lpDisplayName!=NULL && *lpDisplayName!=0 && _wcsicmp(ServiceName.Buffer, DisplayName.Buffer)!=0){
    lpService->lpDisplayName=(PWCHAR)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,
      (wcslen(DisplayName.Buffer)+1) * sizeof(WCHAR));
    wcscpy(lpService->lpDisplayName, DisplayName.Buffer);
  }else
    lpService->lpDisplayName=lpService->lpServiceName;
  lpService->dwResumeCount=1;
  lpService->Status.dwCurrentState=SERVICE_STOPPED;
  lpService->Status.dwControlsAccepted=0;
  lpService->Status.dwWin32ExitCode=ERROR_SERVICE_NEVER_STARTED;
  lpService->Status.dwServiceSpecificExitCode=0;
  lpService->Status.dwCheckPoint=0;
  lpService->Status.dwWaitHint=2000;
  lpService->Status.dwServiceType=dwServiceType;
  lpService->dwStartType=dwStartType;
  lpService->dwErrorControl=dwErrorControl;
  InsertTailList(&ServiceListHead,&lpService->ServiceListEntry);

  RtlInitUnicodeString(&KeyName,swDriverReg);
  InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,NULL,NULL);
  Status=_NtOpenKey(&hServicesKey,KEY_READ|KEY_CREATE_SUB_KEY,&ObjectAttributes);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    goto cleanup;
  }

  InitializeObjectAttributes(&ObjectAttributes,&ServiceName,OBJ_CASE_INSENSITIVE,hServicesKey,NULL);
  Status=_NtCreateKey(&hServiceKey,KEY_WRITE,&ObjectAttributes,0,NULL,REG_OPTION_NON_VOLATILE,NULL);
  _NtClose(hServicesKey);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    goto cleanup;
  }

  if(lpDisplayName!=NULL&&*lpDisplayName!=0){
    RtlInitUnicodeString(&ValueName,L"DisplayName");
    Status=_NtSetValueKey(hServiceKey,&ValueName,0,REG_SZ,(PVOID)DisplayName.Buffer,(DWORD)(DisplayName.Length+sizeof(WCHAR)));
    if(!NT_SUCCESS(Status)){
      SetLastError(RtlNtStatusToDosError(Status));
      goto cleanup;
    }
  }

  RtlInitUnicodeString(&ValueName,L"ImagePath");
  Status=_NtSetValueKey(hServiceKey,&ValueName,0,REG_EXPAND_SZ,(PVOID)lpImagePath,(DWORD)((wcslen(lpImagePath)+1)*sizeof(WCHAR)));
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    goto cleanup;
  }

  RtlInitUnicodeString(&ValueName,L"Type");
  Status=_NtSetValueKey(hServiceKey,&ValueName,0,REG_DWORD,(PVOID)&dwServiceType,sizeof(DWORD));
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    goto cleanup;
  }

  RtlInitUnicodeString(&ValueName,L"Start");
  Status=_NtSetValueKey(hServiceKey,&ValueName,0,REG_DWORD,(PVOID)&dwStartType,sizeof(DWORD));
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    goto cleanup;
  }

  RtlInitUnicodeString(&ValueName,L"ErrorControl");
  Status=_NtSetValueKey(hServiceKey,&ValueName,0,REG_DWORD,(PVOID)&dwErrorControl,sizeof(DWORD));
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    goto cleanup;
  }

  hServiceHandle=(PSERVICE_HANDLE)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(SERVICE_HANDLE));
  if(hServiceHandle == NULL){
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    goto cleanup;
  }

  hServiceHandle->Handle.Tag=SERVICE_TAG;
  hServiceHandle->ServiceEntry=lpService;
  RtlMapGenericMask(&dwDesiredAccess,&ScmServiceMapping);
  hServiceHandle->Handle.DesiredAccess=dwDesiredAccess;
  lpService->dwRefCount=1;

cleanup:

  if(hServiceKey!=NULL)
    _NtClose(hServiceKey);

  if(hServiceHandle==NULL){
    if(lpService!=NULL){
      if(lpService->lpDisplayName!=NULL && lpService->lpServiceName!=lpService->lpDisplayName)
        RtlFreeHeap(RtlGetProcessHeap(), 0, lpService->lpDisplayName);
      RemoveTailList(&lpService->ServiceListEntry);
      RtlFreeHeap(RtlGetProcessHeap(), 0, lpService);
    }
    if(lpImagePath!=NULL)
      RtlFreeHeap(RtlGetProcessHeap(), 0, lpImagePath);
  }

  RtlFreeUnicodeString(&ServiceName);
  RtlFreeUnicodeString(&BinaryPathName);
  if(lpDisplayName)
    RtlFreeUnicodeString(&DisplayName);

  if(dwError!=ERROR_SUCCESS)
    return NULL;
  return (SC_HANDLE)hServiceHandle;
}

BOOL WINAPI DeleteService(SC_HANDLE hService){
  PSERVICE_HANDLE hSvc;PSERVICE lpService;
  HKEY hServicesKey=NULL,hServiceKey=NULL;
  DWORD dwValue=1;NTSTATUS Status;
  UNICODE_STRING KeyName,ValueName;
  OBJECT_ATTRIBUTES ObjectAttributes;

  if(((PSERVICE_HANDLE)hService)->Handle.Tag!=SERVICE_TAG){
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }

  hSvc=(PSERVICE_HANDLE)hService;
  if(!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,DELETE)){
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
  }

  lpService=hSvc->ServiceEntry;
  if(lpService == NULL){
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  if(lpService->bDeleted){
    SetLastError(ERROR_SERVICE_MARKED_FOR_DELETE);
    return FALSE;
  }
  lpService->bDeleted=TRUE;

  RtlInitUnicodeString(&KeyName,swDriverReg);
  InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,NULL,NULL);
  Status=_NtOpenKey(&hServicesKey,KEY_READ|KEY_CREATE_SUB_KEY,&ObjectAttributes);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    return FALSE;
  }

  RtlInitUnicodeString(&KeyName,lpService->lpServiceName);
  InitializeObjectAttributes(&ObjectAttributes,&KeyName,OBJ_CASE_INSENSITIVE,hServicesKey,NULL);
  Status=_NtOpenKey(&hServiceKey,KEY_WRITE,&ObjectAttributes);
  _NtClose(hServicesKey);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    return FALSE;
  }

  RtlInitUnicodeString(&ValueName,L"DeleteFlag");
  Status=_NtSetValueKey(hServiceKey,&ValueName,0,REG_DWORD,(PVOID)&dwValue,sizeof(DWORD));
  _NtClose(hServiceKey);
  if(!NT_SUCCESS(Status)){
    SetLastError(RtlNtStatusToDosError(Status));
    return FALSE;
  }

  return TRUE;
}
