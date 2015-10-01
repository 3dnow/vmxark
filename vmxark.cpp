// vmxark.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "malloc.h"	
#include "stdlib.h"

#include <Dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")

typedef struct ENUMVMX{
	CHAR VmxDisplayName[200];
	WCHAR VmxName[MAX_PATH];
	ULONG MemSizeInMB ; 
	CHAR OsType[200];
	WCHAR vmemPath[MAX_PATH];
	ULONG vmpid ; 
	HANDLE vmprochandle ;
	ULONG vmmdescnum;
	PVOID vmmdes ; 
	BOOL Freezed ; 
	BOOL PaeEnable ; 
	ULONG DirBase ; 
}ENUMVMX , *PENUMVMX;
PVOID EnumVmx , GetVmxInfo , CleanupVmx , writeva , readva , FreezeVmx , ThawVmx ; 
PVOID GetPhyAddr ,readpa ; 
PVOID pOfflineVmm = NULL ; 
BOOL getpa(ULONG vmi , ULONG Addr , PULONG phyaddr)
{
	BOOL bret ; 
	__asm
	{
		push pOfflineVmm
		push phyaddr
		push Addr
		push vmi 
		call GetPhyAddr
		mov bret, eax
	}

	return bret ; 
}
BOOL readpmem(ULONG vmi , PVOID Base , PVOID Buf , ULONG Sizex)
{
	BOOL bret ; 
	__asm{
		push pOfflineVmm
		push Sizex
		push Buf 
		push Base
		push vmi
		call readpa
		mov bret , eax
	}
	
	return bret ;
}
BOOL readmem(ULONG vmi , PVOID Base , PVOID Buf , ULONG Sizex)
{
	BOOL bret ; 
	__asm{
		push pOfflineVmm
		push Sizex
		push Buf 
		push Base
		push vmi
		call readva
		mov bret , eax
	}

	return bret ;
}
BOOL writemem(ULONG vmi , PVOID Base , PVOID Buf , ULONG Sizex)
{
	BOOL bret ; 
	__asm{
		push pOfflineVmm
		push Sizex
		push Buf 
		push Base
		push vmi
		call writeva
		mov bret , eax
	}
	
	return bret ;
}
#define PSMOD_OFFSET 0x18 
#define PROCHEAD_OFFSET 0x78
#define PSPCIDTABLE_OFFSET 0x80
#define BUGCHECKDATA_OFFSET 0xb0
#define	ROOTDIROBJ_OFFSET 0xc0
#define TYPEOBJECTTYPE_OFFSET 0xc8
#define DBGBUF_OFFSET 0x208
#define DBGBUF_WRITEPTR 0x210
#define NTBUILDLAB_OFFSET 0x230
#define MmLastUnloadDrivers 0x250

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef struct _UNLOADED_DRIVERS {
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVERS, *PUNLOADED_DRIVERS;
typedef struct CHKKMODCB{
	ULONG Order ; 
	ULONG Base ;
	ULONG Size ; 
	BOOL Unloaded ; 
	LPWSTR pName ; 
	LPWSTR pBaseName;

}CHKKMODCB , *PCHKKMODCB;
typedef struct FINDMOD_CTX{
	ULONG Addreess ; 
	LPWSTR pModName;
}FINDMOD_CTX , *PFINDMOD_CTX;
typedef struct FINDMODEX_CTX{
	ULONG Addreess ; 
	LPWSTR pModName;
	ULONG Base ;
	ULONG Size ;
}FINDMODEX_CTX , *PFINDMODEX_CTX;
typedef struct FINDMODEX2_CTX{
	ULONG CheckSum ; 
	ULONG Addr ; 
	ULONG TimeStamp ; 
	BOOL bFind ; 
}FINDMODEX2_CTX , *PFINDMODEX2_CTX;
BOOL __stdcall CallBackFindModule(ULONG vmxindex , PCHKKMODCB cb , PFINDMOD_CTX ctx)
{
	if (!cb->Unloaded && cb->Base <= ctx->Addreess && cb->Base + cb->Size > ctx->Addreess)
	{
		wcscpy(ctx->pModName , cb->pName);
		return FALSE;
	}
	return TRUE ; 
} 
BOOL __stdcall CallBackFindModuleEx(ULONG vmxindex , PCHKKMODCB cb , PFINDMODEX_CTX ctx)
{
	if (!cb->Unloaded && cb->Base <= ctx->Addreess && cb->Base + cb->Size > ctx->Addreess)
	{
		wcscpy(ctx->pModName , cb->pBaseName);
		ctx->Base = cb->Base ; 
		ctx->Size = cb->Size ; 
		return FALSE;
	}
	return TRUE ; 
}
PVOID g_PageRead = NULL ;  
BOOL __stdcall CallBackFindModuleEx2(ULONG vmxindex , PCHKKMODCB cb , PFINDMODEX2_CTX ctx)
{

	if (ctx->Addr >= cb->Base && ctx->Addr < cb->Base + cb->Size)
	{
		ctx->bFind = TRUE ; 
		return FALSE ; 
	}

	readmem(vmxindex ,(PVOID)cb->Base , g_PageRead , 0x1000);
	PIMAGE_DOS_HEADER doshdr ; 
	doshdr = (PIMAGE_DOS_HEADER)(g_PageRead);

	if (doshdr->e_magic == 0x5a4d && doshdr->e_lfanew + sizeof(IMAGE_NT_HEADERS) < 0x1000)
	{
		PIMAGE_NT_HEADERS nthdr = (PIMAGE_NT_HEADERS)((ULONG)g_PageRead + doshdr->e_lfanew );
		if (nthdr->Signature == 0x4550 &&
			nthdr->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE &&
			nthdr->OptionalHeader.CheckSum == ctx->CheckSum && 
			nthdr->FileHeader.TimeDateStamp == ctx->TimeStamp)
		{
			ctx->bFind = TRUE ; 
			return FALSE ; 
		}
	}
	return TRUE ; 
} 
typedef struct NTOS_INFO{
	ULONG Base ; 
	ULONG Size ; 
}NTOS_INFO , *PNTOS_INFO;
BOOL __stdcall CallBackGetNtosInfo(ULONG vmxindex , PCHKKMODCB cb , PNTOS_INFO ctx)
{
	if (cb->Order == 0)
	{
		ctx->Base = cb->Base ;
		ctx->Size = cb->Size ;
		return TRUE ; 
	}
	return FALSE ; 
}

void chkkmod(ULONG index , PVOID Callback , PVOID CallerContext)
{
	ULONG KdVersionBlock ; 
	ULONG PsLoadedModuleList ; 
	BOOL bret ; 
	readmem(index , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(index , (PVOID)(KdVersionBlock + PSMOD_OFFSET) , &PsLoadedModuleList , sizeof(ULONG));

	LIST_ENTRY DataTable ;	
	readmem(index , (PVOID)PsLoadedModuleList , &DataTable , sizeof(LIST_ENTRY));
	PVOID pCurrentLink = DataTable.Flink ; 
	BYTE DataInfoBuf[0x34 ] ; 
	ULONG Order = 0 ; 
	do 
	{
		ULONG Base,Size ; 
		
		readmem(index , pCurrentLink , &DataInfoBuf , 0x34);
		pCurrentLink = (PVOID)*(ULONG*)(&DataInfoBuf);
		Base = *(ULONG*)((ULONG)&DataInfoBuf + 0x18);
		Size = *(ULONG*)((ULONG)&DataInfoBuf + 0x20);
		USHORT BaseDllNameSize = *(WORD*)((ULONG)&DataInfoBuf + 0x2c);
		USHORT FullDllNameSize = *(WORD*)((ULONG)&DataInfoBuf + 0x24);
		PVOID FullDllBuf = malloc(FullDllNameSize + sizeof(WCHAR));
		PVOID BaseDllBuf = malloc(BaseDllNameSize + sizeof(WCHAR));
		readmem(index , (PVOID)(*(ULONG*)((ULONG)&DataInfoBuf + 0x30)) , BaseDllBuf , BaseDllNameSize);
		*(WORD*)((ULONG)BaseDllBuf + BaseDllNameSize ) = 0 ; 
		readmem(index , (PVOID)(*(ULONG*)((ULONG)&DataInfoBuf + 0x28)) , FullDllBuf , FullDllNameSize);
		*(WORD*)((ULONG)FullDllBuf + FullDllNameSize) = 0 ; 

		CHKKMODCB cb ;
		cb.Base = Base;
		cb.Size = Size ; 
		cb.pName =(LPWSTR) FullDllBuf ; 
		cb.pBaseName =(LPWSTR)BaseDllBuf;
		cb.Unloaded = FALSE ;
		cb.Order = Order ; 
		__asm
		{
			push CallerContext
				lea eax , cb 
				push eax
				push index
				call Callback
				mov bret , eax
		}
		
		if (bret == 0 )
		{
			free(BaseDllBuf);
			free(FullDllBuf);
			return ; 
		}		
		
		free(BaseDllBuf);
		free(FullDllBuf);

		
		//		getchar();

		Order ++ ; 
	} while(pCurrentLink != (PVOID)PsLoadedModuleList);
	
	ULONG LastUnloadDrivers ; 
	ULONG UnloadDrvInfo[2];
	ULONG i ; 
	readmem(index , (PVOID)(KdVersionBlock + MmLastUnloadDrivers) ,  &LastUnloadDrivers , sizeof(ULONG));
	
	readmem(index , (PVOID)LastUnloadDrivers , UnloadDrvInfo , sizeof(ULONG)*2);
	
	PVOID pUnloadDrvInfo = malloc(UnloadDrvInfo[0] * sizeof(UNLOADED_DRIVERS));
	
	readmem(index , (PVOID)UnloadDrvInfo[1] ,pUnloadDrvInfo , UnloadDrvInfo[0] * sizeof(UNLOADED_DRIVERS) );
	
	for (i = 0 ; i < UnloadDrvInfo[0] ;i++)
	{
		PUNLOADED_DRIVERS punloadinfo = (PUNLOADED_DRIVERS)((ULONG)pUnloadDrvInfo + sizeof(UNLOADED_DRIVERS) *i);
		PVOID pModuleName = malloc(punloadinfo->Name.Length + sizeof(WCHAR));
		readmem(index , (PVOID)punloadinfo->Name.Buffer , pModuleName , punloadinfo->Name.Length);
		*(WCHAR*)((ULONG)pModuleName + punloadinfo->Name.Length) = 0 ; 
		CHKKMODCB cb ;
		cb.Base = (ULONG)punloadinfo->StartAddress;
		cb.Size = (ULONG)punloadinfo->EndAddress - (ULONG)punloadinfo->StartAddress ; 
		cb.pName = (LPWSTR)pModuleName ; 
		cb.pBaseName = (LPWSTR)pModuleName;
		cb.Unloaded = TRUE ;
		__asm
		{
			push CallerContext
			lea eax , cb 
			push eax
			push index
			call Callback
			mov bret , eax
		}

		if (bret == 0 )
		{
			free(pModuleName);
			free(pUnloadDrvInfo);
			return ; 
		}

		free(pModuleName);
		
	}
	
	free(pUnloadDrvInfo);

	return ; 
	
}

void listkmod(ULONG index)
{

	ULONG KdVersionBlock ; 
	ULONG PsLoadedModuleList ;

	readmem(index , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(index , (PVOID)(KdVersionBlock + PSMOD_OFFSET) , &PsLoadedModuleList , sizeof(ULONG));
	printf("PsLoadedModuleList : %08x\nList Current Modules...\n"
		"---------------------------------------------------------------\n"
		"Base     Size     Module Name     Path\n", PsLoadedModuleList);
	
	LIST_ENTRY DataTable ;
	ULONG ModuleCount = 0 ;
	
	readmem(index , (PVOID)PsLoadedModuleList , &DataTable , sizeof(LIST_ENTRY));

	PVOID pCurrentLink = DataTable.Flink ; 
	BYTE DataInfoBuf[0x34 ] ; 
	do 
	{
		ULONG Base,Size ; 
		
		readmem(index , pCurrentLink , &DataInfoBuf , 0x34);
		pCurrentLink = (PVOID)*(ULONG*)(&DataInfoBuf);
		Base = *(ULONG*)((ULONG)&DataInfoBuf + 0x18);
		Size = *(ULONG*)((ULONG)&DataInfoBuf + 0x20);
		USHORT BaseDllNameSize = *(WORD*)((ULONG)&DataInfoBuf + 0x2c);
		USHORT FullDllNameSize = *(WORD*)((ULONG)&DataInfoBuf + 0x24);
		PVOID FullDllBuf = malloc(FullDllNameSize + sizeof(WCHAR));
		PVOID BaseDllBuf = malloc(BaseDllNameSize + sizeof(WCHAR));
		readmem(index , (PVOID)(*(ULONG*)((ULONG)&DataInfoBuf + 0x30)) , BaseDllBuf , BaseDllNameSize);
		*(WORD*)((ULONG)BaseDllBuf + BaseDllNameSize ) = 0 ; 
		readmem(index , (PVOID)(*(ULONG*)((ULONG)&DataInfoBuf + 0x28)) , FullDllBuf , FullDllNameSize);
		*(WORD*)((ULONG)FullDllBuf + FullDllNameSize) = 0 ; 

		
		
		
		printf("%08x %08x %ws" , Base,Size , BaseDllBuf );

		if (wcslen((WCHAR*)BaseDllBuf) < 16)
		{
			ULONG LeftBlank = 16 - wcslen((WCHAR*)BaseDllBuf);
			while(LeftBlank)
			{
				printf(" ");
				LeftBlank -- ;
			}
		}
		printf("%ws\n" , FullDllBuf);
		ModuleCount ++;
		free(BaseDllBuf);
		free(FullDllBuf);
		
		//		getchar();
	} while(pCurrentLink != (PVOID)PsLoadedModuleList);
	
	printf("list %u modules\n\n",ModuleCount);
	
	printf("list unloaded modules....\n"
		"---------------------------------------------------------------\n"
		"Base     Size     Module Name\n");
	
	ULONG LastUnloadDrivers ; 
	ULONG UnloadDrvInfo[2];
	ULONG i ; 
	readmem(index , (PVOID)(KdVersionBlock + MmLastUnloadDrivers) ,  &LastUnloadDrivers , sizeof(ULONG));
	
	readmem(index , (PVOID)LastUnloadDrivers , UnloadDrvInfo , sizeof(ULONG)*2);
	
	PVOID pUnloadDrvInfo = malloc(UnloadDrvInfo[0] * sizeof(UNLOADED_DRIVERS));
	
	readmem(index , (PVOID)UnloadDrvInfo[1] ,pUnloadDrvInfo , UnloadDrvInfo[0] * sizeof(UNLOADED_DRIVERS) );
	
	for (i = 0 ; i < UnloadDrvInfo[0] ;i++)
	{
		PUNLOADED_DRIVERS punloadinfo = (PUNLOADED_DRIVERS)((ULONG)pUnloadDrvInfo + sizeof(UNLOADED_DRIVERS) *i);
		PVOID pModuleName = malloc(punloadinfo->Name.Length + sizeof(WCHAR));
		readmem(index , (PVOID)punloadinfo->Name.Buffer , pModuleName , punloadinfo->Name.Length);
		*(WCHAR*)((ULONG)pModuleName + punloadinfo->Name.Length) = 0 ; 
		
		printf("%08x %08x %ws\n" , punloadinfo->StartAddress , (ULONG)punloadinfo->EndAddress - (ULONG)punloadinfo->StartAddress ,
			pModuleName);
		
		free(pModuleName);
		
	}
	
	free(pUnloadDrvInfo);
	
	printf("list %u unloaded modules\n" , UnloadDrvInfo[0]);

	getchar();
	return ; 
}

BOOL getvmx(ULONG index , PENUMVMX pvmx)
{
	BOOL bret ; 
	__asm
	{
		push index
		push pvmx
		call GetVmxInfo
		mov bret ,eax
	}
	return bret;

}
void cvmx(ULONG maxvmx)
{
	ULONG i ; 
	for (i = 0 ;i<maxvmx;i++)
	{
		ENUMVMX vmx;
		if (getvmx(i , &vmx))
		{
			__asm
			{
				lea eax ,vmx
				push eax
				call CleanupVmx
			}
		}

	}


	return ; 
}
#define PROCNAME_OFF 0x174
#define PID_OFFSET 0x84
#define PROC_FLAGS_OFF 0x248
#define PROC_LINK_OFF 0x88

typedef struct NAME_INFO{
	PVOID pDirObj ;
	UNICODE_STRING ObjName;
}NAME_INFO ,*PNAME_INFO;



BOOL GetObjFullName(ULONG vmxindex , PVOID pObject,LPWSTR ObjName , ULONG cb)
{

	BYTE NameInfoOffset ; 
	ULONG ObjNameLen = 0 ;
	PVOID CurrentObj = pObject ; 
	ULONG KdVersionBlock ; 
	ULONG RootDir ;  

	
	readmem(vmxindex , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(vmxindex , (PVOID)(KdVersionBlock + ROOTDIROBJ_OFFSET) , &RootDir , sizeof(ULONG));
	readmem(vmxindex , (PVOID)RootDir , &RootDir , sizeof(ULONG));

	while(CurrentObj && (ULONG)CurrentObj != RootDir)
	{
		if (!readmem(vmxindex , (PVOID)((ULONG)CurrentObj - 0xc) , &NameInfoOffset , sizeof(BYTE)) ||
			NameInfoOffset == 0)
		{
			return FALSE ; 
		}
		
		NAME_INFO nameinfo ; 
		
		
		readmem(vmxindex , (PVOID)((ULONG)CurrentObj - 0x18 - NameInfoOffset) , &nameinfo , sizeof(nameinfo));
		
		ObjNameLen += nameinfo.ObjName.Length + 2; 
	
		CurrentObj = nameinfo.pDirObj;
	}
	
	if (cb < ObjNameLen + 2)
	{
		return FALSE ; 
	}

	CurrentObj = pObject; 
	LPWSTR pStringBuffer = ObjName + ObjNameLen / sizeof(WCHAR) ; 
	*pStringBuffer = L'\0';
	while(CurrentObj && (ULONG)CurrentObj != RootDir)
	{
		if (!readmem(vmxindex , (PVOID)((ULONG)CurrentObj - 0xc) , &NameInfoOffset , sizeof(BYTE)) ||
			NameInfoOffset == 0)
		{
			return FALSE ; 
		}
		
		NAME_INFO nameinfo ; 
		
		
		readmem(vmxindex , (PVOID)((ULONG)CurrentObj - 0x18 - NameInfoOffset) , &nameinfo , sizeof(nameinfo));
		pStringBuffer -= nameinfo.ObjName.Length / sizeof(WCHAR);
		
		readmem(vmxindex, nameinfo.ObjName.Buffer , pStringBuffer , nameinfo.ObjName.Length);
		pStringBuffer --;
		memcpy(pStringBuffer , L"\\", 2);
		
		CurrentObj = nameinfo.pDirObj;
	}

	return TRUE ; 

}
#define NUMBER_HASH_BUCKETS 37

typedef struct _OBJECT_DIRECTORY_ENTRY {
    struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
    struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[ NUMBER_HASH_BUCKETS ];
    ULONG Lock;
    PVOID DeviceMap;
    ULONG SessionId;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

#define OBJECT_TYPE_OFFSET 0x10

BOOL ObjWalkerFindTarget(ULONG vmi , 
						 POBJECT_DIRECTORY DirObj ,
						 PVOID DirObjectType ,
						 LPWSTR CurrentDir , 
						 LPWSTR FindTarget ,
						 LPWSTR TargetTypeName,
						 PULONG pTargetObject )
{
	LPWSTR DirEnd = wcschr(CurrentDir , L'\\');
	BOOL CheckDir = FALSE ; 
	ULONG DirOff ; 
	*pTargetObject = 0 ;
	if (!DirEnd)
	{
		printf("dir name error!\n");
		return FALSE ; 
	}

	if (wcslen(DirEnd) == 1)
	{
		CheckDir = TRUE ;
	}
	else
	{
		DirOff = DirEnd - CurrentDir ; 
	}

	ULONG i ; 

	for (i = 0 ; i < NUMBER_HASH_BUCKETS ; i++)
	{
		OBJECT_DIRECTORY localDirObj ; 
		readmem(vmi , DirObj , &localDirObj , sizeof(OBJECT_DIRECTORY));
		PVOID ObjDirEntry = localDirObj.HashBuckets[i];

		while(ObjDirEntry)
		{
			OBJECT_DIRECTORY_ENTRY objdirentrylocal ; 
			readmem(vmi , ObjDirEntry , &objdirentrylocal , sizeof(OBJECT_DIRECTORY_ENTRY));
			PVOID pObject = objdirentrylocal.Object ; 
			PVOID pObjectType ; 
			readmem(vmi , (PVOID)((ULONG)pObject - OBJECT_TYPE_OFFSET) , &pObjectType , sizeof(ULONG));
			if (CheckDir)
			{
				UNICODE_STRING uniname ;
				readmem(vmi , (PVOID)((ULONG)pObjectType + 0x40 ) , &uniname , sizeof(UNICODE_STRING));
				PVOID pTypeName = malloc(uniname.Length + 2);
				readmem(vmi , uniname.Buffer , pTypeName , uniname.Length);
				*(WCHAR*)((ULONG)pTypeName + uniname.Length) = 0 ; 
				BYTE NameInfoOffset ; 
				PVOID pObjName ;
				readmem(vmi , (PVOID)((ULONG)pObject - 0xc) , &NameInfoOffset , sizeof(BYTE));
				if (NameInfoOffset)
				{
					readmem(vmi , (PVOID)((ULONG)pObject - 0x18 - NameInfoOffset + 0x4) , &uniname , sizeof(UNICODE_STRING));
					pObjName = malloc(uniname.Length + 2);
					readmem(vmi , uniname.Buffer , pObjName , uniname.Length);
					*(WCHAR*)((ULONG)pObjName+ uniname.Length) = 0 ;
					if (wcsicmp((WCHAR*)pTypeName , TargetTypeName) == 0)
					{
						if (wcsicmp((WCHAR*)pObjName , FindTarget ) == 0)
						{
							
							*pTargetObject = (ULONG)pObject ; 
							free(pObjName);
							free(pTypeName);
							break ; 
						}
					}
					free(pObjName);

				}
				free(pTypeName);

			//	getchar();
			}
			else if (pObjectType == DirObjectType)
			{
				UNICODE_STRING uniname ;
				BYTE NameInfoOffset ; 
				PVOID pObjName ;
				readmem(vmi , (PVOID)((ULONG)pObject - 0xc) , &NameInfoOffset , sizeof(BYTE));
				if (NameInfoOffset)
				{
					readmem(vmi , (PVOID)((ULONG)pObject - 0x18 - NameInfoOffset + 0x4) , &uniname , sizeof(UNICODE_STRING));
					pObjName = malloc(uniname.Length + 4);
					readmem(vmi , uniname.Buffer , pObjName , uniname.Length);
					*(WCHAR*)((ULONG)pObjName+ uniname.Length) = L'\\' ;
					*(WCHAR*)((ULONG)pObjName + uniname.Length + 2) = 0 ;

					if (wcsnicmp((WCHAR*)pObjName , CurrentDir + 1 , (uniname.Length / sizeof(WCHAR)) + 1) == 0 )
					{
						if (ObjWalkerFindTarget(vmi ,
							(POBJECT_DIRECTORY)pObject ,
							DirObjectType ,
							DirEnd+DirOff+1+(uniname.Length / sizeof(WCHAR)),
							FindTarget ,
							TargetTypeName,
							pTargetObject))
						{
							free(pObjName);
							return TRUE ; 
						}
					}
					free(pObjName);

				}
				
			}
			
			ObjDirEntry = objdirentrylocal.ChainLink ; 
		}
	}

	if (CheckDir && *pTargetObject != 0 )
	{
		return TRUE ;
	}

	return FALSE ; 
}
WCHAR DosNamePath[] = L"\\GLOBAL??\\";

BOOL GetDosDevice(ULONG vmxindex , LPWSTR DeviceName , LPWSTR DosName)
{
	ULONG KdVersionBlock ; 
	ULONG RootDir ;  
	ULONG DirObjType ; 
	
	readmem(vmxindex , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(vmxindex , (PVOID)(KdVersionBlock + ROOTDIROBJ_OFFSET) , &RootDir , sizeof(ULONG));
	readmem(vmxindex , (PVOID)RootDir , &RootDir , sizeof(ULONG));
	readmem(vmxindex , (PVOID)((ULONG)RootDir - OBJECT_TYPE_OFFSET) , &DirObjType , sizeof(ULONG));

	WCHAR DosNamex[3] = L"A:";
	BYTE i ; 
	for (i = 0 ; i < 26 ; i++)
	{
		DosNamex[0] = DosNamex[0] + 1  ;
		ULONG pObject = 0 ; 
		WCHAR LinkDeviceName[MAX_PATH];
		if (ObjWalkerFindTarget(vmxindex , 
			(POBJECT_DIRECTORY)RootDir ,
			(PVOID)DirObjType , 
			DosNamePath ,
			DosNamex , 
			L"SymbolicLink",
			&pObject))
		{
			UNICODE_STRING uniname ; 

			if (!readmem(vmxindex , (PVOID)((ULONG)pObject + 8 ), &uniname , sizeof(UNICODE_STRING)) ||
				uniname.Length > MAX_PATH * sizeof(WCHAR))
			{
				continue; 
			}
			
			readmem(vmxindex , uniname.Buffer , LinkDeviceName , uniname.Length);
			*(WCHAR*)((ULONG)LinkDeviceName + uniname.Length) = 0;
				if (wcsicmp(DeviceName , LinkDeviceName) == 0 )
				{
					wcscpy(DosName , DosNamex);
					return TRUE ; 
				}
		}



	}
	return FALSE ; 

}
BOOL DosDeviceCacheInit=FALSE ; 
ULONG DosDeviceCache[26];


BOOL GetProcFullPath(ULONG vmxindex , PVOID Eproc , LPWSTR DeviceName , LPWSTR PathName)
{
	PVOID TempObject ; 
	PVOID DeviceObject ; 
	
	//get section object

	readmem(vmxindex , (PVOID)((ULONG)Eproc + 0x138) , &TempObject , sizeof(ULONG));


	if (TempObject == NULL)
	{
		return FALSE ; 
	}
	//get segment object

	readmem(vmxindex , (PVOID)((ULONG)TempObject + 0x14) , &TempObject , sizeof(ULONG));

	//get base address

	readmem(vmxindex , TempObject , &TempObject , sizeof(ULONG));

	//get file object

	readmem(vmxindex , (PVOID)((ULONG)TempObject + 0x24) , &TempObject , sizeof(ULONG));

	//read file object->DeviceObject

	readmem(vmxindex , (PVOID)((ULONG)TempObject + 0x4) , &DeviceObject , sizeof(ULONG));

	ULONG i ; 
	BOOL bFindInCache = FALSE ; 
	for (i = 0 ; i < 26 ; i++)
	{
		if (DosDeviceCache[i] == (ULONG)DeviceObject)
		{
			WCHAR DosNamex[3] = L"A:";
			DosNamex[0] = DosNamex[0] + (USHORT)i;
			wcscpy(DeviceName , DosNamex);
			bFindInCache = TRUE ; 
		}
	}

	if (bFindInCache == FALSE)
	{
		WCHAR DevName[MAX_PATH];
		GetObjFullName(vmxindex , DeviceObject , DevName , MAX_PATH);
		if (!GetDosDevice(vmxindex ,  DevName , DeviceName ))
		{
			wcscpy(DeviceName , L"\\");
		}
		else
		{
			ULONG dosdeviceindex = DeviceName[0] - L'A';
			DosDeviceCache[dosdeviceindex] = (ULONG)DeviceObject ; 
		}

	}


	UNICODE_STRING uniname ; 
	readmem(vmxindex , (PVOID)((ULONG)TempObject + 0x30) , &uniname , sizeof(UNICODE_STRING));

	readmem(vmxindex , uniname.Buffer , PathName , uniname.Length );

	*(WCHAR*)((ULONG)PathName + uniname.Length ) = L'\0';

	return TRUE ; 


}


void listproc(ULONG index)
{
	ULONG KdVersionBlock ; 
	ULONG PsActiveProcessHead ;
	ULONG Eproc[200];
	ULONG pids[200];

listprocloop:
	if (!DosDeviceCacheInit)
	{
		memset(DosDeviceCache , 0 , 26*sizeof(ULONG));
	}

	readmem(index , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(index , (PVOID)(KdVersionBlock + PROCHEAD_OFFSET) , &PsActiveProcessHead , sizeof(ULONG));

	printf("PsActiveProcessHead : %08x\nlist processes....\n"
		"---------------------------------------------------------------\n"
		"EPROCESS  PID    ProcessName\n"
		"---------------------------------------------------------------\n",
		PsActiveProcessHead);
	ULONG flinkProcessHead = PsActiveProcessHead; 
	readmem(index , (PVOID)flinkProcessHead , &flinkProcessHead , sizeof(ULONG));
	ULONG proccount = 0 ;

	do 
	{

		CHAR ProcName[16];
		CHAR PidStr[6];
		ULONG pid ; 
		readmem(index , (PVOID)(flinkProcessHead - PROC_LINK_OFF + PROCNAME_OFF) , ProcName , 16);
		readmem(index , (PVOID)(flinkProcessHead - PROC_LINK_OFF + PID_OFFSET) , &pid , sizeof(ULONG));
		BYTE ProcessFlags ; 
		sprintf(PidStr , "%u" , pid);

		readmem(index , (PVOID)(flinkProcessHead - PROC_LINK_OFF + 0x248) ,&ProcessFlags , sizeof(BYTE) );
		if ((ProcessFlags & 4) ==0 && (ProcessFlags & 8 ) == 0 )
		{
			WCHAR DevName[MAX_PATH];
			WCHAR PathName[MAX_PATH];
			if (GetProcFullPath(index , (PVOID)(flinkProcessHead - PROC_LINK_OFF) , (WCHAR*)&DevName ,  (WCHAR*)&PathName))
			{
				printf("%08x  %04u   %ws%ws\n" , flinkProcessHead - PROC_LINK_OFF , pid , DevName , PathName);
				
			}
			else
			{
				printf("%08x  %04u   %s\n" , flinkProcessHead - PROC_LINK_OFF , pid , ProcName);
				
			}
			Eproc[proccount] = flinkProcessHead - PROC_LINK_OFF ; 
			pids[proccount] = pid ;

				
			proccount ++ ; 
		}
		else if (ProcessFlags & 4)
		{
			printf("%08x  %04u   %s [EXITING]\n" , flinkProcessHead - PROC_LINK_OFF , pid , ProcName);
		}
		else if (ProcessFlags & 8)
		{
			printf("%08x  %04u   %s [DELETED]\n" , flinkProcessHead - PROC_LINK_OFF , pid , ProcName);
		}



		
		
		readmem(index , (PVOID)flinkProcessHead , &flinkProcessHead , sizeof(ULONG));



	} while(flinkProcessHead != PsActiveProcessHead);


	printf("\nList %u processes\n",proccount);

	ULONG pidtokill ; 

	printf("kill process");
	scanf("%u" , &pidtokill);

	ULONG i ; 
	BOOL bKilled = FALSE; 


	for (i = 0 ; i < proccount ; i ++)
	{
		if (pids[i] == pidtokill)
		{
//			KillProcess(index , Eproc[i]);
			bKilled = TRUE; 
			break ; 
		}
	}

	if (bKilled )
	{
		system("cls");
		goto listprocloop;
	}

	getchar();


}

BOOL suspendvmx(PENUMVMX vmx)
{
	BOOL bret ; 
	__asm
	{
		push vmx
		call FreezeVmx
		mov bret ,eax
	}
	return bret ; 
}
BOOL resumevmx(PENUMVMX vmx)
{
	BOOL bret ; 
	__asm
	{
		push vmx
		call ThawVmx
		mov bret ,eax
	}
	return bret ; 
}
void ShowSystemInfo(ULONG index )
{
	ULONG KdVersionBlock ; 
	ULONG KiBugCheckData ; 
	ULONG BugCheckData[5];
	CHAR BuildLab[33];
	ULONG NtBuildLab;

	readmem(index , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(index , (PVOID)(KdVersionBlock + BUGCHECKDATA_OFFSET) , &KiBugCheckData , sizeof(ULONG));
	readmem(index , (PVOID)KiBugCheckData , BugCheckData , sizeof(ULONG) * 5);
	if (BugCheckData[0] != 0 )
	{
		printf("VMX is in bug check : STOP:0x%08x (%08x %08x %08x %08x)\n" , 
			BugCheckData[0],
			BugCheckData[1],
			BugCheckData[2],
			BugCheckData[3],
			BugCheckData[4]);
	}

	memset(BuildLab , 0 , 33);
	readmem(index , (PVOID)(KdVersionBlock + NTBUILDLAB_OFFSET) , &NtBuildLab , sizeof(ULONG));
	readmem(index , (PVOID)NtBuildLab , BuildLab , 32);
	printf("NtBuildLab:%s\n" , BuildLab);
	

}
void ViewDbgPrint(ULONG index )
{
	ULONG KdVersionBlock ; 
	ULONG DbgData ; 
	ULONG DbgWritePtr ; 

	readmem(index , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(index , (PVOID)(KdVersionBlock + DBGBUF_OFFSET) , &DbgData , sizeof(ULONG));
	readmem(index , (PVOID)(KdVersionBlock + DBGBUF_WRITEPTR) , &DbgWritePtr , sizeof(ULONG));
	readmem(index , (PVOID)DbgWritePtr , &DbgWritePtr , sizeof(ULONG));
	ULONG BufLen = DbgWritePtr - DbgData ; 
	PVOID pDbgData = malloc(BufLen +1) ; 
	memset(pDbgData , 0 , BufLen + 1 );
	readmem(index , (PVOID)DbgData , pDbgData , BufLen);
	system("cls");
	printf("\nDbgprint Data Buffer\n=========================================================\n%s\n" ,(char*)pDbgData);
	free(pDbgData);
	getchar();
	return ; 

	
}

const WCHAR noNameObject[] = L"invalid object name";
BOOL ObjWalker(ULONG vmi , POBJECT_DIRECTORY DirObj , PVOID DirObjectType , LPWSTR CurrentDir )
{
	LPWSTR DirEnd = wcschr(CurrentDir , L'\\');
	BOOL DisplayDir = FALSE ; 
	ULONG DirOff ; 
	if (!DirEnd)
	{
		printf("dir name error!\n");
		return FALSE ; 
	}

	if (wcslen(DirEnd) == 1)
	{
		DisplayDir = TRUE ;
		printf("\nList Object Directory\nAddress  Type          Name\n");
		printf("-------  ----          ----\n");

	}
	else
	{
		DirOff = DirEnd - CurrentDir ; 
	}

	ULONG i ; 

	for (i = 0 ; i < NUMBER_HASH_BUCKETS ; i++)
	{
		OBJECT_DIRECTORY localDirObj ; 
		readmem(vmi , DirObj , &localDirObj , sizeof(OBJECT_DIRECTORY));
		PVOID ObjDirEntry = localDirObj.HashBuckets[i];

		while(ObjDirEntry)
		{
			OBJECT_DIRECTORY_ENTRY objdirentrylocal ; 
			readmem(vmi , ObjDirEntry , &objdirentrylocal , sizeof(OBJECT_DIRECTORY_ENTRY));
			PVOID pObject = objdirentrylocal.Object ; 
			PVOID pObjectType ; 
			readmem(vmi , (PVOID)((ULONG)pObject - OBJECT_TYPE_OFFSET) , &pObjectType , sizeof(ULONG));
			if (DisplayDir)
			{
				UNICODE_STRING uniname ;
				readmem(vmi , (PVOID)((ULONG)pObjectType + 0x40 ) , &uniname , sizeof(UNICODE_STRING));
				PVOID pTypeName = malloc(uniname.Length + 2);
				readmem(vmi , uniname.Buffer , pTypeName , uniname.Length);
				*(WCHAR*)((ULONG)pTypeName + uniname.Length) = 0 ; 
				BYTE NameInfoOffset ; 
				PVOID pObjName ;
				readmem(vmi , (PVOID)((ULONG)pObject - 0xc) , &NameInfoOffset , sizeof(BYTE));
				if (NameInfoOffset)
				{
					readmem(vmi , (PVOID)((ULONG)pObject - 0x18 - NameInfoOffset + 0x4) , &uniname , sizeof(UNICODE_STRING));
					pObjName = malloc(uniname.Length + 2);
					readmem(vmi , uniname.Buffer , pObjName , uniname.Length);
					*(WCHAR*)((ULONG)pObjName+ uniname.Length) = 0 ;
					printf("%08x %ws" , pObject , pTypeName);

					if (wcslen((WCHAR*)pTypeName) < 14)
					{
						ULONG Blanktoprint = 14 - wcslen((WCHAR*)pTypeName);
						while(Blanktoprint)
						{
							printf(" ");
							Blanktoprint--;
						};
			
					}
					printf("%ws\n" ,pObjName);
					free(pObjName);
				}
				else
				{
					pObject = (PVOID)&noNameObject ; 
				}
				free(pTypeName);
			//	getchar();
			}
			else if (pObjectType == DirObjectType)
			{
				UNICODE_STRING uniname ;
				BYTE NameInfoOffset ; 
				PVOID pObjName ;
				readmem(vmi , (PVOID)((ULONG)pObject - 0xc) , &NameInfoOffset , sizeof(BYTE));
				if (NameInfoOffset)
				{
					readmem(vmi , (PVOID)((ULONG)pObject - 0x18 - NameInfoOffset + 0x4) , &uniname , sizeof(UNICODE_STRING));
					pObjName = malloc(uniname.Length + 4);
					readmem(vmi , uniname.Buffer , pObjName , uniname.Length);
					*(WCHAR*)((ULONG)pObjName+ uniname.Length) = L'\\' ;
					*(WCHAR*)((ULONG)pObjName + uniname.Length + 2) = 0 ;

					if (wcsnicmp((WCHAR*)pObjName , CurrentDir + 1 , (uniname.Length / sizeof(WCHAR)) + 1) == 0 )
					{
						if (ObjWalker(vmi , (POBJECT_DIRECTORY)pObject , DirObjectType , DirEnd+DirOff+1+(uniname.Length / sizeof(WCHAR))))
						{
							free(pObjName);
							return TRUE ; 
						}
					}
					free(pObjName);

				}
				
			}
			
			ObjDirEntry = objdirentrylocal.ChainLink ; 
		}
	}

	if (DisplayDir)
	{
		getchar();
		return TRUE ;
	}

	return FALSE ; 
}
void ObjDir(ULONG vmxindex)
{
	ULONG KdVersionBlock ; 
	ULONG RootDir ;  
	ULONG DirObjType ; 

	readmem(vmxindex , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(vmxindex , (PVOID)(KdVersionBlock + ROOTDIROBJ_OFFSET) , &RootDir , sizeof(ULONG));
	readmem(vmxindex , (PVOID)RootDir , &RootDir , sizeof(ULONG));
	readmem(vmxindex , (PVOID)((ULONG)RootDir - OBJECT_TYPE_OFFSET) , &DirObjType , sizeof(ULONG));

	printf("Input Dir Name:\n");
	WCHAR DirName[MAX_PATH];
	scanf("%ws",DirName);
	fflush(stdin);
	if (!ObjWalker(vmxindex , (POBJECT_DIRECTORY)RootDir , (PVOID)DirObjType , DirName))
	{
		printf("cannot find this object directory!\n");
		getchar();
	}

	return ; 

	
}
CHAR* XPSSDT_NAME[] = {"NtAcceptConnectPort","NtAccessCheck","NtAccessCheckAndAuditAlarm","NtAccessCheckByType","NtAccessCheckByTypeAndAuditAlarm","NtAccessCheckByTypeResultList",
"NtAccessCheckByTypeResultListAndAuditAlarm","NtAccessCheckByTypeResultListAndAuditAlarmByHandle","NtAddAtom","NtAddBootEntry","NtAdjustGroupsToken","NtAdjustPrivilegesToken",
"NtAlertResumeThread","NtAlertThread","NtAllocateLocallyUniqueId","NtAllocateUserPhysicalPages","NtAllocateUuids","NtAllocateVirtualMemory",
"NtAreMappedFilesTheSame","NtAssignProcessToJobObject","NtCallbackReturn","NtCancelDeviceWakeupRequest","NtCancelIoFile","NtCancelTimer",
"NtClearEvent","NtClose","NtCloseObjectAuditAlarm","NtCompactKeys","NtCompareTokens","NtCompleteConnectPort",
"NtCompressKey","NtConnectPort","NtContinue","NtCreateDebugObject","NtCreateDirectoryObject","NtCreateEvent",
"NtCreateEventPair","NtCreateFile","NtCreateIoCompletion","NtCreateJobObject","NtCreateJobSet","NtCreateKey",
"NtCreateMailslotFile","NtCreateMutant","NtCreateNamedPipeFile","NtCreatePagingFile","NtCreatePort","NtCreateProcess",
"NtCreateProcessEx","NtCreateProfile","NtCreateSection","NtCreateSemaphore","NtCreateSymbolicLinkObject","NtCreateThread",
"NtCreateTimer","NtCreateToken","NtCreateWaitablePort","NtDebugActiveProcess","NtDebugContinue","NtDelayExecution",
"NtDeleteAtom","NtDeleteBootEntry","NtDeleteFile","NtDeleteKey","NtDeleteObjectAuditAlarm","NtDeleteValueKey",
"NtDeviceIoControlFile","NtDisplayString","NtDuplicateObject","NtDuplicateToken","NtEnumerateBootEntries","NtEnumerateKey",
"NtEnumerateSystemEnvironmentValuesEx","NtEnumerateValueKey","NtExtendSection","NtFilterToken","NtFindAtom","NtFlushBuffersFile",
"NtFlushInstructionCache","NtFlushKey","NtFlushVirtualMemory","NtFlushWriteBuffer","NtFreeUserPhysicalPages","NtFreeVirtualMemory",
"NtFsControlFile","NtGetContextThread","NtGetDevicePowerState","NtGetPlugPlayEvent","NtGetWriteWatch","NtImpersonateAnonymousToken",
"NtImpersonateClientOfPort","NtImpersonateThread","NtInitializeRegistry","NtInitiatePowerAction","NtIsProcessInJob","NtIsSystemResumeAutomatic",
"NtListenPort","NtLoadDriver","NtLoadKey","NtLoadKey2","NtLockFile","NtLockProductActivationKeys",
"NtLockRegistryKey","NtLockVirtualMemory","NtMakePermanentObject","NtMakeTemporaryObject","NtMapUserPhysicalPages","NtMapUserPhysicalPagesScatter",
"NtMapViewOfSection","NtModifyBootEntry","NtNotifyChangeDirectoryFile","NtNotifyChangeKey","NtNotifyChangeMultipleKeys","NtOpenDirectoryObject",
"NtOpenEvent","NtOpenEventPair","NtOpenFile","NtOpenIoCompletion","NtOpenJobObject","NtOpenKey",
"NtOpenMutant","NtOpenObjectAuditAlarm","NtOpenProcess","NtOpenProcessToken","NtOpenProcessTokenEx","NtOpenSection",
"NtOpenSemaphore","NtOpenSymbolicLinkObject","NtOpenThread","NtOpenThreadToken","NtOpenThreadTokenEx","NtOpenTimer",
"NtPlugPlayControl","NtPowerInformation","NtPrivilegeCheck","NtPrivilegeObjectAuditAlarm","NtPrivilegedServiceAuditAlarm","NtProtectVirtualMemory",
"NtPulseEvent","NtQueryAttributesFile","NtQueryBootEntryOrder","NtQueryBootOptions","NtQueryDebugFilterState","NtQueryDefaultLocale",
"NtQueryDefaultUILanguage","NtQueryDirectoryFile","NtQueryDirectoryObject","NtQueryEaFile","NtQueryEvent","NtQueryFullAttributesFile",
"NtQueryInformationAtom","NtQueryInformationFile","NtQueryInformationJobObject","NtQueryInformationPort","NtQueryInformationProcess","NtQueryInformationThread",
"NtQueryInformationToken","NtQueryInstallUILanguage","NtQueryIntervalProfile","NtQueryIoCompletion","NtQueryKey","NtQueryMultipleValueKey",
"NtQueryMutant","NtQueryObject","NtQueryOpenSubKeys","NtQueryPerformanceCounter","NtQueryQuotaInformationFile","NtQuerySection",
"NtQuerySecurityObject","NtQuerySemaphore","NtQuerySymbolicLinkObject","NtQuerySystemEnvironmentValue","NtQuerySystemEnvironmentValueEx","NtQuerySystemInformation",
"NtQuerySystemTime","NtQueryTimer","NtQueryTimerResolution","NtQueryValueKey","NtQueryVirtualMemory","NtQueryVolumeInformationFile",
"NtQueueApcThread","NtRaiseException","NtRaiseHardError","NtReadFile","NtReadFileScatter","NtReadRequestData",
"NtReadVirtualMemory","NtRegisterThreadTerminatePort","NtReleaseMutant","NtReleaseSemaphore","NtRemoveIoCompletion","NtRemoveProcessDebug",
"NtRenameKey","NtReplaceKey","NtReplyPort","NtReplyWaitReceivePort","NtReplyWaitReceivePortEx","NtReplyWaitReplyPort",
"NtRequestDeviceWakeup","NtRequestPort","NtRequestWaitReplyPort","NtRequestWakeupLatency","NtResetEvent","NtResetWriteWatch",
"NtRestoreKey","NtResumeProcess","NtResumeThread","NtSaveKey","NtSaveKeyEx","NtSaveMergedKeys",
"NtSecureConnectPort","NtSetBootEntryOrder","NtSetBootOptions","NtSetContextThread","NtSetDebugFilterState","NtSetDefaultHardErrorPort",
"NtSetDefaultLocale","NtSetDefaultUILanguage","NtSetEaFile","NtSetEvent","NtSetEventBoostPriority","NtSetHighEventPair",
"NtSetHighWaitLowEventPair","NtSetInformationDebugObject","NtSetInformationFile","NtSetInformationJobObject","NtSetInformationKey","NtSetInformationObject",
"NtSetInformationProcess","NtSetInformationThread","NtSetInformationToken","NtSetIntervalProfile","NtSetIoCompletion","NtSetLdtEntries",
"NtSetLowEventPair","NtSetLowWaitHighEventPair","NtSetQuotaInformationFile","NtSetSecurityObject","NtSetSystemEnvironmentValue","NtSetSystemEnvironmentValueEx",
"NtSetSystemInformation","NtSetSystemPowerState","NtSetSystemTime","NtSetThreadExecutionState","NtSetTimer","NtSetTimerResolution",
"NtSetUuidSeed","NtSetValueKey","NtSetVolumeInformationFile","NtShutdownSystem","NtSignalAndWaitForSingleObject","NtStartProfile",
"NtStopProfile","NtSuspendProcess","NtSuspendThread","NtSystemDebugControl","NtTerminateJobObject","NtTerminateProcess",
"NtTerminateThread","NtTestAlert","NtTraceEvent","NtTranslateFilePath","NtUnloadDriver","NtUnloadKey",
"NtUnloadKeyEx","NtUnlockFile","NtUnlockVirtualMemory","NtUnmapViewOfSection","NtVdmControl","NtWaitForDebugEvent",
"NtWaitForMultipleObjects","NtWaitForSingleObject","NtWaitHighEventPair","NtWaitLowEventPair","NtWriteFile","NtWriteFileGather",
"NtWriteRequestData","NtWriteVirtualMemory","NtYieldExecution","NtCreateKeyedEvent","NtOpenKeyedEvent","NtReleaseKeyedEvent",
"NtWaitForKeyedEvent","NtQueryPortInformationProcess"};

BOOL RestroeOrgSSDTAddr(ULONG vmxindex , 
						ULONG sdtindex ,
						ULONG ntbase , 
						ULONG ntimagebase , 
						ULONG ssdtTableOffset ,
						LPSTR exename ,
						ULONG orgPtr)
{
	HMODULE hmod = LoadLibraryEx(exename , 0 , DONT_RESOLVE_DLL_REFERENCES);
	if (hmod == 0 )
	{
		printf("load %s failed\n" , exename);
		getchar();
		return FALSE ; 
	}
	
	ULONG OrgTableBase = ssdtTableOffset + (ULONG)hmod ; 
	ULONG OrgFunction = *(ULONG*)(OrgTableBase + sdtindex * sizeof(ULONG)) +  ntbase - ntimagebase ; 
	printf("OrgFunction = %08x\n" , OrgFunction);;


	writemem(vmxindex , (PVOID)orgPtr , &OrgFunction , sizeof(ULONG));


	printf("RestoreHook OK!\n");
	getchar();

	return TRUE;

}

void CheckSSDT(ULONG vmxindex)
{ 
	ULONG CurrentThread ;  
	ULONG ServiceTable ; 
	ULONG TableBase ; 
	ULONG Limit ; 

	readmem(vmxindex , (PVOID)0xffdff124 , &CurrentThread , sizeof(ULONG));
	readmem(vmxindex , (PVOID)(CurrentThread + 0xe0) , &ServiceTable , sizeof(ULONG));
	readmem(vmxindex , (PVOID)ServiceTable , &TableBase , sizeof(ULONG));
	readmem(vmxindex ,(PVOID)(ServiceTable + 8) , &Limit , sizeof(ULONG));
	
	NTOS_INFO ntosinfo ; 
	chkkmod(vmxindex ,CallBackGetNtosInfo , &ntosinfo);

	printf("KeServiceDescriptorTable = %08x FunctionNumer = %08x\n" 
		"===============================================================\n", ServiceTable , Limit);

	ULONG i ;
	ULONG HookCount = 0 ;
	for (i = 0 ; i < Limit ; i++)
	{
		ULONG ssdtaddr ;
		readmem(vmxindex , (PVOID)(TableBase +i *sizeof(ULONG)) , &ssdtaddr , sizeof(ULONG));
//		printf("%s :%08x\n" ,XPSSDT_NAME[i] , ssdtaddr);
		if (ssdtaddr < ntosinfo.Base || ssdtaddr > ntosinfo.Base + ntosinfo.Size)
		{
			FINDMOD_CTX findmod ; 
			WCHAR ModName[MAX_PATH] = L"unknown module";
			findmod.Addreess = ssdtaddr;
			findmod.pModName = (WCHAR*)&ModName;
			chkkmod(vmxindex , CallBackFindModule , &findmod);

			if (i < 0x11c)
			{
				printf("[%08x] %s",ssdtaddr , XPSSDT_NAME[i]  );
				
				if (strlen(XPSSDT_NAME[i]) < 20)
				{
					ULONG left = 20-strlen(XPSSDT_NAME[i]);
					while(left)
					{
						printf(" ");
						left --;
					}
				}
				
				printf("Hooker: %ws\n" , ModName);
				HookCount++;

			}
			else
			{
				printf("[%08x]:Unknown Function Hooker:%ws\n",ssdtaddr , ModName);
			}

		}



	}

	printf("Find %u ssdt hook\n" , HookCount);
	
	if (HookCount)
	{
		printf("Input RestroeFunction Name: ");
		CHAR NeedRestroeName[100];
		BOOL bFind = FALSE ;
		scanf("%s" , NeedRestroeName);
		fflush(stdin);
		for (i = 0 ; i < 0x11c ; i++)
		{
			if (stricmp(NeedRestroeName , XPSSDT_NAME[i])==0)
			{
				bFind = TRUE ; 
				break ; 
			}
		}
		if (bFind)
		{
			IMAGE_DOS_HEADER doshdr ; 
			IMAGE_NT_HEADERS nthdr ; 
			readmem(vmxindex , (PVOID)ntosinfo.Base , &doshdr , sizeof(IMAGE_DOS_HEADER));
			
			readmem(vmxindex , (PVOID)(ntosinfo.Base + doshdr.e_lfanew) , &nthdr , sizeof(IMAGE_NT_HEADERS));
			
			CHAR ExeCodeString[100];
			IMAGE_DEBUG_DIRECTORY debugdata ; 
			
			readmem(vmxindex , 
				(PVOID)(nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + ntosinfo.Base ),
				&debugdata , 
				sizeof(IMAGE_DEBUG_DIRECTORY));
			
			PIMAGE_SECTION_HEADER pSecHdr =  (PIMAGE_SECTION_HEADER)(ntosinfo.Base + doshdr.e_lfanew + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +  nthdr.FileHeader.SizeOfOptionalHeader);
			ULONG VirtualAddr ; 
			
			for (i = 0 ; i < nthdr.FileHeader.NumberOfSections ; i++)
			{
				IMAGE_SECTION_HEADER sechdr ; 
				readmem(vmxindex , pSecHdr , &sechdr , sizeof(IMAGE_SECTION_HEADER));
				if (sechdr.PointerToRawData <= debugdata.PointerToRawData && 
					sechdr.PointerToRawData + sechdr.SizeOfRawData > debugdata.PointerToRawData)
				{
					VirtualAddr = ntosinfo.Base + debugdata.PointerToRawData - sechdr.PointerToRawData + sechdr.VirtualAddress;
					break ; 
				}
				pSecHdr ++ ; 
			}
			
			PVOID pSymbolData = malloc(debugdata.SizeOfData);
			
			readmem(vmxindex , (PVOID)VirtualAddr , pSymbolData , debugdata.SizeOfData);
			
			// 		CHAR SymbolPath[100];
			// 		sprintf(SymbolPath , "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%01x" ,
			// 			*(ULONG*)((ULONG)pSymbolData + 4),
			// 			*(WORD*)((ULONG)pSymbolData + 8),
			// 			*(WORD*)((ULONG)pSymbolData + 0xA),
			// 			*(BYTE*)((ULONG)pSymbolData + 0xC),
			// 			*(BYTE*)((ULONG)pSymbolData + 0xD),
			// 			*(BYTE*)((ULONG)pSymbolData + 0xE),
			// 			*(BYTE*)((ULONG)pSymbolData + 0xF),
			// 			*(BYTE*)((ULONG)pSymbolData + 0x10),
			// 			*(BYTE*)((ULONG)pSymbolData + 0x11),
			// 			*(BYTE*)((ULONG)pSymbolData + 0x12),
			// 			*(BYTE*)((ULONG)pSymbolData + 0x13),
			// 			*(ULONG*)((ULONG)pSymbolData + 0x14));
			
			LPSTR SymbolName = (LPSTR)((ULONG)pSymbolData + 0x18);
			SymbolName[strlen(SymbolName)-1] = 'e';
			SymbolName[strlen(SymbolName)-2] = 'x';
			SymbolName[strlen(SymbolName)-3] = 'e';		
			SymbolName[strlen(SymbolName)-4] = '.';
			
			
			
			
			sprintf(ExeCodeString , 
				"C:\\mysyms\\%s\\%x%x\\%s" ,
				SymbolName,
				nthdr.FileHeader.TimeDateStamp ,
				nthdr.OptionalHeader.SizeOfImage,
				SymbolName);
			free(pSymbolData);
			
			RestroeOrgSSDTAddr(vmxindex ,
				i ,
				ntosinfo.Base,
				nthdr.OptionalHeader.ImageBase,
				TableBase - ntosinfo.Base , 
				ExeCodeString ,
				TableBase + i * sizeof(ULONG));
		}
	}

	getchar();

	return ; 
	

	
}
char* irpname[] = {
"IRP_MJ_CREATE",
"IRP_MJ_CREATE_NAMED_PIPE",
"IRP_MJ_CLOSE",
"IRP_MJ_READ",
"IRP_MJ_WRITE",
"IRP_MJ_QUERY_INFORMATION",
"IRP_MJ_SET_INFORMATION",
"IRP_MJ_QUERY_EA",
"IRP_MJ_SET_EA",
"IRP_MJ_FLUSH_BUFFERS",
"IRP_MJ_QUERY_VOLUME_INFORMATION",
"IRP_MJ_SET_VOLUME_INFORMATION",
"IRP_MJ_DIRECTORY_CONTROL",
"IRP_MJ_FILE_SYSTEM_CONTROL",
"IRP_MJ_DEVICE_CONTROL",
"IRP_MJ_INTERNAL_DEVICE_CONTROL",
"IRP_MJ_SHUTDOWN",
"IRP_MJ_LOCK_CONTROL",
"IRP_MJ_CLEANUP",
"IRP_MJ_CREATE_MAILSLOT",
"IRP_MJ_QUERY_SECURITY",
"IRP_MJ_SET_SECURITY",
"IRP_MJ_POWER",
"IRP_MJ_SYSTEM_CONTROL",
"IRP_MJ_DEVICE_CHANGE",
"IRP_MJ_QUERY_QUOTA",
"IRP_MJ_SET_QUOTA",
"IRP_MJ_PNP"};
CHAR* fastioname[] ={"FastIoCheckIfPossible",
"FastIoRead",
"FastIoWrite",
"FastIoQueryBasicInfo",
"FastIoQueryStandardInfo",
"FastIoLock",
"FastIoUnlockSingle",
"FastIoUnlockAll",
"FastIoUnlockAllByKey",
"FastIoDeviceControl",
"AcquireFileForNtCreateSection",
"ReleaseFileForNtCreateSection",
"FastIoDetachDevice",
"FastIoQueryNetworkOpenInfo",
"AcquireForModWrite",
"MdlRead",
"MdlReadComplete",
"PrepareMdlWrite",
"MdlWriteComplete",
"FastIoReadCompressed",
"FastIoWriteCompressed",
"MdlReadCompleteCompressed",
"MdlWriteCompleteCompressed",
"FastIoQueryOpen",
"ReleaseForModWrite",
"AcquireForCcFlush",
"ReleaseForCcFlush"};

typedef struct NAMETOADDR_CTX{
	LPSTR SourceName ; 
	ULONG Addreess ;
	ULONG AddAddr ; 
}NAMETOADDR_CTX , *PNAMETOADDR_CTX;

BOOL CALLBACK SymbolGetAddrFromName( PSTR SymbolName, ULONG SymbolAddress, ULONG SymbolSize, PNAMETOADDR_CTX UserContext )
{
	if (stricmp(SymbolName , UserContext->SourceName) == 0 )
	{
		UserContext->Addreess = SymbolAddress ; 
		return FALSE ; 
	}
	return TRUE ; 
}


BOOL CALLBACK SymbolGetNameFromAddr( PSTR SymbolName, ULONG SymbolAddress, ULONG SymbolSize, PNAMETOADDR_CTX UserContext )
{

	if ( (ULONG)SymbolAddress == UserContext->Addreess)
	{
		UserContext->AddAddr = 0 ;
		strcpy(UserContext->SourceName , SymbolName);
		return FALSE ; 
	}
	else if ( (ULONG)SymbolAddress < UserContext->Addreess &&
		(UserContext->AddAddr > UserContext->Addreess -  (ULONG)SymbolAddress ||
		UserContext->AddAddr==0))
	{
		UserContext->AddAddr = UserContext->Addreess - (ULONG)SymbolAddress ; 
		strcpy(UserContext->SourceName , SymbolName);
	}



	return TRUE ; 
}

ULONG LastSymbolModBase = 0 ;
CHAR LastSysName[MAX_PATH] = "";
ULONG LastLoadBase = 0 ; 

BOOL GetModSymbol(ULONG vmxindex , 
					ULONG Base ,
					ULONG Size , 
					PVOID EnumCallBack ,
					PVOID EnumContext,
					LPSTR SysName,
					PULONG LoadAddr)
{
	IMAGE_DOS_HEADER doshdr ; 
	IMAGE_NT_HEADERS nthdr ; 
	ULONG i ; 
	CHAR PdbName[MAX_PATH];
	DWORD64 LoadModBase;

	if (Base == LastSymbolModBase)
	{
		strcpy(SysName , LastSysName);
		LoadModBase = (DWORD64)LastLoadBase;
	}
	else
	{
		
		readmem(vmxindex , (PVOID)Base , &doshdr , sizeof(IMAGE_DOS_HEADER));
		
		readmem(vmxindex , (PVOID)(Base + doshdr.e_lfanew) , &nthdr , sizeof(IMAGE_NT_HEADERS));
		
		IMAGE_DEBUG_DIRECTORY debugdata ; 
		
		readmem(vmxindex , 
			(PVOID)(nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + Base ),
			&debugdata , 
			sizeof(IMAGE_DEBUG_DIRECTORY));
		
		PIMAGE_SECTION_HEADER pSecHdr =  (PIMAGE_SECTION_HEADER)(Base + doshdr.e_lfanew + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +  nthdr.FileHeader.SizeOfOptionalHeader);
		ULONG VirtualAddr ; 
		
		for (i = 0 ; i < nthdr.FileHeader.NumberOfSections ; i++)
		{
			IMAGE_SECTION_HEADER sechdr ; 
			readmem(vmxindex , pSecHdr , &sechdr , sizeof(IMAGE_SECTION_HEADER));
			if (sechdr.PointerToRawData <= debugdata.PointerToRawData && 
				sechdr.PointerToRawData + sechdr.SizeOfRawData > debugdata.PointerToRawData)
			{
				VirtualAddr = Base + debugdata.PointerToRawData - sechdr.PointerToRawData + sechdr.VirtualAddress;
				break ; 
			}
			pSecHdr ++ ; 
		}
		
		PVOID pSymbolData = malloc(debugdata.SizeOfData);
		
		readmem(vmxindex , (PVOID)VirtualAddr , pSymbolData , debugdata.SizeOfData);
		
		sprintf(PdbName , "c:\\mysyms\\%s\\%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%01x\\%s" ,
			(LPSTR)((ULONG)pSymbolData + 0x18),
			*(ULONG*)((ULONG)pSymbolData + 4),
			*(WORD*)((ULONG)pSymbolData + 8),
			*(WORD*)((ULONG)pSymbolData + 0xA),
			*(BYTE*)((ULONG)pSymbolData + 0xC),
			*(BYTE*)((ULONG)pSymbolData + 0xD),
			*(BYTE*)((ULONG)pSymbolData + 0xE),
			*(BYTE*)((ULONG)pSymbolData + 0xF),
			*(BYTE*)((ULONG)pSymbolData + 0x10),
			*(BYTE*)((ULONG)pSymbolData + 0x11),
			*(BYTE*)((ULONG)pSymbolData + 0x12),
			*(BYTE*)((ULONG)pSymbolData + 0x13),
			*(ULONG*)((ULONG)pSymbolData + 0x14),
			(LPSTR)((ULONG)pSymbolData + 0x18));
		
		LPSTR SymbolName = (LPSTR)((ULONG)pSymbolData + 0x18);
		
		SymbolName[strlen(SymbolName)-1] = 'e';
		SymbolName[strlen(SymbolName)-2] = 'x';
		SymbolName[strlen(SymbolName)-3] = 'e';		
		SymbolName[strlen(SymbolName)-4] = '.';
		
		sprintf(SysName , 
			"C:\\mysyms\\%s\\%x%x\\%s" ,
			SymbolName,
			nthdr.FileHeader.TimeDateStamp ,
			nthdr.OptionalHeader.SizeOfImage,
			SymbolName);
		
		free(pSymbolData);

		SymUnloadModule64(GetCurrentProcess() , (ULONG64)LastLoadBase );
		SymCleanup(GetCurrentProcess());
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
		
		SymInitialize(GetCurrentProcess(), NULL, TRUE);
		
		HANDLE hFile = CreateFile(PdbName , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , 0 , 0 );
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return FALSE ; 
		}
		ULONG FileSize = GetFileSize(hFile , 0 );
		CloseHandle(hFile);
		//If the function succeeds, the return value is the base address of the loaded module.
		
		LoadModBase = SymLoadModule(GetCurrentProcess(),            // Process handle of the current process 
			NULL,                // Handle to the module's image file (not needed)
			PdbName,            // Path/name of the file 
			NULL,                // User-defined short name of the module (it can be NULL) 
			0x20000000,            // Base address of the module (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
			FileSize);           // Size of the file (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
		
		if( LoadModBase == 0 ) 
		{
			printf("Error: SymLoadModule64() failed. Error code: %u \n", GetLastError());
			return FALSE; 
		}
		LastSymbolModBase = Base ; 
		LastLoadBase = (ULONG)LoadModBase ; 
		strcpy(LastSysName , SysName);
	}
	
	SymEnumerateSymbols(GetCurrentProcess(), (ULONG)LoadModBase, (PSYM_ENUMSYMBOLS_CALLBACK )EnumCallBack,EnumContext);

	*LoadAddr = (ULONG)LoadModBase;
	return TRUE ; 

}
	

void CheckDriver(ULONG vmxindex)
{
	ULONG KdVersionBlock ; 
	ULONG RootDir ;  
	ULONG DirObjType ; 
	WCHAR ModName[MAX_PATH];
	CHAR FuncName[100];


	NTOS_INFO ntosinfo ; 
	chkkmod(vmxindex ,CallBackGetNtosInfo , &ntosinfo);
	
	readmem(vmxindex , (PVOID)0xffdff034 , &KdVersionBlock , sizeof(ULONG));
	readmem(vmxindex , (PVOID)(KdVersionBlock + ROOTDIROBJ_OFFSET) , &RootDir , sizeof(ULONG));
	readmem(vmxindex , (PVOID)RootDir , &RootDir , sizeof(ULONG));
	readmem(vmxindex , (PVOID)((ULONG)RootDir - OBJECT_TYPE_OFFSET) , &DirObjType , sizeof(ULONG));

	WCHAR DrvName[100];
	printf("Input Driver Name:\n");
	scanf("%ws",DrvName);
	LPWSTR pEndName = wcsrchr(DrvName , L'\\');
	if (pEndName == 0)
	{
		return ; 
	}
	WCHAR TargetName[100];
	pEndName++;
	wcscpy(TargetName , pEndName);
	*pEndName = L'\0';
	fflush(stdin);
	ULONG pObject  = 0 ; 
	if (ObjWalkerFindTarget(vmxindex , 
		(POBJECT_DIRECTORY)RootDir , 
		(PVOID)DirObjType , 
		DrvName,
		TargetName , 
		L"Driver",
		&pObject
		) && pObject )
	{
		printf("\nDriverObject %ws%ws :%08x\n" , DrvName , TargetName , pObject);
		WCHAR DevName[100];
		ULONG pCurrentDevObj ;
		readmem(vmxindex , (PVOID)(pObject + 0x4) , &pCurrentDevObj , sizeof(ULONG));
		ULONG DrvStart , DrvSize , DrvInit , DrvUnload , DrvStartIo ;
		ULONG MajorFunctions[28];
		ULONG FastIoDispatch[26];
		ULONG pFastIoDispatch;

		readmem(vmxindex , (PVOID)(pObject + 0xc ) , &DrvStart , sizeof(ULONG));
		readmem(vmxindex , (PVOID)(pObject + 0x10 ) , &DrvSize , sizeof(ULONG));
		readmem(vmxindex , (PVOID)(pObject + 0x2C ) , &DrvInit , sizeof(ULONG));
		readmem(vmxindex , (PVOID)(pObject + 0x34 ) , &DrvUnload , sizeof(ULONG));
		readmem(vmxindex , (PVOID)(pObject + 0x30 ) , &DrvStartIo , sizeof(ULONG));
		readmem(vmxindex , (PVOID)(pObject + 0x38) , &MajorFunctions , sizeof(ULONG) * 28);
		readmem(vmxindex , (PVOID)(pObject + 0x28 ) , &pFastIoDispatch , sizeof(ULONG));
		if (pFastIoDispatch)
		{
			readmem(vmxindex , (PVOID)(pFastIoDispatch + 4) , &FastIoDispatch , sizeof(ULONG) * 26);
		}
		FINDMODEX_CTX exctx ; 
		NAMETOADDR_CTX nctx ; 
		FINDMOD_CTX fmctx ; 
		CHAR SysName[MAX_PATH];
		ULONG LoadAddr ; 


		exctx.Addreess = DrvInit ; 
		exctx.pModName = (WCHAR*)&ModName ;
		chkkmod(vmxindex , CallBackFindModuleEx , &exctx);
		
		nctx.AddAddr = 0 ;
		nctx.Addreess = exctx.Addreess + 0x20000000 - exctx.Base; 
		nctx.SourceName = (CHAR*)&FuncName ; 

		if (!GetModSymbol(vmxindex , exctx.Base , 0 , SymbolGetNameFromAddr , &nctx , SysName , &LoadAddr) ||
			nctx.AddAddr !=0)
		{
			fmctx.Addreess = DrvInit ; 
			fmctx.pModName = (WCHAR*)&ModName;
			chkkmod(vmxindex , CallBackFindModule , &fmctx);
			printf("DriverEntry : %08x -> %ws\n" , DrvInit , fmctx.pModName);
		}
		else
		{
			printf("DriverEntry : %08x -> %ws!%s\n" , DrvInit , exctx.pModName , nctx.SourceName);

		}
		
		printf("DriverStart : %08x DriverSize = %08x\n" , DrvStart , DrvSize);
		if (DrvStartIo)
		{
			exctx.Addreess = DrvStartIo ; 
			exctx.pModName = (WCHAR*)&ModName ;
			chkkmod(vmxindex , CallBackFindModuleEx , &exctx);
			
			nctx.AddAddr = 0 ;
			nctx.Addreess = exctx.Addreess + 0x20000000 - exctx.Base ; 
			nctx.SourceName = (CHAR*)&FuncName ; 
			
			if (!GetModSymbol(vmxindex , exctx.Base , 0 , SymbolGetNameFromAddr , &nctx , SysName , &LoadAddr) ||
				nctx.AddAddr !=0)
			{
				fmctx.Addreess = DrvStartIo ; 
				fmctx.pModName = (WCHAR*)&ModName;
				chkkmod(vmxindex , CallBackFindModule , &fmctx);
				printf("DriverStartIo : %08x -> %ws\n" , DrvStartIo , fmctx.pModName);
			}
			else
			{
				printf("DriverStartIo : %08x -> %ws!%s\n" , DrvStartIo , exctx.pModName , nctx.SourceName);
				
			}

		}
		if (DrvUnload)
		{
			exctx.Addreess = DrvUnload ; 
			exctx.pModName = (WCHAR*)&ModName ;
			chkkmod(vmxindex , CallBackFindModuleEx , &exctx);
			
			nctx.AddAddr = 0 ;
			nctx.Addreess = exctx.Addreess + 0x20000000 - exctx.Base ; 
			nctx.SourceName = (CHAR*)&FuncName ; 
			
			if (!GetModSymbol(vmxindex , exctx.Base , 0 , SymbolGetNameFromAddr , &nctx , SysName , &LoadAddr) ||
				nctx.AddAddr !=0)
			{
				fmctx.Addreess = DrvUnload ; 
				fmctx.pModName = (WCHAR*)&ModName;
				chkkmod(vmxindex , CallBackFindModule , &fmctx);
					printf("DriverStartIo : %08x -> %ws\n" , DrvUnload , fmctx.pModName);
			}
			else
			{
				printf("DriverUnload : %08x -> %ws!%s\n" , DrvUnload , exctx.pModName , nctx.SourceName);
				
			}
		}
		
		ULONG i ; 
		ULONG LongestNameLen = 0 ; 
		for (i = 0 ; i < 28 ; i ++)
		{
			if (MajorFunctions[i] < ntosinfo.Base || MajorFunctions[i] > ntosinfo.Base + ntosinfo.Size)
			{
				if (strlen(irpname[i]) > LongestNameLen)
				{
					LongestNameLen = strlen(irpname[i]);
				}
			}
			
		}
		for (i = 0 ; i < 28 ; i ++)
		{
			{
				BOOL bShowFuncName = TRUE ; 
				exctx.Addreess = MajorFunctions[i] ; 
				exctx.pModName = (WCHAR*)&ModName ;
				chkkmod(vmxindex , CallBackFindModuleEx , &exctx);
				
				nctx.AddAddr = 0 ;
				nctx.Addreess = exctx.Addreess + 0x20000000 - exctx.Base; 
				nctx.SourceName = (CHAR*)&FuncName ; 
				
				if (!GetModSymbol(vmxindex , exctx.Base , 0 , SymbolGetNameFromAddr , &nctx , SysName , &LoadAddr) ||
					nctx.AddAddr !=0)
				{
					fmctx.Addreess = MajorFunctions[i] ; 
					fmctx.pModName = (WCHAR*)&ModName;
					chkkmod(vmxindex , CallBackFindModule , &fmctx);
					bShowFuncName = FALSE ; 
				}
				else if (strcmp(nctx.SourceName , "IopInvalidDeviceRequest") == 0)
				{
					continue;
				}
				FINDMOD_CTX findmod ; 
				WCHAR ModName[MAX_PATH] = L"unknown module";
				findmod.Addreess = MajorFunctions[i];
				findmod.pModName = (WCHAR*)&ModName;
				chkkmod(vmxindex , CallBackFindModule , &findmod);
				printf("%s" , irpname[i]);
				if (strlen(irpname[i]) < LongestNameLen)
				{
					ULONG charleft = LongestNameLen - strlen(irpname[i]);
					while(charleft)
					{
						printf(" ");
						charleft--;
					}
				}
				if (!bShowFuncName)
				{
					printf(" : %08x -> %ws\n" , MajorFunctions[i] , fmctx.pModName );
				}
				else
				{
					printf(" : %08x -> %ws!%s\n" , MajorFunctions[i], exctx.pModName , nctx.SourceName );
					
				}
				
			}
			
		}
		if (pFastIoDispatch)
		{
			LongestNameLen = 0 ; 
			for (i = 0 ; i < 26 ; i ++)
			{
				if (FastIoDispatch[i] &&
					(FastIoDispatch[i] < ntosinfo.Base || FastIoDispatch[i] > ntosinfo.Base + ntosinfo.Size))
				{
					if (strlen(fastioname[i]) > LongestNameLen)
					{
						LongestNameLen = strlen(fastioname[i]);
					}
				}
				
			}
			for (i = 0 ; i < 26 ; i ++)
			{
				if (FastIoDispatch[i])
				{
					BOOL bShowFuncName = TRUE ; 
					exctx.Addreess = FastIoDispatch[i]; 
					exctx.pModName = (WCHAR*)&ModName ;
					chkkmod(vmxindex , CallBackFindModuleEx , &exctx);
					
					nctx.AddAddr = 0 ;
					nctx.Addreess = exctx.Addreess + 0x20000000 - exctx.Base; 
					nctx.SourceName = (CHAR*)&FuncName ;

					if (!GetModSymbol(vmxindex , exctx.Base , 0 , SymbolGetNameFromAddr , &nctx , SysName , &LoadAddr) ||
						nctx.AddAddr !=0)
					{
						fmctx.Addreess = FastIoDispatch[i] ; 
						fmctx.pModName = (WCHAR*)&ModName;
						chkkmod(vmxindex , CallBackFindModule , &fmctx);
						bShowFuncName = FALSE ; 
					}


					FINDMOD_CTX findmod ; 
					WCHAR ModName[MAX_PATH] = L"unknown module";
					findmod.Addreess = FastIoDispatch[i];
					findmod.pModName = (WCHAR*)&ModName;
					chkkmod(vmxindex , CallBackFindModule , &findmod);
					printf("%s" , fastioname[i]);
					if (strlen(fastioname[i]) < LongestNameLen)
					{
						ULONG charleft = LongestNameLen - strlen(fastioname[i]);
						while(charleft)
						{
							printf(" ");
							charleft--;
						}
					}
					if (!bShowFuncName)
					{
						printf(" : %08x -> %ws\n" , FastIoDispatch[i] , fmctx.pModName );
					}
					else
					{
						printf(" : %08x -> %ws!%s\n" , FastIoDispatch[i] , exctx.pModName , nctx.SourceName );
						
					}
					

					
				}
				
			}
		}
		
		while(pCurrentDevObj)
		{
			printf("\nDeviceObject : %08x " ,pCurrentDevObj);
			if (GetObjFullName(vmxindex , (PVOID)pCurrentDevObj , (WCHAR*)&DevName , 100 ))
			{
				printf("DeviceName : %ws\n" , DevName);
			}
			else
			{
				printf("\n");
			}

			ULONG AttachedDevice ;

			readmem(vmxindex , (PVOID)(pCurrentDevObj + 0x10) , &AttachedDevice , sizeof(ULONG));
			ULONG AttachCount = 1 ; 
			while(AttachedDevice)
			{
				for (i = 0 ;i < AttachCount ;i++)
				{
					printf("  ");
				}
				printf("|___");

				printf("Attached Dev : %08x " , AttachedDevice);
				if (GetObjFullName(vmxindex , (PVOID)AttachedDevice , (WCHAR*)&DevName , 100))
				{
					printf("DevName: %ws " , DevName);
				}
				ULONG AttachedDrv ; 
				readmem(vmxindex , (PVOID)(AttachedDevice + 0x8) , &AttachedDrv ,sizeof(ULONG));
				printf("Drv : %08x " , AttachedDrv);
				if (GetObjFullName(vmxindex , (PVOID)AttachedDrv , (WCHAR*)&DevName , 100))
				{
					printf("DrvName : %ws\n" , DevName);
				}
				else
				{
					printf("\n");
				}
				readmem(vmxindex , (PVOID)(AttachedDevice + 0x10) , &AttachedDevice , sizeof(ULONG));
				AttachCount++;
			}

			readmem(vmxindex , (PVOID)(pCurrentDevObj + 0xc) , &pCurrentDevObj , sizeof(ULONG));
		}

	}

	getchar();
	return ;
}
				PIMAGE_SECTION_HEADER
RtlImageRvaToSection(
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Rva
    )

/*++

Routine Description:

    This function locates an RVA within the image header of a file
    that is mapped as a file and returns a pointer to the section
    table entry for that virtual address

Arguments:

    NtHeaders - Supplies the pointer to the image or data file.

    Base - Supplies the base of the image or data file.  The image
        was mapped as a data file.

    Rva - Supplies the relative virtual address (RVA) to locate.

Return Value:

    NULL - The RVA was not found within any of the sections of the image.

    NON-NULL - Returns the pointer to the image section that contains
               the RVA

--*/

{
    ULONG i;
    PIMAGE_SECTION_HEADER NtSection;

    NtSection = IMAGE_FIRST_SECTION( NtHeaders );
    for (i=0; i<NtHeaders->FileHeader.NumberOfSections; i++) {
        if (Rva >= NtSection->VirtualAddress &&
            Rva < NtSection->VirtualAddress + NtSection->SizeOfRawData
           ) {
            return NtSection;
            }
        ++NtSection;
        }

    return NULL;
}



PVOID
RtlImageRvaToVa(
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Rva)

/*++

Routine Description:

    This function locates an RVA within the image header of a file that
    is mapped as a file and returns the virtual addrees of the
    corresponding byte in the file.


Arguments:

    NtHeaders - Supplies the pointer to the image or data file.

    Base - Supplies the base of the image or data file.  The image
        was mapped as a data file.

    Rva - Supplies the relative virtual address (RVA) to locate.

Return Value:

    NULL - The file does not contain the specified RVA

    NON-NULL - Returns the virtual addrees in the mapped file.

--*/

{
	PIMAGE_SECTION_HEADER  NtSection;

    NtSection = RtlImageRvaToSection( NtHeaders,
                                          Base,
                                          Rva
                                        );

    if (NtSection != NULL) {

        return (PVOID)((PCHAR)Base +
                       (Rva - NtSection->VirtualAddress) +
                       NtSection->PointerToRawData
                      );
        }
    else {
        return NULL;
        }
}
PVOID MapSectionAndReloc(PIMAGE_NT_HEADERS nthdr , 
						 PIMAGE_SECTION_HEADER SecHdr ,
						 PVOID BaseOfPe , 
						 ULONG NewBase)
{
	//map section 
	PVOID pSection = malloc(SecHdr->Misc.VirtualSize);
	memcpy(pSection , (PVOID)((ULONG)BaseOfPe + SecHdr->PointerToRawData) , SecHdr->Misc.VirtualSize);

	// do relocation
	PIMAGE_BASE_RELOCATION Reloc ; 
	ULONG relocsize ; 
	ULONG ImageBaseDelta ; 
	ULONG Size  = 0 ; 
	ULONG Number ;
	PUSHORT Rel ; 
	PIMAGE_BASE_RELOCATION pRelocBase ; 

	relocsize = nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size ;
	Reloc = (PIMAGE_BASE_RELOCATION)(RtlImageRvaToVa(nthdr , 
		BaseOfPe ,
		nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ));
	ImageBaseDelta = (ULONG)NewBase - nthdr->OptionalHeader.ImageBase ; 
	pRelocBase = Reloc ; 
	
	while(relocsize > Size)
	{
		ULONG i ; 
		Size += Reloc->SizeOfBlock ; 
		Number = (Reloc->SizeOfBlock - 8 ) /2 ; 
		Rel = (PUSHORT)((ULONG)Reloc + 8);
		for (i = 0 ; i < Number ; i++)
		{
			ULONG TargetAddr = Reloc->VirtualAddress + (*(ULONG*)Rel & 0xfff);

			if ((*(ULONG*)Rel & 0xf000) == 0x3000 &&
				TargetAddr >= SecHdr->VirtualAddress &&
				TargetAddr < SecHdr->VirtualAddress + SecHdr->Misc.VirtualSize)
			{
				ULONG FinalAddr = TargetAddr - SecHdr->VirtualAddress + (ULONG)pSection ;
				*(PULONG)(FinalAddr) += ImageBaseDelta ; 
			}
			Rel = (PUSHORT)((ULONG)Rel + 2);
		}
		Reloc = (PIMAGE_BASE_RELOCATION)((ULONG)pRelocBase + Size);
	}
	return pSection ; 

}
PVOID pCachePool = NULL;
ULONG CacheAddr = 0 ;
BOOL memreadbytecache(ULONG vmxindex , ULONG Addr , PBYTE outbyte)
{
	if (pCachePool == NULL)
	{
		pCachePool = malloc(0x1000);
		if (!readmem(vmxindex , (PVOID)Addr , pCachePool , 0x1000))
		{
			return FALSE ; 
		}
		CacheAddr = Addr ; 

		*outbyte = *(BYTE*)(pCachePool);
		return TRUE; 
	}
	if (Addr >= CacheAddr && Addr < CacheAddr + 0x1000)
	{
		*outbyte = *(BYTE*)((ULONG)pCachePool + (Addr - CacheAddr));
		return TRUE; 
	}
	else
	{
		if (!readmem(vmxindex , (PVOID)Addr , pCachePool , 0x1000))
		{
			return FALSE ; 
		}
		*outbyte = *(BYTE*)pCachePool ; 
		CacheAddr = Addr ; 
		return TRUE; 
	}

}
VOID ProcessHookTarget(ULONG vmxindex , ULONG ModBase , ULONG LoadAddr,ULONG HookTargetAddr , ULONG OrgPtr , BOOL GetNeg , BOOL bSSDT)
{
	FINDMOD_CTX ctx ; 
	WCHAR ModName[MAX_PATH] = L"Unknown Module";
	CHAR FuncName[100] = "UnknownFunction";
	CHAR SysName[MAX_PATH];
	if (bSSDT)
	{
		ctx.Addreess = HookTargetAddr ; 
		ctx.pModName = (WCHAR*)&ModName ;
		
		chkkmod(vmxindex , CallBackFindModule , &ctx);
		printf("\t Jump to [%08x] Module :%ws\n", ctx.Addreess , ctx.pModName);
		
		
	}
	BYTE BytesData[9];
	NAMETOADDR_CTX nctx ; 
	readmem(vmxindex , (PVOID)(HookTargetAddr - 2) , 
								&BytesData , 
								9);

	ULONG JumpAddr ; 
	if (GetNeg && BytesData[0] == 0xff && 
		(BytesData[1] == 0x15 || BytesData[2] == 0x25 || BytesData[3] == 0x35))
	{
		JumpAddr = *(ULONG*)((ULONG)&BytesData + 2);
		readmem(vmxindex , (PVOID)JumpAddr , &JumpAddr , 4);
		ctx.Addreess = JumpAddr ; 
		ctx.pModName = (WCHAR*)&ModName ;
		
		chkkmod(vmxindex , CallBackFindModule , &ctx);
		printf("\t Jump to [%08x] Module :%ws\n", ctx.Addreess , ctx.pModName);
	
		ProcessHookTarget(vmxindex , 0 , 0 , JumpAddr , 0 , FALSE , FALSE);


	}
	else if (GetNeg && BytesData[1] == 0xe9 || BytesData[1] == 0xe8)
	{
		JumpAddr = *(ULONG*)((ULONG)&BytesData + 2)+4+HookTargetAddr;
		ctx.Addreess = JumpAddr ; 
		ctx.pModName = (WCHAR*)&ModName ;
		
		chkkmod(vmxindex , CallBackFindModule , &ctx);
		printf("\t Jump to [%08x] Module :%ws\n", ctx.Addreess , ctx.pModName);
		nctx.AddAddr = 0 ;
		nctx.Addreess = *(ULONG*)(OrgPtr) + 4 + HookTargetAddr - ModBase + LoadAddr ;
		nctx.SourceName = (CHAR*)&FuncName;
		GetModSymbol(vmxindex, ModBase , 0 , SymbolGetNameFromAddr , &nctx , SysName , &LoadAddr);
		
		printf("\t CallAddress Original : [%08x]:%s\n" , *(ULONG*)(OrgPtr) + 4 + HookTargetAddr , nctx.SourceName);
		
		ProcessHookTarget(vmxindex , 0 , 0 , JumpAddr , 0 , FALSE , FALSE);
		
	}
	else if (BytesData[2] == 0xe9 || BytesData[2] == 0xe8)
	{
		JumpAddr = *(ULONG*)((ULONG)&BytesData + 3) + 5 + HookTargetAddr;
		ctx.Addreess = JumpAddr ; 
		ctx.pModName = (WCHAR*)&ModName ;
		
		chkkmod(vmxindex , CallBackFindModule , &ctx);
		printf("\t Jump to [%08x] Module :%ws\n", ctx.Addreess , ctx.pModName);
		
		ProcessHookTarget(vmxindex , 0 , 0 , JumpAddr , 0 , FALSE , FALSE);

	}
	else if (BytesData[2] == 0xff &&
		(BytesData[3] == 0x15 || BytesData[3] == 0x25 || (BytesData[3] == 0x35 && BytesData[8] == 0xc3)))
	{
		JumpAddr = *(ULONG*)((ULONG)&BytesData + 4);
		readmem(vmxindex , (PVOID)JumpAddr , &JumpAddr , 4);
		ctx.Addreess = JumpAddr ; 
		ctx.pModName = (WCHAR*)&ModName ;
		
		chkkmod(vmxindex , CallBackFindModule , &ctx);
		printf("\t Jump to [%08x] Module :%ws\n", ctx.Addreess , ctx.pModName);
		
		ProcessHookTarget(vmxindex , 0 , 0 , JumpAddr , 0 , FALSE , FALSE);

	}
	else if (BytesData[2] == 0x68 && BytesData[7] == 0xc3)
	{
		JumpAddr = *(ULONG*)((ULONG)&BytesData + 3);
		ctx.Addreess = JumpAddr ; 
		ctx.pModName = (WCHAR*)&ModName ;
		
		chkkmod(vmxindex , CallBackFindModule , &ctx);
		printf("\t Jump to [%08x] Module :%ws\n", ctx.Addreess , ctx.pModName);
		
		ProcessHookTarget(vmxindex , 0 , 0 , JumpAddr , 0 , FALSE , FALSE);
	}
	else
	{
		BYTE ReadCode[0x50];
		readmem(vmxindex , (PVOID)HookTargetAddr , &ReadCode , 0x50 );
		ULONG i ;
		for (i = (ULONG)&ReadCode ; i < (ULONG)&ReadCode + 0x40 ; i++)
		{
			if (*(BYTE*)i >= 0xb8 && *(BYTE*)i <= 0xbf &&
				*(BYTE*)(i + 4) > 0x80)
			{
				ctx.Addreess = *(ULONG*)(i + 1) ; 
				ctx.pModName = (WCHAR*)&ModName ;
				
				chkkmod(vmxindex , CallBackFindModule , &ctx);
				if (wcscmp(ctx.pModName , L"Unknown Module"))
				{
					printf("\t Jump to [%08x] Module :%ws\n", ctx.Addreess , ctx.pModName);

				}
				break;
				
			}
		}
	}


	return ; 
}
void CheckInlineHook(ULONG vmxindex)
{
	NTOS_INFO ntosinfo ; 
	ULONG i ;
	CHAR SymbolName[100];
	chkkmod(vmxindex ,CallBackGetNtosInfo , &ntosinfo);
	NAMETOADDR_CTX ctx ; 
	strcpy(SymbolName , "NtSetValueKey");
	ctx.SourceName = SymbolName;
	ctx.Addreess = 0 ;
	ctx.AddAddr = 0 ;
	ULONG LoadAddr ; 
	CHAR SysName[MAX_PATH];



	if (!GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr))
	{
		printf("Symbol Err\n");
		getchar();
		return ;
	}
	
	HANDLE hFile = CreateFile(SysName , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , 0 , 0 );

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return ; 
	}

	HANDLE hMap = CreateFileMapping(hFile , 0 , PAGE_READONLY , 0 , 0 , 0 );

	PVOID pPeMapped = MapViewOfFile(hMap , FILE_MAP_READ , 0 , 0 , 0);


	PIMAGE_DOS_HEADER DosHdr = (PIMAGE_DOS_HEADER)pPeMapped ; 
	PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)((ULONG)pPeMapped + DosHdr->e_lfanew);
	ULONG ImportAddrTableBase , ImportAddressTableEnd ; 

	ImportAddrTableBase = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress ; 
	ImportAddressTableEnd = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size + ImportAddrTableBase;

	PIMAGE_SECTION_HEADER SecHdr = IMAGE_FIRST_SECTION(NtHdr);
	ULONG j ; 
	BOOL FindForMatch ;
	ULONG NotMatchStart; 
	for (i = 0 ; i < NtHdr->FileHeader.NumberOfSections ; i++)
	{
		if ((SecHdr->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_NOT_PAGED)) == (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_NOT_PAGED) ||
			strnicmp((CHAR*)SecHdr->Name , "PAGE" , 8) == 0 ||
			strnicmp((CHAR*)SecHdr->Name , "POOLMI" , 8) == 0 ||
			strnicmp((CHAR*)SecHdr->Name , "MISYSPTE" , 8) == 0 ||
			strnicmp((CHAR*)SecHdr->Name , "POOLCODE" , 8) == 0 ||
			strnicmp((CHAR*)SecHdr->Name , "PAGELK" , 8) == 0 ||
			strnicmp((CHAR*)SecHdr->Name , "PAGEWMI" , 8) == 0 ||
			strnicmp((CHAR*)SecHdr->Name , "PAGEHDLS" , 8) == 0)
		{
			CHAR SectionName[9];
			strncpy(SectionName , (CHAR*)SecHdr->Name , 8);
			SectionName[8] = '\0';
			printf("Checking Section %s %u Bytes....\n",SectionName , SecHdr->Misc.VirtualSize);
			PVOID pMappedSection = MapSectionAndReloc(NtHdr, SecHdr , pPeMapped, ntosinfo.Base);
			FindForMatch = FALSE ; 
			NotMatchStart = 0 ; 
			for (j = 0 ; j < SecHdr->Misc.VirtualSize ; j++)
			{
				BYTE readbyte ; 

				//ignore iat 
				if (SecHdr->VirtualAddress + j >= ImportAddrTableBase &&
					SecHdr->VirtualAddress +j < ImportAddressTableEnd)
				{
					continue ; 
				}
				if (memreadbytecache(vmxindex , (ULONG)(SecHdr->VirtualAddress + j + ntosinfo.Base) ,
					&readbyte ))
				{
					if (FindForMatch == FALSE)
					{
						if (readbyte != *(BYTE*)(j + (ULONG)pMappedSection))
						{
							FindForMatch = TRUE ; 
							NotMatchStart = j + SecHdr->VirtualAddress ;
						}
					}
					else
					{
						if (readbyte == *(BYTE*)(j + (ULONG)pMappedSection))
						{	
							FindForMatch = FALSE ; 
							ctx.AddAddr = 0 ;
							ctx.Addreess = NotMatchStart + LoadAddr; 
							strcpy(ctx.SourceName , "Unknown Function");
							if (!GetModSymbol(vmxindex , 
								ntosinfo.Base , 
								ntosinfo.Size , 
								SymbolGetNameFromAddr , 
								&ctx , 
								SysName, 
								&LoadAddr))
							{
								ctx.AddAddr = 0 ;
							}

							if (ctx.AddAddr)
							{
								printf("Hook: %08x length %x %s + %x\n" , NotMatchStart +ntosinfo.Base , 
									j + SecHdr->VirtualAddress - NotMatchStart ,
									ctx.SourceName,
									ctx.AddAddr);
							}
							else
							{
								printf("Hook : %x length %x %s\n" , NotMatchStart + ntosinfo.Base, 
									j + SecHdr->VirtualAddress - NotMatchStart ,
									ctx.SourceName);
							}
							if (stricmp(ctx.SourceName, "KiServiceTable") == 0)
							{
								//continue;
								ULONG k ; 
								for (k = 0 ; k < (j + SecHdr->VirtualAddress - NotMatchStart) / 4 ; k++)
								{
									ULONG JumpToAddr ; 
									ctx.AddAddr = 0 ;
									ctx.Addreess = *(ULONG*)(NotMatchStart - SecHdr->VirtualAddress + (ULONG)pMappedSection + k * 4 ) - ntosinfo.Base + LoadAddr;
									strcpy(ctx.SourceName , "UnknownSSDT");
									if (!GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetNameFromAddr , &ctx , SysName , &LoadAddr))
									{
										ctx.AddAddr = 0 ; 
									}

									printf("\tSSDT HOOK : %s\n" , ctx.SourceName );
									readmem(vmxindex , (PVOID)(NotMatchStart + ntosinfo.Base + k * 4) , &JumpToAddr , 4);
									ProcessHookTarget(vmxindex , 0 , 0 ,JumpToAddr , 0 , FALSE ,TRUE);


								}
								
							}

							ProcessHookTarget(vmxindex ,
								ntosinfo.Base ,
								LoadAddr,
								NotMatchStart +  ntosinfo.Base ,
								NotMatchStart - SecHdr->VirtualAddress + (ULONG)pMappedSection,
								TRUE  ,FALSE);


							
						//	getchar();
						}	
					}
				}
			}


			free(pMappedSection);
		}
		SecHdr ++ ; 
	}

	UnmapViewOfFile(pPeMapped);

	CloseHandle(hMap);
	CloseHandle(hFile);

	printf("Kernel inline hook scan fininished\n");

	getchar();

	return ; 



}
void CheckCallback(ULONG vmxindex)
{
	NTOS_INFO ntosinfo ; 
	ULONG i ;
	CHAR SymbolName[100];
	chkkmod(vmxindex ,CallBackGetNtosInfo , &ntosinfo);
	NAMETOADDR_CTX ctx ; 
	strcpy(SymbolName , "PspCreateProcessNotifyRoutine");
	ctx.SourceName = SymbolName;
	ctx.Addreess = 0 ;
	ctx.AddAddr = 0 ;
	ULONG LoadAddr ; 
	CHAR SysName[MAX_PATH];
	FINDMOD_CTX fmctx ; 
	WCHAR ModName[MAX_PATH] = L"Unknown Module";
	
	
	
	
	if (!GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr))
	{
		printf("Symbol Err\n");
		getchar();
		return ;
	}
	ULONG cpnr = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	printf("PspCreateProcessNotifyRoutine:%08x\n", cpnr);

	strcpy(SymbolName , "PspCreateProcessNotifyRoutineCount");

	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG cpnrct = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	ULONG cpnrcount ; 
	readmem(vmxindex , (PVOID)cpnrct , &cpnrcount , 4);
	printf("PspCreateProcessNotifyRoutineCount:%08x Count = %x\nList CreateProcessNotifyRoutines:\n", cpnrct , cpnrcount);

	for (i = 0 ; i < cpnrcount ; i++)
	{
		ULONG pCallback  ,finaladdr;
		readmem(vmxindex , (PVOID)((ULONG)cpnr + i * 4) , &pCallback , 4);
		pCallback = (pCallback & 0xfffffff8) + 4; 
		readmem(vmxindex , (PVOID)pCallback , &finaladdr , 4);
		fmctx.Addreess = finaladdr ; 
		fmctx.pModName = (WCHAR*)&ModName;
		chkkmod(vmxindex , CallBackFindModule , &fmctx);
		printf("%x.[%08x] %ws\n" , i , finaladdr , fmctx.pModName);
		
	}
	printf("\n\n===========================================\n\n");
	strcpy(ctx.SourceName , "PspCreateThreadNotifyRoutine");
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG ctnr = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	printf("PspCreateThreadNotifyRoutine:%08x\n", ctnr);
	
	strcpy(SymbolName , "PspCreateThreadNotifyRoutineCount");
	
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG ctnrct = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	ULONG ctnrcount ; 
	readmem(vmxindex , (PVOID)ctnrct , &ctnrcount , 4);
	printf("PspCreateThreadNotifyRoutineCount:%08x Count = %x\n", ctnrct , ctnrcount);
	for (i = 0 ; i < ctnrcount ; i++)
	{
		ULONG pCallback  ,finaladdr;
		readmem(vmxindex , (PVOID)((ULONG)ctnr + i * 4) , &pCallback , 4);
		pCallback = (pCallback & 0xfffffff8) + 4; 
		readmem(vmxindex , (PVOID)pCallback , &finaladdr , 4);
		fmctx.Addreess = finaladdr ; 
		fmctx.pModName = (WCHAR*)&ModName;
		chkkmod(vmxindex , CallBackFindModule , &fmctx);
		printf("%x.[%08x] %ws\n" , i , finaladdr , fmctx.pModName);
		
	}
	
	printf("\n===========================================\n\n");
	strcpy(ctx.SourceName , "PspLoadImageNotifyRoutine");
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG linr = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	printf("PspLoadImageNotifyRoutine:%08x\n", linr);
	
	strcpy(SymbolName , "PspLoadImageNotifyRoutineCount");
	
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG linrct = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	ULONG linrcount ; 
	readmem(vmxindex , (PVOID)linrct , &linrcount , 4);
	printf("PspLoadImageNotifyRoutineCount:%08x Count = %x\n", linrct , linrcount);
	for (i = 0 ; i < linrcount ; i++)
	{
		ULONG pCallback  ,finaladdr;
		readmem(vmxindex , (PVOID)((ULONG)linr + i * 4) , &pCallback , 4);
		pCallback = (pCallback & 0xfffffff8) + 4; 
		readmem(vmxindex , (PVOID)pCallback , &finaladdr , 4);
		fmctx.Addreess = finaladdr ; 
		fmctx.pModName = (WCHAR*)&ModName;
		chkkmod(vmxindex , CallBackFindModule , &fmctx);
		printf("%x.[%08x] %ws\n" , i , finaladdr , fmctx.pModName);
		
	}

	printf("\n===========================================\n\n");

	strcpy(ctx.SourceName , "CmpCallBackVector");
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG cbvr = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	printf("CmpCallBackVector:%08x\n", cbvr);
	
	strcpy(SymbolName , "CmpCallBackCount");
	
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG cbvrct = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	ULONG cbvrcount ; 
	readmem(vmxindex , (PVOID)cbvrct , &cbvrcount , 4);
	printf("CmpCallBackCount:%08x Count = %x\nList CmRegisterCallbacks:\n", cbvrct , cbvrcount);
	for (i = 0 ; i < cbvrcount ; i++)
	{
		ULONG pCallback  ,finaladdr;
		readmem(vmxindex , (PVOID)((ULONG)cbvr + i * 4) , &pCallback , 4);
		pCallback = (pCallback & 0xfffffff8) + 4; 
		readmem(vmxindex , (PVOID)pCallback , &finaladdr , 4);
		fmctx.Addreess = finaladdr ; 
		fmctx.pModName = (WCHAR*)&ModName;
		chkkmod(vmxindex , CallBackFindModule , &fmctx);
		printf("%x.[%08x] %ws\n" , i , finaladdr , fmctx.pModName);
		
	}
	printf("\n\n===========================================\n\n");
	
	strcpy(ctx.SourceName , "KeBugCheckCallbackListHead");
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
	ULONG bccblh = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	printf("KeBugCheckCallbackListHead = %08x\nList KeBugCheckCallbacks\n" , bccblh );
	ULONG ListItem;
	ULONG Count = 0 ;
	readmem(vmxindex , (PVOID)bccblh , &ListItem , 4);
	while(bccblh != ListItem)
	{
		ULONG CallbackRoutine ;
		readmem(vmxindex , (PVOID)(ListItem + 8) , &CallbackRoutine , 4);

		FINDMODEX_CTX exctx ; 
		exctx.Addreess = CallbackRoutine ; 
		exctx.pModName = (WCHAR*)ModName;
		chkkmod(vmxindex , CallBackFindModuleEx , &exctx);
		
		ctx.AddAddr = 0 ;
		ctx.Addreess = CallbackRoutine - exctx.Base + 0x20000000;
		if (!GetModSymbol(vmxindex , exctx.Base , exctx.Size , SymbolGetNameFromAddr , &ctx, SysName , &LoadAddr) ||
			ctx.AddAddr != 0)
		{
			fmctx.Addreess = CallbackRoutine ; 
			fmctx.pModName = (WCHAR*)&ModName;
			chkkmod(vmxindex , CallBackFindModule , &fmctx);
			printf("%x. [%08x] %ws\n" , Count , fmctx.Addreess , fmctx.pModName);
			
		}
		else
		{
			printf("%x. [%08x] %ws!%s\n" , Count , fmctx.Addreess , exctx.pModName , ctx.SourceName);
		}
		Count++;
		readmem(vmxindex , (PVOID)ListItem , &ListItem , 4);
	}
	printf("\n\n===========================================\n\n");
	
	strcpy(ctx.SourceName , "KeBugCheckReasonCallbackListHead");
	GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr);
    bccblh = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
	printf("KeBugCheckReasonCallbackListHead = %08x\nList KeBugCheckReasonCallbacks\n" , bccblh );
	 ListItem;
	 Count = 0 ;
	readmem(vmxindex , (PVOID)bccblh , &ListItem , 4);
	while(bccblh != ListItem)
	{
		ULONG CallbackRoutine ;
		readmem(vmxindex , (PVOID)(ListItem + 8) , &CallbackRoutine , 4);
		
		FINDMODEX_CTX exctx ; 
		exctx.Addreess = CallbackRoutine ; 
		exctx.pModName = (WCHAR*)ModName;
		chkkmod(vmxindex , CallBackFindModuleEx , &exctx);

		ctx.AddAddr = 0 ;
		ctx.Addreess = CallbackRoutine - exctx.Base + 0x20000000;
		if (!GetModSymbol(vmxindex , exctx.Base , exctx.Size , SymbolGetNameFromAddr , &ctx, SysName , &LoadAddr) ||
			ctx.AddAddr != 0)
		{
			fmctx.Addreess = CallbackRoutine ; 
			fmctx.pModName = (WCHAR*)&ModName;
			chkkmod(vmxindex , CallBackFindModule , &fmctx);
			printf("%x. [%08x] %ws\n" , Count , fmctx.Addreess , fmctx.pModName);
		
		}
		else
		{
			printf("%x. [%08x] %ws!%s\n" , Count , fmctx.Addreess , exctx.pModName , ctx.SourceName);
		}

		Count++;
		readmem(vmxindex , (PVOID)ListItem , &ListItem , 4);
	}


	
	getchar();

	return ; 
}
CHAR* ProcedureNames[] = {"DumpProcedure",
"OpenProcedure",
"CloseProcedure",
"DeleteProcedure",
"ParseProcedure",
"SecurityProcedure",
"QueryNameProcedure",
"OkeyToCloseProcedure"};
CHAR* ObjectTypeNames[] = {"CmpKeyObjectType",
	"IoFileObjectType",
	"IoDeviceObjectType",
	"IoDriverObjectType",
	"PsThreadType",
	"PsProcessType",
	"MmSectionObjectType",
	"ExCallbackObjectType",
	"DbgkDebugObjectType",
	"ExEventObjectType",
	"ExEventPairObjectType",
	"IoAdapterObjectType",
	"IoDeviceHandlerObjectType",
	"IoControllerObjectType",
	"IoCompletionObjectType",
	"ExpKeyedEventObjectType",
	"LpcPortObjectType",
	"LpcWaitablePortObjectType",
	"ExMutantObjectType",
	"ObpTypeObjectType",
	"ObpDirectoryObjectType",
	"ObpSymbolicLinkObjectType",
	"ExProfileObjectType",
	"PsJobType",
	"WmipGuidObjectType",
	"ExSemaphoreObjectType",
	"SeTokenObjectType",
	"ExWindowStationObjectType",
	"ExDesktopObjectType",
	"End"
	};

void CheckObjectHook(ULONG vmxindex)
{
	NTOS_INFO ntosinfo ; 
	ULONG i ;
	CHAR SymbolName[100];
	chkkmod(vmxindex ,CallBackGetNtosInfo , &ntosinfo);
	NAMETOADDR_CTX ctx ; 
	ctx.SourceName = SymbolName;
	ctx.Addreess = 0 ;
	ctx.AddAddr = 0 ;
	ULONG LoadAddr ; 
	CHAR SysName[MAX_PATH];	
	
	
	ULONG j = 0 ; 

	while(strcmp(ObjectTypeNames[j] , "End")!=0)
	{
		strcpy(SymbolName , ObjectTypeNames[j]);
		
		if (!GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetAddrFromName , &ctx  , SysName,&LoadAddr))
		{
			printf("Symbol Err\n");
			getchar();
			return ;
		}
		ULONG pObjectType = ctx.Addreess - LoadAddr + ntosinfo.Base ; 
		
		printf("%s = 0x%08x\n" , ObjectTypeNames[j],pObjectType);
		
		ULONG ObjType;
		
		readmem(vmxindex , (PVOID)pObjectType , &ObjType , sizeof(ULONG));
		
	//	printf("real %08x\n" , ObjType);
		if (ObjType == 0 )
		{
			j++;
			continue;
		}

		for (i = 0 ; i < 8 ; i++)
		{
			ULONG procedure ; 
			readmem(vmxindex , (PVOID)(ObjType + 0x8c + i * sizeof(ULONG)) , &procedure , sizeof(ULONG));
			
			if (procedure != 0 )
			{
				if (procedure < ntosinfo.Base || procedure > ntosinfo.Base + ntosinfo.Size)
				{
					printf("%s Hooked by %08x :\n" , ProcedureNames[i] , procedure);
					ProcessHookTarget(vmxindex , ntosinfo.Base , LoadAddr , procedure ,   0 , FALSE ,TRUE);
				}
				else
				{
					ctx.Addreess = procedure - ntosinfo.Base + LoadAddr ; 
					sprintf(ctx.SourceName , "Hooked In Ntoskrnl %08x\n" , procedure);
					
					if (!GetModSymbol(vmxindex , ntosinfo.Base , ntosinfo.Size , SymbolGetNameFromAddr , &ctx , SysName , &LoadAddr) ||
						ctx.AddAddr != 0 )
					{
						sprintf(ctx.SourceName , "Hooked In NtosKrnl %08x\n" ,procedure);
					}
					else
					{
						printf("%s : %s\n",ProcedureNames[i] , ctx.SourceName );
					}
					
				}
			}
		}
		printf("\n\n");

		j++;
	}


	getchar();

	return ; 

}
const CHAR xxstring[] = "This program cannot be run in DOS mode.";

void CheckHiddenMod(ULONG vmxindex)
{
	PVOID PageBuf = malloc(0x1000);
	ULONG readaddr = 0 ; 
	ULONG i ; 
	for (i = 0x80000000;i!=0 ;i+=0x1000)
	{
		if (!readmem(vmxindex , (PVOID)i , PageBuf , 0x1000))
		{
			continue ; 
		}
		if (*(BYTE*)PageBuf == 'M' && *(BYTE*)((ULONG)PageBuf+1) == 'Z')
		{
			if (*(ULONG*)((ULONG)PageBuf + 0x3c) + sizeof(IMAGE_NT_HEADERS) < 0x1000)
			{
				PIMAGE_NT_HEADERS pnthdr = (PIMAGE_NT_HEADERS)((ULONG)PageBuf + *(ULONG*)((ULONG)PageBuf + 0x3c)) ; 
				if (pnthdr->Signature == 0x4550)
				{
					if (pnthdr->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE)
					{
						FINDMODEX2_CTX ctx ;
						ctx.bFind = FALSE ;
						ctx.CheckSum = pnthdr->OptionalHeader.CheckSum ; 
						ctx.TimeStamp = pnthdr->FileHeader.TimeDateStamp;
						ctx.Addr = i ;

						if (g_PageRead == NULL)
						{
							g_PageRead = malloc(0x1000);
						}

						chkkmod(vmxindex , CallBackFindModuleEx2 , &ctx);

						if (ctx.bFind == FALSE)
						{
							IMAGE_DOS_HEADER doshdr ; 
							IMAGE_NT_HEADERS nthdr ; 
							ULONG j ; 
							readmem(vmxindex , (PVOID)i , &doshdr , sizeof(IMAGE_DOS_HEADER));
							
							readmem(vmxindex , (PVOID)(i + doshdr.e_lfanew) , &nthdr , sizeof(IMAGE_NT_HEADERS));
							
							IMAGE_DEBUG_DIRECTORY debugdata ; 
							
							readmem(vmxindex , 
								(PVOID)(nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + i ),
								&debugdata , 
								sizeof(IMAGE_DEBUG_DIRECTORY));

							ULONG tt = nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + i;
							
							PIMAGE_SECTION_HEADER pSecHdr =  (PIMAGE_SECTION_HEADER)(i + doshdr.e_lfanew + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +  nthdr.FileHeader.SizeOfOptionalHeader);
							ULONG VirtualAddr  = 0 ; 
							
							for (j = 0 ; j < nthdr.FileHeader.NumberOfSections ; j++)
							{
								IMAGE_SECTION_HEADER sechdr ; 
								readmem(vmxindex , pSecHdr , &sechdr , sizeof(IMAGE_SECTION_HEADER));
								if (sechdr.PointerToRawData <= debugdata.PointerToRawData && 
									sechdr.PointerToRawData + sechdr.SizeOfRawData > debugdata.PointerToRawData)
								{
									VirtualAddr = j + debugdata.PointerToRawData - sechdr.PointerToRawData + sechdr.VirtualAddress;
									break ; 
								}
								pSecHdr ++ ; 
							}
							
							PVOID pSymbolData = malloc(debugdata.SizeOfData);
							
							readmem(vmxindex , (PVOID)VirtualAddr , pSymbolData , debugdata.SizeOfData);
							
							
							LPSTR SymbolName = (LPSTR)((ULONG)pSymbolData + 0x18);
							SymbolName[strlen(SymbolName)-1] = 's';
							SymbolName[strlen(SymbolName)-2] = 'y';
							SymbolName[strlen(SymbolName)-3] = 's';
							printf("find hidden module :%08x moudle name:%s\n" , i , SymbolName);
						}
					}
				}
			}
		}
		else if (memcmp((PVOID)((ULONG)PageBuf + 0x4e)  , xxstring , sizeof(xxstring) - 1) == 0 )
		{

		}
	}
	free(PageBuf);
	free(g_PageRead);
	g_PageRead = NULL ;
	getchar();
}
void enumcurrentvmx()
{
	ULONG vmxnumber ; 
	__asm
	{
		call	EnumVmx
		mov		vmxnumber,eax
	}

	if (vmxnumber == 0 )
	{
		printf("donnot find any active VMX!\n");
		getchar();
		return ;
	}
	
	system("cls");
	printf("Active Vmx Count:%u\n" , vmxnumber);

	ULONG i ; 
	ULONG sl ; 
	ULONG vmxindex ; 
	ENUMVMX vmx ; 	
	BOOL bret ; 
	for (i = 0 ; i < vmxnumber ; i++)
	{
		bret = getvmx(i , &vmx);

		if (bret)
		{
			printf("[%u]:%s\n" , i+1 , vmx.VmxDisplayName);
		}
		else
		{
			printf("[%u]:This VMX is corrupted\n" , i+1);
		}
	}

	scanf("%u" , &sl);

	if (sl>vmxnumber)
	{
		cvmx(vmxnumber);
		return  ; 
	}

	bret = getvmx(sl-1 , &vmx);
	vmxindex = sl-1;
	

	if (!bret)
	{
		printf("this vmx is corrupted\n");
		cvmx(vmxnumber);
		return ; 
	}
	fflush(stdin);

	printf("Do you want to freeze this VMX ?(Y/N)\n");
	CHAR usl=getchar();
	if (usl == 'Y' || usl == 'y')
	{
		suspendvmx(&vmx);
	}
	fflush(stdin);

l1:
	printf("Vmx:%s\nVmx FileName:%ws\nMemory Size:%uKBs\nOS:%s\nVmx Memory File:%ws\n",
		vmx.VmxDisplayName,
		vmx.VmxName,
		vmx.MemSizeInMB * 1024 ,
		vmx.OsType,
		vmx.vmemPath);

	ShowSystemInfo(vmxindex);

	printf("\n\n1.List Kernel Modules\n"
		"2.List Processes\n"
		"3.View DebugPrint Information\n"
		"4.Object Walker\n"
		"5.Check SSDT Hook\n"
		"6.Check DriverObject Hook/ Device Attachment\n"
		"7.Check Kernel Inline Hook\n"
		"8.Check KernelMode Callback\n"
		"9.Check Object Hook\n"
		"10.Exit\n");

	sl=0;
	fflush(stdin);
	scanf("%u", &sl);
	fflush(stdin);
	switch(sl)
	{
	case 1:
		{
			listkmod(vmxindex);
		}break ; 
	case 2:
		{
			listproc(vmxindex);
		}break ; 
	case 3:
		{
			ViewDbgPrint(vmxindex);
		}break ;
	case 4:
		{
			ObjDir(vmxindex);
		}break ;
	case 5:
		{
			CheckSSDT(vmxindex);
		}break ; 
	case 6 :
		{
			CheckDriver(vmxindex);

		}break ; 
	case 7:
		{
			CheckInlineHook(vmxindex);
		}break;
	case 8:
		{
			CheckCallback(vmxindex);
		}break ;
	case 9:
		{
			CheckObjectHook(vmxindex);
		}break ;
	case 10:
		{
			CheckHiddenMod(vmxindex);
		}break;
		

	default:
		{
			if (vmx.Freezed == TRUE)
			{
				resumevmx(&vmx);
			}
			cvmx(vmxnumber);
			return ; 
		}break ; 
	}

	system("cls");
	goto l1;

	return ;



	
}
ULONG OpenVmm = 0 ;
void analyzeofflinevmm()
{
CHAR vmemPath[MAX_PATH]= "";
ULONG sl ;
printf("Input vmem file path:\n");
scanf("%s" , vmemPath);
if (strcmp(vmemPath , "1") == 0)
{
	strcpy(vmemPath , "c:\\vms\\WINXVM\\Windows XP Professional.vmem");
}
LPSTR pVmmPath = vmemPath ; 
__asm
{
	push pVmmPath
	call OpenVmm
	mov  pOfflineVmm , eax
}

if (pOfflineVmm == NULL)
{
	printf("cannot open this vmem\n");
	fflush(stdin);
	getchar();
	return ;
}

l1:

ShowSystemInfo(0);
	printf("\n\n1.List Kernel Modules\n"
		"2.List Processes\n"
		"3.View DebugPrint Information\n"
		"4.Object Walker\n"
		"5.Check SSDT Hook\n"
		"6.Check DriverObject Hook/ Device Attachment\n"
		"7.Check Kernel Inline Hook\n"
		"8.Check KernelMode Callback\n"
		"9.Check Object Hook\n"
		"10.Exit\n");

sl=0;
fflush(stdin);
scanf("%u", &sl);
fflush(stdin);
switch(sl)
{
case 1:
	{
		listkmod(0);
	}break ; 
case 2:
	{
		listproc(0);
	}break ; 
case 3:
	{
		ViewDbgPrint(0);
	}break ;
case 4:
	{
		ObjDir(0);
	}break ;
case 5:
	{
		CheckSSDT(0);
	}break ; 
case 6 :
	{
		CheckDriver(0);
		
	}break ; 
case 7:
	{
		CheckInlineHook(0);
	}break;	
case 8:
	{
		CheckCallback(0);
	}break ;
case 9:
	{
		CheckObjectHook(0);
	}break;
case 10:
	{
		CheckHiddenMod(0);
	}break ; 
	
default:
	{
		return ; 
	}break ; 
}

system("cls");
goto l1;

return ;

}
int main(int argc, char* argv[])
{

	printf("VMWare Anit-Rootkit tools\n"
		"By MJ0011 2009-9\n"
		);

	HMODULE vmalib = LoadLibrary("vmmaccess.dll");
	if (vmalib == NULL)
	{
		printf("cannot load engine!\n");
		return 0 ;
	}
	
	EnumVmx = GetProcAddress(vmalib , "EnumVMX" );
	GetVmxInfo =GetProcAddress(vmalib , "GetVMMInfo");
	CleanupVmx = GetProcAddress(vmalib , "CleanupVmm");
	writeva = GetProcAddress(vmalib , "WriteVirtualVmm");
	readva = GetProcAddress(vmalib , "ReadVirtualVmm");
	FreezeVmx = GetProcAddress(vmalib , "FreezeVmx");
	ThawVmx= GetProcAddress(vmalib , "ThawVmx");
	GetPhyAddr = GetProcAddress(vmalib , "GetPhyAddr");
	readpa = GetProcAddress(vmalib , "ReadPhyVmm");
	OpenVmm = (ULONG)GetProcAddress(vmalib , "OpenOfflineVmm");

	if (!EnumVmx || !GetVmxInfo || !writeva || !readva || !CleanupVmx || !GetPhyAddr ||
		!readpa || !OpenVmm)
	{
		printf("engine error %08x %08x %08x %08x %08x\n" ,
			EnumVmx,
			GetVmxInfo,
			writeva,
			readva , 
			CleanupVmx);
		return 0 ;
	}

	ULONG sl ; 

	printf("1.Enumerate Current VMX\n"
		"2.Analyze Offline VMX\n");


	scanf("%u",&sl);

	if (sl==1)
	{
		enumcurrentvmx();
		
	}
	else if(sl==2)
	{
		analyzeofflinevmm();
	}

	return 0 ; 
}

