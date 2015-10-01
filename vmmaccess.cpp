// vmmaccess.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "windows.h"
#include "shlwapi.h"
#include "tlhelp32.h"
#include "stdio.h"
#include "winioctl.h"
#include "vmmaccess.h"

#pragma  comment(lib, "shlwapi.lib")

CHAR xxsharebuf[3000];
char* __buf = xxsharebuf;


void	dbgmsg(const char* format, ...)
{
	
	va_list ap;
	
	va_start(ap, format);
	
	vsprintf(__buf, format, ap);
	
	OutputDebugString(__buf);
	
	va_end(ap);
	
	return ;	
}
#define MYDEBUG 1
#if MYDEBUG

#define VaPrint(_x_) dbgmsg _x_

#else

#define VaPrint(_x_)

#endif

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}


#define ProcessBasicInformation 0

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	PVOID Handle;
}CURDIR, *PCURDIR;

typedef struct PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
}PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;

typedef struct
{
    ULONG               AllocationSize;
    ULONG               Unknown1;
    HINSTANCE           ProcessHinstance;
    PVOID               ListDlls;
    PPROCESS_PARAMETERS ProcessParameters;
    ULONG               Unknown2;
    HANDLE              Heap;
} PEB, *PPEB;

typedef struct
{
    DWORD ExitStatus;
    PPEB  PebBaseAddress;
    DWORD AffinityMask;
    DWORD BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
}   PROCESS_BASIC_INFORMATION;

typedef LONG (WINAPI *PROCNTQSIP)(HANDLE,UINT,PVOID,ULONG,PULONG);


PROCNTQSIP NtQueryInformationProcess;


BOOL GetProcessCmdLine(HANDLE hProc,LPWSTR wBuf,DWORD dwBufLen)
{
    LONG                      status;
    PROCESS_BASIC_INFORMATION pbi;
    PEB                       Peb;
    PROCESS_PARAMETERS        ProcParam;
    DWORD                     dwDummy;
    DWORD                     dwSize;
    LPVOID                    lpAddress;
    BOOL                      bRet = FALSE;

	if (NtQueryInformationProcess == 0 )
	{
		HMODULE hntdll = GetModuleHandle("ntdll.dll");
		NtQueryInformationProcess = (PROCNTQSIP)GetProcAddress(hntdll , "NtQueryInformationProcess");
	}

	memset(wBuf , 0 , dwBufLen);

    // Retrieve information
    status = NtQueryInformationProcess( hProc,
                                        ProcessBasicInformation,
                                        (PVOID)&pbi,
                                        sizeof(PROCESS_BASIC_INFORMATION),
                                        NULL
                                      );


    if (status)
       return bRet ; 

    if (!ReadProcessMemory( hProc,
                            pbi.PebBaseAddress,
                            &Peb,
                            sizeof(PEB),
                            &dwDummy
                          )
       )
       return bRet ; 

    if (!ReadProcessMemory( hProc,
                            (PVOID)(Peb.ProcessParameters),
                            (PVOID)&ProcParam,
                            sizeof(PROCESS_PARAMETERS),
                            &dwDummy
                          )
       )
       return bRet ; 

    lpAddress = ProcParam.CommandLine.Buffer;
    dwSize = ProcParam.CommandLine.Length;

    if (dwBufLen + sizeof(WCHAR)<dwSize)
       return bRet ; 

    if (!ReadProcessMemory( hProc,
                            lpAddress,
                            wBuf,
                            dwSize,
                            &dwDummy
                          )
       )
       return bRet ; 


    bRet = TRUE;



     
    return bRet;
} 

ENUMVMX g_vmxs[20];
ULONG vmxindex = 0 ;
PVOID pZwQueryVirtualMemory = NULL ;
PVOID pZwQueryInformationThread = NULL ;
PVOID pZwCreateFile = NULL ; 
PVOID pRtlInitUnicodeString = NULL ;
PVOID pZwQueryInformationProcess = NULL ; 
typedef LONG NTSTATUS, *PNTSTATUS;
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
LONG MyZwQueryVirtualMemory(
					   HANDLE ProcessHandle,
					   ULONG BaseAddress,
					   ULONG MemoryInformationClass,
					   PVOID MemoryInformation,
					   SIZE_T MemoryInformationLength,
					   PSIZE_T ReturnLength
					   )
{
	LONG stat ; 
	if (pZwQueryVirtualMemory == NULL)
	{
		HMODULE hlib = LoadLibrary("ntdll.dll");
		pZwQueryVirtualMemory = GetProcAddress(hlib , "ZwQueryVirtualMemory");
		if (pZwQueryVirtualMemory == NULL)
		{
			return STATUS_UNSUCCESSFUL ; 
		}
	}
	__asm
	{
		push	ReturnLength
		push	MemoryInformationLength
		push	MemoryInformation
		push	MemoryInformationClass
		push	BaseAddress
		push	ProcessHandle
		call	pZwQueryVirtualMemory
		mov		stat , eax
	}
	return stat ; 
}


BOOL IsDosNtFileTheSame(LPWSTR FileNameNtPath , LPWSTR FileNameDosPath)
{
	ULONG DosNameEndingLen = (wcslen(FileNameDosPath) - 3 ) * sizeof(WCHAR);

	if (wcslen(FileNameNtPath) * sizeof(WCHAR) < DosNameEndingLen)
	{
		return FALSE ; 
	}
	LPWSTR NtPathCompareStart = (LPWSTR)((ULONG)FileNameNtPath + (wcslen(FileNameNtPath) * sizeof(WCHAR) - DosNameEndingLen));
	LPWSTR DosPathCompareStart = (LPWSTR)((ULONG)FileNameDosPath + sizeof(WCHAR) * 3);

	if (wcsnicmp(NtPathCompareStart , DosPathCompareStart , DosNameEndingLen / sizeof(WCHAR)) != 0)
	{
		return FALSE ; 
	}

	
	if (*(WCHAR*)((ULONG)FileNameDosPath + 2 * sizeof(WCHAR)) == L'\\')
	{
		WCHAR RawDevice[MAX_PATH];

		*(WCHAR*)((ULONG)FileNameDosPath + 2 * sizeof(WCHAR)) = L'\0';
		
		if (!QueryDosDeviceW(FileNameDosPath ,RawDevice ,   MAX_PATH))
		{
			*(WCHAR*)((ULONG)FileNameDosPath + 2 * sizeof(WCHAR)) = L'\\';
			return FALSE ; 
		}

		*(WCHAR*)((ULONG)FileNameDosPath + 2 * sizeof(WCHAR)) = L'\\';

		return (BOOL)(wcsnicmp(RawDevice , FileNameNtPath , wcslen(RawDevice)) == 0) ;


	}
	else
	{
		return FALSE ;
	}
}
typedef struct QUERY_ADDRESS_FILEOFFSET{
	HANDLE hProc ; 
	ULONG Address ; 
	LARGE_INTEGER FileOffset ; 
}QUERY_ADDRESS_FILEOFFSET , *PQUERY_ADDRESS_FILEOFFSET;
#define IOCTL_QUERY_ADDRESS_FILEOFFSET CTL_CODE(FILE_DEVICE_UNKNOWN , 0x800 , METHOD_BUFFERED , FILE_ANY_ACCESS)
//////////////////////////////////////////////////////////////////////////
//
// Get File Offset by mapped base address
//////////////////////////////////////////////////////////////////////////

BOOL GetFileOffsetByMappedAddress(PVOID Address , HANDLE hProc , PLARGE_INTEGER FileOffset)
{
	BOOL DrvIsLoaded = FALSE ; 

tryagain:


	HANDLE hDev = CreateFile("\\\\.\\vmmdetect",
		FILE_READ_ATTRIBUTES , 
		FILE_SHARE_READ | FILE_SHARE_WRITE , 
		0,
		OPEN_EXISTING , 
		0,
		0);

	if (hDev != INVALID_HANDLE_VALUE)
	{
		
		QUERY_ADDRESS_FILEOFFSET qb ; 
		ULONG btr ; 
		qb.Address = (ULONG)Address ; 
		qb.hProc = hProc ; 
		qb.FileOffset.QuadPart = 0 ; 

		if (!DeviceIoControl(hDev , 
			IOCTL_QUERY_ADDRESS_FILEOFFSET , 
			&qb , 
			sizeof(qb) , 
			&qb ,
			sizeof(qb),
			&btr , 
			NULL))
		{
			CloseHandle(hDev);
			VaPrint(("Device Io Control to vmmdetect device failed %u\n", GetLastError()));
			return FALSE  ; 
		}
		else
		{
			CloseHandle(hDev);
			FileOffset->QuadPart = qb.FileOffset.QuadPart ; 
			return TRUE ; 
		}
		
	}
	else
	{
		if (DrvIsLoaded)
		{
			VaPrint(("Driver is loaded but open handle failed! %u\n" , GetLastError()));
			return FALSE ; 
		}
		SC_HANDLE mhandle , shandle ; 

		mhandle = OpenSCManager(0 , 0 , SC_MANAGER_ALL_ACCESS);

		if (mhandle == 0 )
		{
			VaPrint(("open sc manager failed\n"));
			return FALSE ; 
		}

		shandle = OpenService(mhandle , "vmmdetect" , SERVICE_ALL_ACCESS);

		if (shandle == 0)
		{
			if (GetFileAttributes(".\\vmmdetect.sys")== INVALID_FILE_ATTRIBUTES)
			{
				VaPrint(("file vmmdetect.sys is not found!\n"));
				CloseServiceHandle(mhandle);
				return FALSE ; 
			}
			CHAR SystemDir[MAX_PATH];
			CHAR TargetDrvPath[MAX_PATH];

			GetSystemDirectoryA(SystemDir , MAX_PATH);

			sprintf(TargetDrvPath , "%s\\Drivers\\vmmdetect.sys" , SystemDir);

			if (!CopyFile(".\\vmmdetect.sys" , TargetDrvPath  , FALSE))
			{
				VaPrint(("copy file to drivers failed %u!\n" , GetLastError()));
				CloseServiceHandle(mhandle);
				return FALSE ; 
			}
			shandle = CreateService(mhandle , 
				"vmmdetect",
				"vmm detect driver",
				SERVICE_ALL_ACCESS , 
				SERVICE_KERNEL_DRIVER , 
				SERVICE_DEMAND_START , 
				SERVICE_ERROR_NORMAL ,
				TargetDrvPath , 
				NULL,
				0,
				NULL,
				NULL,
				NULL
				);
			if (shandle == 0 )
			{
				VaPrint(("CreateService failed %u\n" , GetLastError()));
				CloseServiceHandle(mhandle);
				return FALSE ; 
			}

			if (StartService(shandle , NULL , NULL) == FALSE)
			{
				VaPrint(("service is created but start service failed %u\n" , GetLastError()));
				CloseServiceHandle(shandle);
				CloseServiceHandle(mhandle);
				return FALSE ; 
			}
			else
			{
				CloseServiceHandle(shandle);
				CloseServiceHandle(mhandle);
				DrvIsLoaded = TRUE ; 
				goto tryagain;
			}
		}
		else
		{
			if (StartService(shandle , NULL , NULL) == FALSE)
			{
				VaPrint(("service is exist but start service failed %u" , GetLastError()));
				CloseServiceHandle(shandle);
				CloseServiceHandle(mhandle);
				return FALSE ; 
			}
			else
			{
				CloseServiceHandle(shandle);
				CloseServiceHandle(mhandle);
				DrvIsLoaded = TRUE ;
				goto tryagain ; 
			}
		}
	}
}

// 4096MB = 4GB
#define MAX_MEMDESC_MB 4096 
#define MAX_MEMDESCSIZE sizeof(VMMDESC) * MAX_MEMDESC_MB

////////////////////////////////////////////////////////////////////////////
// 
// Get VMX Memory Descriptor
//
//////////////////////////////////////////////////////////////////////////
BOOL GetVMXMemdesc(PENUMVMX vmxs )
{
	ULONG btr ; 
	
	ULONG CheckAddress = 0 ; 
	MEMORY_BASIC_INFORMATION basicinfo ; 
	SYSTEM_INFO SystemInfo ; 
	ULONG UserProbeAddress; 
	BOOL bFindish = FALSE ; 
	NTSTATUS stat ; 

	if (vmxs->MemSizeInMB > MAX_MEMDESC_MB)
	{
		VaPrint(("This VMX Memory = %u is too large!\n" , vmxs->MemSizeInMB));
		return FALSE ; 
	}
	PVOID pVmmDesc = malloc(MAX_MEMDESCSIZE);

	if (!pVmmDesc)
	{
		VaPrint(("allocate 64KB failed\n"));
		return FALSE ; 
	}

	vmxs->vmmdescnum = 0 ; 
	
	
	//get user highest address 

	GetSystemInfo(&SystemInfo);
	UserProbeAddress = (ULONG)SystemInfo.lpMaximumApplicationAddress;
	
	
	while(TRUE)
	{
		stat = MyZwQueryVirtualMemory(vmxs->vmprochandle , 
			CheckAddress , 
			0, 
			&basicinfo , 
			sizeof(MEMORY_BASIC_INFORMATION) , 
			&btr);
#define NT_SUCCESS(Status) ((LONG)(Status) >= 0)
		if (!NT_SUCCESS(stat))
		{
			bFindish = TRUE ; 
			break ; 
		}
		
		if (basicinfo.Type == MEM_MAPPED)
		{
			
			PVOID pNameBuffer = malloc(MAX_PATH * sizeof(WCHAR) + sizeof(UNICODE_STRING) );
			
			
			stat = MyZwQueryVirtualMemory(vmxs->vmprochandle , 
				CheckAddress , 
				2,
				pNameBuffer , 
				MAX_PATH * sizeof(WCHAR) + sizeof(UNICODE_STRING),
				&btr);
			
			//get mapped file name
			
			if (NT_SUCCESS(stat))
			{
			
				PUNICODE_STRING pName = (PUNICODE_STRING)pNameBuffer ; 

				//VaPrint(("Mapped File :%ws\n" , pName->Buffer));
			
				if (PathFileExistsW(vmxs->vmemPath))
				{
					if (IsDosNtFileTheSame(pName->Buffer , vmxs->vmemPath ) == TRUE)
					{
					//	VaPrint(("DOS NT PATH MATCHED! Base = %08x , Size = %08x\n" , basicinfo.BaseAddress , basicinfo.RegionSize));
						LARGE_INTEGER FileOffset ; 
						if (GetFileOffsetByMappedAddress(basicinfo.BaseAddress , vmxs->vmprochandle ,&FileOffset ))
						{
								VaPrint(("File Offset = %08x %08x\n" , FileOffset.HighPart, FileOffset.LowPart));
							PVMMDESC pCurrentDesc = (PVMMDESC)((ULONG)pVmmDesc + sizeof(VMMDESC) * vmxs->vmmdescnum);
							pCurrentDesc->FileOffset.QuadPart = FileOffset.QuadPart ; 
							pCurrentDesc->MappedAddress = basicinfo.BaseAddress ; 
							pCurrentDesc->MappedSize = basicinfo.RegionSize ; 
							vmxs->vmmdescnum ++ ; 
							if (vmxs->vmmdescnum > MAX_MEMDESC_MB)
							{
								printf("vmmdesc not enough to take mapped information!!\n");
								free(pNameBuffer);
								break ; 
							}
							
						}
						
						
					}
				}
				else
				{
					if (wcsnicmp((LPWSTR)((ULONG)pName->Buffer + pName->Length - 5 * sizeof(WCHAR)) , 
						L".vmem" , 
						5) == 0)
					{
						*(WCHAR*)(pName->Buffer + pName->Length / sizeof(WCHAR)) = L'\0';
						wcscpy(vmxs->vmemPath , pName->Buffer);
						LARGE_INTEGER FileOffset ; 
						if (GetFileOffsetByMappedAddress(basicinfo.BaseAddress , vmxs->vmprochandle ,&FileOffset ))
						{
							VaPrint(("File Offset = %08x %08x\n" , FileOffset.HighPart, FileOffset.LowPart));
							PVMMDESC pCurrentDesc = (PVMMDESC)((ULONG)pVmmDesc + sizeof(VMMDESC) * vmxs->vmmdescnum);
							pCurrentDesc->FileOffset.QuadPart = FileOffset.QuadPart ; 
							pCurrentDesc->MappedAddress = basicinfo.BaseAddress ; 
							pCurrentDesc->MappedSize = basicinfo.RegionSize ; 
							vmxs->vmmdescnum ++ ; 
							if (vmxs->vmmdescnum > MAX_MEMDESC_MB)
							{
								printf("vmmdesc not enough to take mapped information!!\n");
								free(pNameBuffer);
								break ; 
							}
							
						}
					}
				}


						
			}
			else
			{
				free(pNameBuffer);
			}
			
			
			
		}
		
		CheckAddress += basicinfo.RegionSize ; 
		if (CheckAddress > UserProbeAddress)
		{
			bFindish = TRUE ; 
			break ; 
		}
	}

	if (bFindish && vmxs->vmmdescnum != 0 )
	{
		vmxs->vmmdes = pVmmDesc ;
		return TRUE ; 
	}
	else
	{
		free(pVmmDesc);
	}
	
	return FALSE ; 
}

BOOL IsVMXExit(PENUMVMX vmx)
{
	DWORD exitcode ;
	if (!GetExitCodeProcess(vmx->vmprochandle , &exitcode))
	{
		return FALSE ; 
	}

	return (exitcode != STILL_ACTIVE);
}
#define PAGE_SHIFT 12
#define PAGE_SIZE 2^PAGE_SHIFT
BOOL ReadVMXMem(PVOID Base , ULONG Size ,PVOID Buf ,  PENUMVMX vmx)
{
	ULONG btr ; 
	if (!ReadProcessMemory(vmx->vmprochandle ,
		Base ,
		Buf , 
		Size, 
		&btr))
	{
		VaPrint(("ReadPhyMem: Read process memory failed %u , pid = %u Addr = %08x Size = %08x\n" , GetLastError(),
			vmx->vmpid , 
			Base , 
			Size));
		return FALSE ; 
	}
	else
	{
		return TRUE ; 
	}
}
BOOL WriteVMXMem(PVOID Base , ULONG Size ,PVOID Buf ,  PENUMVMX vmx)
{
	ULONG btr ; 
	if (!WriteProcessMemory(vmx->vmprochandle ,
		Base ,
		Buf , 
		Size, 
		&btr))
	{
		VaPrint(("WritePhyMem: Write process memory failed %u , pid = %u Addr = %08x Size = %08x\n" , GetLastError(),
			vmx->vmpid , 
			Base , 
			Size));
		return FALSE ; 
	}
	else
	{
		return TRUE ; 
	}
}
PVMMDESC GetVmmDescByOffset(ULONG Offset , PENUMVMX vmx)
{
	ULONG i ; 
	for (i = 0 ; i < vmx->vmmdescnum ; i ++)
	{
		PVMMDESC CurrentVmmDesc = (PVMMDESC)((ULONG)vmx->vmmdes + sizeof(VMMDESC) * i);
		
		if (CurrentVmmDesc->FileOffset.QuadPart <= Offset &&
			CurrentVmmDesc->FileOffset.QuadPart + CurrentVmmDesc->MappedSize > Offset)
		{
			return CurrentVmmDesc ; 
		}
	}

	return NULL ;
}

//size can be 4 bytes or 4096 bytes

BOOL __stdcall ReadPhyVmm(ULONG vmxindex , ULONG Offset , PVOID pBuffer , ULONG Size , POFFLINE_VMM ovmm)
{
	if (ovmm)
	{
		ULONG btr ; 
		if (SetFilePointer(ovmm->vmemFile , Offset , NULL , FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			return FALSE ; 
		}
		
		if (!ReadFile(ovmm->vmemFile , pBuffer , Size,&btr , NULL ))
		{
			return FALSE ; 
		}

		return TRUE ; 
	}


	if (IsVMXExit(&g_vmxs[vmxindex]))
	{
		return FALSE ;
	}
	PENUMVMX pvmx = &g_vmxs[vmxindex] ; 
	PVMMDESC Vmm = GetVmmDescByOffset(Offset , pvmx);
	
	if (!Vmm)
	{
		VaPrint(("[ReadPhyVmm]: cannot find this offset : %08x\n", Offset));
		return FALSE ; 
	}
	
	return	ReadVMXMem((PVOID)(Offset - Vmm->FileOffset.QuadPart + (ULONG)Vmm->MappedAddress) , Size ,  pBuffer , pvmx);

}
BOOL __stdcall WritePhyVmm(ULONG vmxindex , ULONG Offset ,PVOID pBuffer , ULONG Size, POFFLINE_VMM ovmm)
{
	if (ovmm)
	{
		ULONG btr ; 
		if (SetFilePointer(ovmm->vmemFile , Offset , NULL , FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			return FALSE ; 
		}
		
		if (!WriteFile(ovmm->vmemFile , pBuffer , Size,&btr , NULL ))
		{
			return FALSE ; 
		}
		
		return TRUE ; 
	}
	if (IsVMXExit(&g_vmxs[vmxindex]))
	{
		return FALSE ;
	}
	
	PENUMVMX pvmx = &g_vmxs[vmxindex] ; 
	PVMMDESC Vmm = GetVmmDescByOffset(Offset , pvmx);
	
	if (!Vmm)
	{
		VaPrint(("[ReadPhyVmm]: cannot find this offset : %08x\n", Offset));
		return FALSE ; 
	}
	
	return	WriteVMXMem((PVOID)(Offset - Vmm->FileOffset.QuadPart + (ULONG)Vmm->MappedAddress) , Size ,  pBuffer , pvmx);

}
typedef struct _VIRTUAL_ADDRESS_PAE_4KB {
    union
    {
        ULONG u;	
        struct
        {
            ULONG PageOffset:12;
            ULONG PageTableEntry:9;
            ULONG PageDirectoryEntry:9;
            ULONG PageDirectoryPointerTable:2;
        };
    };
} VIRTUAL_ADDRESS_PAE_4KB, *PVIRTUAL_ADDRESS_PAE_4KB;
typedef struct _HARDWARE_PTE
{
	union
	{
		ULONG u;
		struct
		{
			ULONG Valid: 1;
			ULONG Write: 1;
			ULONG Owner: 1;
			ULONG WriteThrough: 1;
			ULONG CacheDisable: 1;
			ULONG Accessed: 1;
			ULONG Dirty: 1;
			ULONG LargePage: 1;
			ULONG Global: 1;
			ULONG CopyOnWrite: 1;
			ULONG Prototype: 1;
			ULONG reserved0: 1;
			ULONG PageFrameNumber: 10;
		};
	};
} HARDWARE_PTE, *PHARDWARE_PTE;
typedef struct _VIRTUAL_ADDRESS_PAE_4MB {
    union
    {
        ULONG u;
        struct
        {
            ULONG PageOffset:21;
            ULONG PageDirectoryEntry:9;
            ULONG PageDirectoryPointerTable:2;
        };
    };
} VIRTUAL_ADDRESS_PAE_4MB, *PVIRTUAL_ADDRESS_PAE_4MB;
typedef struct _VIRTUAL_ADDRESS_4KB {
    union
    {
        ULONG u;
        struct
        {
            ULONG PageOffset:12;
            ULONG PageTableEntry:10;
            ULONG PageDirectoryEntry:10;
        };
    };
} VIRTUAL_ADDRESS_4KB, *PVIRTUAL_ADDRESS_4KB;
typedef struct _VIRTUAL_ADDRESS_4MB {
    union
    {
        ULONG u;
        struct
        {
            ULONG PageOffset:22;
            ULONG PageDirectoryEntry:10;
        };
    };
} VIRTUAL_ADDRESS_4MB, *PVIRTUAL_ADDRESS_4MB;
BOOL __stdcall GetPhyAddr(ULONG vmxindex , ULONG Virtual , PULONG PhyAddr , POFFLINE_VMM ovmm)
{

//	ULONG Pde , Pte ; 
	ULONG pAddr ; 
	ULONG DirBase ;
	BOOL PaeEnable ; 
	if (ovmm)
	{
		PaeEnable = ovmm->PaeIsEnable ;
		DirBase = ovmm->DirBase ; 
	}
	else
	{
		PaeEnable = g_vmxs[vmxindex].PaeEnable;
		DirBase = g_vmxs[vmxindex].DirBase ; 
	}

	
// 	if (!PaeEnable && Virtual > 0x80000000 && Virtual < 0xa0000000)
// 	{
// 		*PhyAddr = Virtual & 0x1fffffff ; 
// 		return TRUE ; 
// 	}

	if (PaeEnable)
	{
		VIRTUAL_ADDRESS_PAE_4KB vapae4kb ; 
		VIRTUAL_ADDRESS_PAE_4MB vapae4mb ; 
		vapae4kb.u = Virtual ; 
		ULONG ppde = DirBase + vapae4kb.PageDirectoryPointerTable*sizeof(LONGLONG);
		ULONG ulppde ; 
		if (!ReadPhyVmm(vmxindex , ppde , &ulppde , sizeof(LONG) ,ovmm))
		{
			return FALSE ; 
		}

		if ((ulppde & 1) == 0)
		{
			return FALSE ; 
		}

		ULONG ulpde = ((ulppde >> 12 ) * 0x1000) + vapae4kb.PageDirectoryEntry * sizeof(LONGLONG);

		if (!ReadPhyVmm(vmxindex , ulpde , &ulpde , sizeof(ULONG) ,ovmm))
		{
			return FALSE ; 
		}

		if ((ulpde & 1) == 0 )
		{
			return FALSE ; 
		}

		ULONG ulpte ; 
		ULONG ppte ; 
		if ((ulpde & 0x80)==0)
		{
			ulpte = (ulpde >> 12) * 0x1000 + vapae4kb.PageTableEntry * sizeof(LONGLONG);
			if (!ReadPhyVmm(vmxindex , ulpte , &ppte , sizeof(ULONG) ,ovmm))
			{
				return FALSE ; 
			}

			pAddr = ((ppte >> 12) * 0x1000 ) + vapae4kb.PageOffset;
		}
		else
		{
			vapae4mb.u = Virtual ; 
			pAddr = ((ulpde >> 12) * 0x1000) + vapae4mb.PageOffset;

		}


	}
	else
	{
		VIRTUAL_ADDRESS_4KB va4Kb;
		VIRTUAL_ADDRESS_4MB va4Mb;

		va4Kb.u = Virtual ; 

		ULONG ulPde = DirBase ; 

		ulPde += va4Kb.PageDirectoryEntry * sizeof(ULONG);
		if (!ReadPhyVmm(vmxindex  , ulPde  , &ulPde , sizeof(ULONG) , ovmm))
		{
			return FALSE ; 
		}

		HARDWARE_PTE hPde;
		hPde.u = ulPde ; 
		if (hPde.LargePage ==0)
		{
            ULONG ulPte = ((ulPde >> 12) * 0x1000);
            ulPte += va4Kb.PageTableEntry * sizeof(ULONG);	
			if (!ReadPhyVmm(vmxindex , ulPte , &ulPte , sizeof(ULONG) ,ovmm))
			{
				return FALSE ; 
			}
			pAddr = ((ulPte >> 12 )*0x1000 ) + va4Kb.PageOffset ; 
		}
		else
		{
			va4Mb.u = Virtual ; 
			pAddr = ulPde & 0xffc00000;
			pAddr += Virtual & 0x003fffff;

		}
	}
// 	else
// 	{
// 		if (!ReadPhyVmm(vmxindex , (Virtual >> 22 ) * sizeof(ULONG) + DirBase, &Pde , sizeof(ULONG) , ovmm))
// 		{
// 			return FALSE; 
// 		}
// 		if ((Pde & 1) == 0 )
// 		{
// 			return FALSE ; 
// 		}
// 		
// 		ULONG PageFlag = Pde & 0x80 ; 
// 		if (PageFlag != 0 )
// 		{
// 			pAddr = (Pde & 0xffc00000) + (Virtual & 0x003fffff);
// 		}
// 		else
// 		{
// 			
// 			if (!ReadPhyVmm(vmxindex , 
// 				(Pde & 0xfffff000) + ((Virtual & 0x003ff000) >> 12) * sizeof(ULONG) ,
// 				&Pte , 
// 				sizeof(ULONG),
// 				ovmm))
// 			{
// 				return FALSE ; 
// 			}
// 			
// 			if ((Pte & 1) == 0)
// 			{
// 				return FALSE  ;
// 			}
// 			
// 			pAddr = (Pte & 0xfffff000 ) + (Virtual & 0xfff);
// 		}
// 	}
//	VaPrint(("GetPhyAddr :%08x %08x\n",Virtual,pAddr));

	*PhyAddr = pAddr ; 
	return TRUE ; 

	
}


BOOL __stdcall ReadVirtualVmm(ULONG vmxindex ,
							  ULONG Address ,
							  PVOID pBuffer ,
							  ULONG Size,
							  POFFLINE_VMM ovmm)
{
	ULONG paddr ; 
	ULONG curraddr = Address; 
	ULONG PageNumber = Size /0x1000;
	ULONG i ; 
	for (i = 0 ; i < PageNumber ; i++)
	{
		if (!GetPhyAddr(vmxindex , curraddr , &paddr , ovmm))
		{
//			VaPrint(("[ReadVirtualVmm] : Error get phyaddress %08x\n" , Address, ovmm));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}

		if (!ReadPhyVmm(vmxindex , paddr , (PVOID)((ULONG)pBuffer + curraddr - Address) , 0x1000 ,ovmm))
		{
			VaPrint(("ReadVirtual:read phy memory failed! %08x\n" , paddr));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}

		curraddr += 0x1000;

	}

	if ((Size & 0xfff)!=0 )
	{
		Size -= PageNumber * 0x1000 ;
		if (!GetPhyAddr(vmxindex , Address + PageNumber * 0x1000, &paddr ,ovmm))
		{
//			VaPrint(("[ReadVirtualVmm] : Error get phyaddress %08x\n" , Address + PageNumber * 0x1000));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}

		
		if (!ReadPhyVmm(vmxindex , paddr , (PVOID)((ULONG)pBuffer + PageNumber * 0x1000) , Size ,ovmm ))
		{
			VaPrint(("ReadVirtual:read phy memory failed!\n"));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}		

		
	}

	return TRUE ; 

}
BOOL __stdcall WriteVirtualVmm(ULONG vmxindex , 
							   ULONG Address ,
							   PVOID pBuffer ,
							   ULONG Size,
							   POFFLINE_VMM ovmm)
{
	ULONG paddr ; 
	ULONG curraddr = Address; 
	ULONG PageNumber = Size /0x1000;
	ULONG i ; 
	for (i = 0 ; i < PageNumber ; i++)
	{
		if (!GetPhyAddr(vmxindex , curraddr , &paddr , ovmm))
		{
			VaPrint(("[WriteVirtualVmm] : Error get phyaddress\n"));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}
		
		if (!WritePhyVmm(vmxindex , paddr , (PVOID)((ULONG)pBuffer + curraddr - Address) , 0x1000  ,ovmm))
		{
			VaPrint(("WriteVirtual:Write phy memory failed!\n"));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}
		
		curraddr += 0x1000;
		
	}
	
	if ((Size & 0xfff)!=0 )
	{
		Size -= PageNumber * 0x1000 ;
		if (!GetPhyAddr(vmxindex , Address + PageNumber * 0x1000, &paddr ,ovmm))
		{
			VaPrint(("[WriteVirtualVmm] : Error get phyaddress\n"));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}
		
		if (!WritePhyVmm(vmxindex , paddr , (PVOID)((ULONG)pBuffer + PageNumber * 0x1000) , Size ,ovmm ))
		{
			VaPrint(("WriteVirtual:Write phy memory failed!\n"));
			memset(pBuffer , 0x3f , Size);
			return FALSE ; 
		}		
		
		
	}
	
	return TRUE ; 
}

void __stdcall CleanupVmm(PENUMVMX vmxs)
{
	CloseHandle(vmxs->vmprochandle);
	if (vmxs->vmmdes )
	{
		free(vmxs->vmmdes);
	}

	return ; 
}
BOOL __stdcall GetVMMInfo(PENUMVMX vmx , ULONG index)
{
	if (index >= vmxindex)
	{
		return FALSE ; 
	}

	memcpy(vmx , &g_vmxs[index] , sizeof(ENUMVMX));

	return TRUE ; 
}
ULONG NtSuspendProcess = 0 ;
ULONG NtResumeProcess = 0 ;
BOOL __stdcall FreezeVmx(PENUMVMX vmx)
{
	if (vmx->Freezed == TRUE)
	{
		return TRUE ; 
	}
	if (NtSuspendProcess == 0 )
	{
		HMODULE hlib = GetModuleHandle("ntdll.dll");
		NtSuspendProcess = (ULONG)GetProcAddress(hlib , "NtSuspendProcess");

		if (NtSuspendProcess == 0 )
		{
			VaPrint(("[FreezeVmx] :NtSuspendProcess == 0!!\n"));
			return FALSE ; 
		}
	}
	HANDLE hproc = vmx->vmprochandle ; 
	LONG stat  ; 
	__asm
	{
		push hproc
		call NtSuspendProcess
		mov  stat , eax
	}
	if (stat ==0)
		vmx->Freezed = TRUE ; 
	return (stat ==0);
}

BOOL __stdcall ThawVmx(PENUMVMX vmx)
{
	if (vmx->Freezed == FALSE)
	{
		return TRUE ; 
	}
	if (NtResumeProcess == 0 )
	{
		HMODULE hlib = GetModuleHandle("ntdll.dll");
		NtResumeProcess = (ULONG)GetProcAddress(hlib , "NtResumeProcess");
		
		if (NtResumeProcess == 0 )
		{
			VaPrint(("[FreezeVmx] :NtResumeProcess == 0!!\n"));
			return FALSE ; 
		}
	}
	HANDLE hproc = vmx->vmprochandle ; 
	LONG stat  ; 
	__asm
	{
		push hproc
		call NtResumeProcess
		mov  stat , eax
	}

	if (stat == 0 )
		vmx->Freezed = FALSE ; 
	return (stat ==0);
}

POFFLINE_VMM __stdcall OpenOfflineVmm(LPCSTR FileName)
{
	HANDLE hFile ;
	
	hFile = CreateFile(FileName , FILE_READ_DATA | FILE_WRITE_DATA , FILE_SHARE_READ , NULL , OPEN_EXISTING , 0 , 0 );

	if (hFile == INVALID_HANDLE_VALUE)
	{
		ULONG u = GetLastError();
		return NULL ; 
	}
	POFFLINE_VMM pOvmm = (POFFLINE_VMM)malloc(sizeof(OFFLINE_VMM));

	if (pOvmm == 0 )
	{
		CloseHandle(hFile);
		return NULL;
	}
	pOvmm->vmemFile = hFile;

	pOvmm->SizeInMB = GetFileSize(hFile , NULL) / 1024 / 1024;
	//initialize the guess cr3
	
	pOvmm->DirBase = 0x39000 ; 
	pOvmm->PaeIsEnable = FALSE ; 
	
	ULONG KdVersionBlock ; 
	
	if (!ReadVirtualVmm(0 , 0xffdff034 , &KdVersionBlock , sizeof(ULONG) , pOvmm))
	{
		VaPrint(("get KdVersionBlock failed!\n"));
		CloseHandle(hFile);
		return NULL;
	}
	USHORT PaeIsEnable ; 
	
	if (!ReadVirtualVmm(0 , KdVersionBlock + 0x5e , &PaeIsEnable , sizeof(USHORT) ,pOvmm ))
	{
		VaPrint(("get PaeIsEnable failed!\n"));
		CloseHandle(hFile);
		return NULL;
	}
	
	ULONG cr3 ; 
	if (!ReadVirtualVmm(0 , 0xffdff410 , &cr3 , sizeof(ULONG) ,pOvmm))
	{
		VaPrint(("get cr3 failed!\n"));
		CloseHandle(hFile);
		return NULL;
	}

	pOvmm->PaeIsEnable = PaeIsEnable ; 
	pOvmm->DirBase = cr3 ; 

	return pOvmm;
}


//////////////////////////////////////////////////////////////////////////
// Enumerate VMX with process walker
//
// return : Number of vmxs
//////////////////////////////////////////////////////////////////////////

ULONG __stdcall EnumVMX()
{
	HANDLE hSnapShot = NULL;
	PROCESSENTRY32 pe;

	vmxindex = 0 ;
	
	////////////////////////////////////////////////////////////////////////////

	//
	// first , we collect all vmxs
	//
	// 
	
	hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hSnapShot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	ULONG pid = 0 ; 
	ULONG vmpidnum = 0 ;
	ULONG vmpids[20];
	ULONG i ; 
	
	ZeroMemory(&pe, sizeof(pe));
	pe.dwSize = sizeof(pe);
	
	BOOL bNext = Process32First( hSnapShot, &pe );
	while(bNext)
	{
		if( pe.th32ProcessID > 20 )
		{
			if( lstrcmpiA(pe.szExeFile, "vmware-vmx.exe") == 0 )
			{
				pid = pe.th32ProcessID ; 
				vmpids[vmpidnum] = pid ; 
				vmpidnum ++;
			}
		}
		
		pe.dwSize = sizeof(pe);
		bNext = Process32Next( hSnapShot, &pe );
	}
	
	CloseHandle(hSnapShot);
	

	//////////////////////////////////////////////////////////////////////////
	//
	// get all vmx information
	//

	for (i = 0  ; i < vmpidnum ; i++ )
	{
		WCHAR cmdline[1024];

		VaPrint(("VMX pid = %u\n", vmpids[i]));

		//////////////////////////////////////////////////////////////////////////
		//
		// open vmx process for :
		// 1.Get vmx command (pipe , vmx file...)
		// 2.Read / Write phyisical memory in vmx
		// 
		//

		HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION |
			PROCESS_VM_READ |
			PROCESS_VM_WRITE |
			PROCESS_VM_OPERATION |
			PROCESS_SUSPEND_RESUME ,
			FALSE , 
			vmpids[i]
			);

		if (hproc == 0)
		{
			VaPrint(("Error Open VMX Process :%u \n", vmpids[i]));
			return 0; 
		}

		ThawVmx(&g_vmxs[i]);

		g_vmxs[i].Freezed = FALSE ; 

		g_vmxs[i].vmprochandle = hproc ; 
		
		if (!GetProcessCmdLine(hproc , cmdline , 1024 * sizeof(WCHAR)))
		{
			VaPrint(("Error Get VMX process cmd line :%u\n" , vmpids[i]));
			CloseHandle(hproc);
			return 0 ; 
		}

		VaPrint(("command line = %ws\n" , cmdline));
			
		//command line here like:
		//"%vmxpath%" -T querytoken -# "product=1;name=%vmp%;version=%vmv%;buildnumber=%vmbn%;licensename=%vmlic%;
		//licenseversion=6.0 build-126130;" -@ pipe=%vmxpipename%; "%vmx_filepath%"


		//get .vmx file name
		WCHAR VmxFileName[MAX_PATH] ; 
		LPWSTR pVmxName = wcsstr(cmdline , L".vmx");
		while(*(WCHAR*)pVmxName != L'"' && (ULONG)pVmxName > (ULONG)cmdline)
		{
			pVmxName -- ; 
		};
		if ((ULONG)pVmxName == (ULONG)cmdline)
		{
			VaPrint(("cannot find vmx filename\n"));
			CloseHandle(hproc);
			return 0 ; 
		}
		memset(VmxFileName , 0 , MAX_PATH * sizeof(WCHAR));
		wcsncpy(VmxFileName , pVmxName + 1 , wcslen(pVmxName)-2);
		
		VaPrint(("VmxFileName = %ws\n" , VmxFileName));

		//read out vmx file content


		HANDLE hvmxfile = CreateFileW(VmxFileName ,
			FILE_READ_DATA ,
			FILE_SHARE_READ , 
			NULL ,
			OPEN_EXISTING , 
			0,
			0);

		if (hvmxfile == INVALID_HANDLE_VALUE)
		{
			VaPrint(("open vmx file :%ws failed! err :%u \n", VmxFileName , GetLastError()));
			CloseHandle(hproc);
			return 0 ; 
		}

		ULONG vmxfilesize = GetFileSize(hvmxfile , NULL);

		if (vmxfilesize == 0 )
		{
			VaPrint(("vmx file :%ws invalid " ,VmxFileName));
			CloseHandle(hvmxfile);
			CloseHandle(hproc);
			return 0 ; 
		}

		LPCSTR pVmxFileContext = (LPSTR)VirtualAlloc(NULL , vmxfilesize , MEM_COMMIT , PAGE_READWRITE);

		if (pVmxFileContext == NULL)
		{
			VaPrint(("allocate memory for vmx file failed!\n"));
			CloseHandle(hvmxfile);
			CloseHandle(hproc);
			return 0 ; 
		}
		ULONG btr ; 
		if (!ReadFile(hvmxfile , 
			(PVOID)pVmxFileContext , 
			vmxfilesize , 
			&btr , 
			0))
		{
			VaPrint(("read file from vmx file %ws failed %u!\n" , VmxFileName , GetLastError()));
			VirtualFree((PVOID)pVmxFileContext , vmxfilesize , MEM_FREE);
			CloseHandle(hvmxfile);
			CloseHandle(hproc);
			return 0 ; 			
		}

		CloseHandle(hvmxfile);

		
		//store vmx and vmm file name
		wcscpy(g_vmxs[i].VmxName , VmxFileName);
		wcscpy(g_vmxs[i].vmemPath , VmxFileName );
		ULONG namelen = wcslen(VmxFileName);
		g_vmxs[i].vmemPath[namelen-1] = L'e';
		g_vmxs[i].vmemPath[namelen] = L'm';
		g_vmxs[i].vmemPath[namelen+1]=L'\0';

		VaPrint(("vmem name = %ws\n" , g_vmxs[i].vmemPath));

		CHAR TempPath[MAX_PATH];
		CHAR TempFileName[MAX_PATH];

		GetTempPath(MAX_PATH , TempPath );

		GetTempFileName(TempPath , "vmx" , 0 , TempFileName);

		HANDLE hTempvmxfile = CreateFile(TempFileName , 
			FILE_WRITE_DATA , 
			FILE_SHARE_READ , 
			0,
			CREATE_ALWAYS , 
			0,
			0);

		if (hTempvmxfile == INVALID_HANDLE_VALUE)
		{
			VaPrint(("create temp file failed! %u\n", GetLastError()));
			CloseHandle(hproc);
			return 0 ;
		}

		if (!WriteFile(hTempvmxfile , 
			"[vmx]\r\n",
			8,
			&btr ,
			0))
		{
			VaPrint(("write file failed%u\n" , GetLastError()));
			CloseHandle(hTempvmxfile);
			CloseHandle(hproc);
			return 0 ; 
		}

		if (!WriteFile(hTempvmxfile , 
			pVmxFileContext,
			vmxfilesize , 
			&btr , 
			0))
		{
			VaPrint(("write file failed%u\n" , GetLastError()));
			CloseHandle(hTempvmxfile);
			CloseHandle(hproc);
			return 0 ; 
		}

		CloseHandle(hTempvmxfile);

		CHAR memsizestr[20];
		if (GetPrivateProfileStringA("vmx",
			"memsize",
			NULL,
			memsizestr , 
			20 , 
			TempFileName) == 0 )
		{
			VaPrint(("cannot get vmx memory size!\n"));
			CloseHandle(hproc);
			return 0 ; 
		}

		//save memory size

		g_vmxs[i].MemSizeInMB = atoi(memsizestr);

		VaPrint(("memsize = %u\n" , g_vmxs[i].MemSizeInMB));


		if (GetPrivateProfileStringA("vmx",
			"guestOS",
			NULL , 
			g_vmxs[i].OsType,
			200,
			TempFileName) == 0)
		{
			VaPrint(("cannot get vmx OS Type!\n"));
			CloseHandle(hproc);
			return 0 ; 
		}
		
		VaPrint(("Os = %s\n" , g_vmxs[i].OsType));
		if (GetPrivateProfileStringA("vmx" , 
			"displayName" , 
			NULL ,
			g_vmxs[i].VmxDisplayName ,
			200,
			TempFileName)==0)
		{
			VaPrint(("cannot get vmx display name!\n"));
			CloseHandle(hproc);
			return 0 ; 
		}

		VaPrint(("Display name = %s\n" , g_vmxs[i].VmxDisplayName));
		
		DeleteFile(TempFileName);

		g_vmxs[i].vmpid = vmpids[i];

		if (!GetVMXMemdesc(&g_vmxs[i]))
		{
			VaPrint(("take memory desc info failed\n"));
			CloseHandle(hproc);
			return 0 ; 
		}

		//initialize the guess cr3

		g_vmxs[i].DirBase = 0x39000 ; 
		g_vmxs[i].PaeEnable = FALSE ; 

		ULONG KdVersionBlock ; 

		if (!ReadVirtualVmm(i , 0xffdff034 , &KdVersionBlock , sizeof(ULONG) , NULL))
		{
			VaPrint(("get KdVersionBlock failed!\n"));
			CloseHandle(hproc);
			return 0 ;
		}
		USHORT PaeIsEnable ; 

		if (!ReadVirtualVmm(i , KdVersionBlock + 0x5e , &PaeIsEnable , sizeof(USHORT) , NULL ))
		{
			VaPrint(("get PaeIsEnable failed!\n"));
			CloseHandle(hproc);
			return 0 ;
		}

		ULONG cr3 ; 
		if (!ReadVirtualVmm(i , 0xffdff410 , &cr3 , sizeof(ULONG) , NULL))
		{
			VaPrint(("get cr3 failed!\n"));
			CloseHandle(hproc);
			return 0 ;
		}
		VaPrint(("real cr3 = %08x paeenable = %u\n" , cr3 , PaeIsEnable));
		g_vmxs[i].PaeEnable = ((PaeIsEnable & 1) != 0 );

		g_vmxs[i].DirBase = cr3 ; 

	}
	vmxindex = vmpidnum ; 
	return vmpidnum;	
}
