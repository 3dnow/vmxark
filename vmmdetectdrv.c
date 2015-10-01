
#include "ntddk.h"
#include "windef.h"
#include "resource.h"
#define MYDEBUG 1

#if MYDEBUG

#define KDMSG(_x_) DbgPrint _x_

#else

#define KDMSG(_x_)

#endif

typedef struct QUERY_ADDRESS_FILEOFFSET{
	HANDLE hProc ; 
	ULONG Address ; 
	LARGE_INTEGER FileOffset ; 
}QUERY_ADDRESS_FILEOFFSET , *PQUERY_ADDRESS_FILEOFFSET;

#define IOCTL_QUERY_ADDRESS_FILEOFFSET CTL_CODE(FILE_DEVICE_UNKNOWN , 0x800 , METHOD_BUFFERED , FILE_ANY_ACCESS)
NTSYSAPI POBJECT_TYPE PsProcessType;
ULONG ProcessFlagsOffVista = 0x228 ;
ULONG ProcessVadRootOffVista = 0x238 ; 
#define COMMIT_SIZE 19
typedef struct _MMVAD_FLAGS {
    ULONG_PTR CommitCharge : COMMIT_SIZE; // limits system to 4k pages or bigger!
    ULONG_PTR NoChange : 1;
    ULONG_PTR VadType : 3;
    ULONG_PTR MemCommit: 1;
    ULONG_PTR Protection : 5;
    ULONG_PTR Spare : 2;
    ULONG_PTR PrivateMemory : 1;    // used to tell VAD from VAD_SHORT
} MMVAD_FLAGS;
typedef struct _MMVAD_FLAGS2 {
    unsigned FileOffset : 24;       // number of 64k units into file
    unsigned SecNoChange : 1;       // set if SEC_NOCHANGE specified
    unsigned OneSecured : 1;        // set if u3 field is a range
    unsigned MultipleSecured : 1;   // set if u3 field is a list head
    unsigned ReadOnly : 1;          // protected as ReadOnly
    unsigned LongVad : 1;           // set if VAD is a long VAD
    unsigned ExtendableFile : 1;
    unsigned Inherit : 1;           //1 = ViewShare, 0 = ViewUnmap
    unsigned CopyOnWrite : 1;
} MMVAD_FLAGS2;
typedef struct _MMVAD {
	ULONG u1;
    struct _MMVAD *LeftChild;
    struct _MMVAD *RightChild;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
	
    union {
        ULONG_PTR LongFlags;
        MMVAD_FLAGS VadFlags;
    } u;
	PVOID pPushLock ; 
	ULONG u5 ; 
	ULONG u2 ; 
	PVOID SubSection ; 
	PVOID FirstPrototypePte;
    PVOID LastContiguousPte;
} MMVAD, *PMMVAD;
typedef struct _MMADDRESS_NODE {
    union {
        LONG_PTR Balance : 2;
        struct _MMADDRESS_NODE *Parent;
    } u1;
    struct _MMADDRESS_NODE *LeftChild;
    struct _MMADDRESS_NODE *RightChild;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
} MMADDRESS_NODE, *PMMADDRESS_NODE;


typedef struct _MMVADXP {
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
    PVOID Parent;
    PVOID LeftChild;
    PVOID RightChild;
    union {
        ULONG_PTR LongFlags;
        MMVAD_FLAGS VadFlags;
    } u;
    PVOID ControlArea;
    PVOID FirstPrototypePte;
    PVOID LastContiguousPte;
	ULONG u2 ; 
    union {
        LIST_ENTRY List;
        LONGLONG Secured;
    } u3;
    union {
        PVOID Banked;
        PVOID ExtendedInfo;
    } u4;
} MMVADXP, *PMMVADXP;

typedef struct _MM_AVL_TABLE {
    MMADDRESS_NODE  BalancedRoot;
    ULONG_PTR DepthOfTree: 5;
    ULONG_PTR Unused: 3;
    ULONG_PTR NumberGenericTableElements: 24;
    PVOID NodeHint;
    PVOID NodeFreeHint;
} MM_AVL_TABLE, *PMM_AVL_TABLE;
#define PROCESS_QUERY_INFORMATION (0x0400)
#define PS_PROCESS_FLAGS_VM_DELETED 0x00000020
typedef struct _KAPC_STATE {
    LIST_ENTRY  ApcListHead[2];
    PVOID   Process;
    BOOLEAN     KernelApcInProgress;
    BOOLEAN     KernelApcPending;
    BOOLEAN     UserApcPending;
} KAPC_STATE, *PKAPC_STATE;
NTKERNELAPI
VOID
KeStackAttachProcess (
					  IN PVOID    Process,
					  OUT PKAPC_STATE ApcState
);
#define MI_VA_TO_VPN(va)  ((ULONG_PTR)(va) >> PAGE_SHIFT)
NTKERNELAPI
VOID
KeUnstackDetachProcess (
						IN PKAPC_STATE ApcState
);
ULONG ProcessFlagsOffXP = 0x248 ; 
ULONG VadRootOffsetXP = 0x11c ; 
NTSTATUS QueryMappedAddressXP(PQUERY_ADDRESS_FILEOFFSET QueryBuffer , 
							  PVOID Eproc)
{
	NTSTATUS stat = STATUS_SUCCESS ; 
	KAPC_STATE ApcState ;
	PMMVADXP pVadRoot;
	PMMVADXP Vad ; 
	ULONG BaseVpn ;
	BOOL bFound =FALSE  ; 
	
	//
	// Make sure the address space was not deleted, if so, return an error.
	//
	
	if (*(ULONG*)((ULONG)Eproc + ProcessFlagsOffXP) & PS_PROCESS_FLAGS_VM_DELETED)
	{
		KDMSG(("ProcessVmDeleted\n"));
		stat = STATUS_PROCESS_IS_TERMINATING ; 
		goto end ; 
	}
	
	//
	// We need attach to this process to access virtual memory
	//
	
	KeStackAttachProcess(Eproc , &ApcState );
	
	pVadRoot = (PMMVADXP)*(ULONG*)((ULONG)Eproc + VadRootOffsetXP);
	
	KDMSG(("pVadRoot = %08x\n" , pVadRoot));
	//
	//walk VAD Root (AVL Tree)
	//
	{
		Vad = (PMMVADXP)pVadRoot ;
		BaseVpn = MI_VA_TO_VPN(QueryBuffer->Address);
		
		while(TRUE)
		{
			if (Vad == NULL)
			{
				break ; 
			}
			
			if ((BaseVpn >= Vad->StartingVpn) &&
				(BaseVpn <= Vad->EndingVpn) )
			{
				bFound = TRUE ;
				break ; 
			}
			if (BaseVpn < Vad->StartingVpn)
			{
				if (Vad->LeftChild == NULL)
				{
					break ; 
				}
				Vad = Vad->LeftChild ; 
			}
			else
			{
				if (Vad->RightChild == NULL)
				{
					break ; 
				}
				Vad = Vad->RightChild ; 
				
			}
		}
		
		
		
	}
	
	//
	//if address not found
	//
	
	if (!bFound)
	{
		KDMSG(("cannot find vmm\n"));
		KeUnstackDetachProcess(&ApcState);
		stat = STATUS_INVALID_ADDRESS ; 
		goto end ; 
		
	}
	
	QueryBuffer->FileOffset.QuadPart = Int32x32To64((Vad->u2 & 0xFFFFFF) , 0x10000);
	
	KeUnstackDetachProcess(&ApcState);
end:	
	return stat ; 
}
NTSTATUS QueryMappedAddressVista(PQUERY_ADDRESS_FILEOFFSET QueryBuffer , 
								 PVOID Eproc)
{
	NTSTATUS stat = STATUS_SUCCESS ; 
	KAPC_STATE ApcState ;
	PMM_AVL_TABLE pVadRoot;
	PMMVAD Vad ; 
	ULONG BaseVpn ;
	BOOL bFound =FALSE  ; 

	//
	// Make sure the address space was not deleted, if so, return an error.
	//
	
	if (*(ULONG*)((ULONG)Eproc + ProcessFlagsOffVista) & PS_PROCESS_FLAGS_VM_DELETED)
	{
		stat = STATUS_PROCESS_IS_TERMINATING ; 
		goto end ; 
	}
	
	//
	// We need attach to this process to access virtual memory
	//
	
	KeStackAttachProcess(Eproc , &ApcState );
	
	pVadRoot = (PVOID)((ULONG)Eproc + ProcessVadRootOffVista);
	
	
	//
	//walk VAD Root (AVL Tree)
	//
	if (pVadRoot->NumberGenericTableElements != 0 )
	{
		Vad = (PMMVAD)(pVadRoot->BalancedRoot.RightChild);
		BaseVpn = MI_VA_TO_VPN(QueryBuffer->Address);
		
		while(TRUE)
		{
			if (Vad == NULL)
			{
				break ; 
			}
			
			if ((BaseVpn >= Vad->StartingVpn) &&
				(BaseVpn <= Vad->EndingVpn) )
			{
				bFound = TRUE ;
				break ; 
			}
			if (BaseVpn < Vad->StartingVpn)
			{
				if (Vad->LeftChild == NULL)
				{
					break ; 
				}
				Vad = Vad->LeftChild ; 
			}
			else
			{
				if (Vad->RightChild == NULL)
				{
					break ; 
				}
				Vad = Vad->RightChild ; 
				
			}
		}
		
		
		
	}
	
	//
	//if address not found
	//
	
	if (!bFound)
	{
		KeUnstackDetachProcess(&ApcState);
		stat = STATUS_INVALID_ADDRESS ; 
		goto end ; 
		
	}
	
	QueryBuffer->FileOffset.QuadPart = Int32x32To64((Vad->u2 & 0xFFFFFF) , 0x10000);
	
	KeUnstackDetachProcess(&ApcState);
end:	
	return stat ; 

}
NTSTATUS DevCtlDispatch(PDEVICE_OBJECT devobj , PIRP pIrp)
{
	PIO_STACK_LOCATION IrpStack ; 
	NTSTATUS stat ; 

	IrpStack = IoGetCurrentIrpStackLocation(pIrp);
	pIrp->IoStatus.Status = STATUS_SUCCESS ; 
	pIrp->IoStatus.Information = 0 ;

	if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_QUERY_ADDRESS_FILEOFFSET)
	{
		PQUERY_ADDRESS_FILEOFFSET QueryBuffer = (PQUERY_ADDRESS_FILEOFFSET)(pIrp->AssociatedIrp.SystemBuffer);

		
		if (IrpStack->Parameters.DeviceIoControl.InputBufferLength != sizeof(QUERY_ADDRESS_FILEOFFSET) ||
			IrpStack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(QUERY_ADDRESS_FILEOFFSET))
		{
			KDMSG(("Input Buffer length err!\n"));
			pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			goto end ; 
		}
		KDMSG(("qb: hproc = %08x Address = %08x\n", QueryBuffer->hProc , QueryBuffer->Address));

		if (QueryBuffer->hProc != 0 )
		{
			PVOID Eproc ; 
			ULONG Major , Minor , Build ; 

			//
			// Get process object by handle , if handle invalid ,return an error
			//

			stat = ObReferenceObjectByHandle(QueryBuffer->hProc , 
				PROCESS_QUERY_INFORMATION , 
				PsProcessType ,
				KernelMode ,
				&Eproc , 
				NULL);

			if (!NT_SUCCESS(stat))
			{
				KDMSG(("ReferenceHandle failed %08x\n",stat));
				pIrp->IoStatus.Status = stat ; 
				goto end ; 
			}
			PsGetVersion(&Major , &Minor , &Build , 0 );
			if (Major == 5 && Minor == 1)
			{
				stat = QueryMappedAddressXP(QueryBuffer , Eproc);
				if (NT_SUCCESS(stat))
				{
					pIrp->IoStatus.Information = sizeof(QUERY_ADDRESS_FILEOFFSET);
				}
				else
				{
					pIrp->IoStatus.Status = stat ; 
				}
			}
			else if (Major == 6 && Minor == 0 )
			{
				stat = QueryMappedAddressVista(QueryBuffer , Eproc);
				if (NT_SUCCESS(stat))
				{
					pIrp->IoStatus.Information = sizeof(QUERY_ADDRESS_FILEOFFSET);
				}
				else
				{
					pIrp->IoStatus.Status = stat ; 
				}
			}
			else
			{
				pIrp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
			}


			ObDereferenceObject(Eproc);

		}

	}
	else
	{
		pIrp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST ; 
	}
end:
	stat = pIrp->IoStatus.Status ; 

	IoCompleteRequest(pIrp , IO_NO_INCREMENT);
	return stat ; 
}


NTSTATUS CreateCloseDispatch(PDEVICE_OBJECT devobj , PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS ;
	pIrp->IoStatus.Information = 0 ; 
	IoCompleteRequest(pIrp , IO_NO_INCREMENT);
	
	return STATUS_SUCCESS ; 
	
}


CONST WCHAR g_wszDeviceName[] = L"\\Device\\vmmdetect";
CONST WCHAR g_wszSymbolName[] = L"\\DosDevices\\vmmdetect";
VOID DrvUnload( IN PDRIVER_OBJECT DriverObject )
{
	
	UNICODE_STRING ustrSymbolName;
	RtlInitUnicodeString(&ustrSymbolName, g_wszSymbolName);
	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&ustrSymbolName);
	return ; 
}
NTSTATUS DriverEntry(
	IN	PDRIVER_OBJECT		pDriverObject,
	IN	PUNICODE_STRING		pRegistry
	)
{
	NTSTATUS ntStatus ;
	
	UNICODE_STRING ustrDeviceName;
	UNICODE_STRING ustrSymbolName;
	PDEVICE_OBJECT pDeviceObject = NULL;
	

	RtlInitUnicodeString(&ustrDeviceName, g_wszDeviceName);
	RtlInitUnicodeString(&ustrSymbolName, g_wszSymbolName);
		
	ntStatus = IoCreateDevice(
		pDriverObject,
		0,
		&ustrDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObject
		);
	
	if(!NT_SUCCESS(ntStatus))
	{
		KDMSG(("Create vmmdetect device failed! stat = %08x\n" , ntStatus));
		return STATUS_UNSUCCESSFUL;
	}
	
	ntStatus = IoCreateSymbolicLink(
		&ustrSymbolName,
		&ustrDeviceName
		);
	
	if(!NT_SUCCESS(ntStatus))
	{
		KDMSG(("Create symbolic link failed! stat = %08x\n" , ntStatus));
		IoDeleteDevice(pDeviceObject);
		return STATUS_UNSUCCESSFUL ; 
	}
	
	
	//填充处理例程
	
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)CreateCloseDispatch ; 
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)CreateCloseDispatch ; 
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DevCtlDispatch ; 
	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)DrvUnload;
	
	
	return STATUS_SUCCESS;
}
