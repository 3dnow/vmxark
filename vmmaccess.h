typedef struct VMMDESC{
	LARGE_INTEGER FileOffset ; 
	PVOID MappedAddress ; 
	ULONG MappedSize ; 
}VMMDESC, *PVMMDESC;

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
	BOOL Freezed;
	BOOL PaeEnable ; 
	ULONG DirBase ; 
}ENUMVMX , *PENUMVMX;

typedef struct OFFLINE_VMM{
	HANDLE vmemFile ; 
	BOOL PaeIsEnable ; 
	ULONG DirBase ; 
	ULONG SizeInMB ;
}OFFLINE_VMM , *POFFLINE_VMM;
