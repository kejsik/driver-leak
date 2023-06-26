#define PFN_TO_PAGE(pfn) ( pfn << 12 )
#define dereference(ptr) (const uintptr_t)(ptr + *( int * )( ( BYTE * )ptr + 3 ) + 7)
#define in_range(x,a,b)    (x >= a && x <= b) 
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))
#define size_align(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define to_lower_i(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define to_lower_c(Char) ((Char >= (char*)'A' && Char <= (char*)'Z') ? (Char + 32) : Char)

typedef unsigned int uint32_t;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	VOID *EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;


typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION
{
	VOID *DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG ImageUsesLargePages : 1;
	ULONG IsProtectedProcess : 1;
	ULONG IsLegacyProcess : 1;
	ULONG IsImageDynamicallyRelocated : 1;
	ULONG SpareBits : 4;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	VOID *ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	ULONG ProcessInJob : 1;
	ULONG ProcessInitializing : 1;
	ULONG ReservedBits0 : 30;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG SpareUlong;
	VOID *FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	VOID **ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID **ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[34];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	VOID *ActivationContextData;
	VOID *ProcessAssemblyStorageMap;
	VOID *SystemDefaultActivationContextData;
	VOID *SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	VOID *FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
} PEB, *PPEB;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	system_bigpool_information = 0x42
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _PAGE_INFORMATION
{
	PML4E_64 *PML4E;
	PDPTE_64 *PDPTE;
	PDE_64 *PDE;
	PTE_64 *PTE;
}PAGE_INFORMATION, *PPAGE_INFORMATION;

typedef struct _MDL_INFORMATION
{
	MDL *mdl;
	uintptr_t va;
}MDL_INFORMATION, *PMDL_INFORMATION;

typedef union _VIRTUAL_ADDRESS
{
	PVOID value;
	struct
	{
		ULONG64 offset : 12;
		ULONG64 pt_index : 9;
		ULONG64 pd_index : 9;
		ULONG64 pdpt_index : 9;
		ULONG64 pml4_index : 9;
		ULONG64 reserved : 16;
	};
} VIRTUAL_ADDRESS, *PVIRTUAL_ADDRESS;

extern "C"
{
	NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_ PVOID SystemInformation,
		_In_ ULONG SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	NTSTATUS ZwAllocateVirtualMemory(
		_In_    HANDLE    ProcessHandle,
		_Inout_ PVOID *BaseAddress,
		_In_    ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T   RegionSize,
		_In_    ULONG     AllocationType,
		_In_    ULONG     Protect
	);

	NTKERNELAPI
		PPEB
		PsGetProcessPeb(
			IN PEPROCESS Process
		);

	NTKERNELAPI
		PVOID NTAPI RtlFindExportedRoutineByName(
			_In_ PVOID ImageBase,
			_In_ PCCH RoutineName
		);

	NTKERNELAPI
		PVOID
		PsGetProcessSectionBaseAddress(
			__in PEPROCESS Process
		);
}

typedef union _KWAIT_STATUS_REGISTER
{
	union
	{
		/* 0x0000 */ unsigned char Flags;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned char State : 3; /* bit position: 0 */
			/* 0x0000 */ unsigned char Affinity : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned char Priority : 1; /* bit position: 4 */
			/* 0x0000 */ unsigned char Apc : 1; /* bit position: 5 */
			/* 0x0000 */ unsigned char UserApc : 1; /* bit position: 6 */
			/* 0x0000 */ unsigned char Alert : 1; /* bit position: 7 */
		}; /* bitfield */
	}; /* size: 0x0001 */
} KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER; /* size: 0x0001 */

typedef struct _KTHREAD_META
{
	/* 0x0000 */ struct _DISPATCHER_HEADER Header;
	/* 0x0018 */ void* SListFaultAddress;
	/* 0x0020 */ unsigned __int64 QuantumTarget;
	/* 0x0028 */ void* InitialStack;
	/* 0x0030 */ void* volatile StackLimit;
	/* 0x0038 */ void* StackBase;
	/* 0x0040 */ unsigned __int64 ThreadLock;
	/* 0x0048 */ volatile unsigned __int64 CycleTime;
	/* 0x0050 */ unsigned long CurrentRunTime;
	/* 0x0054 */ unsigned long ExpectedRunTime;
	/* 0x0058 */ void* KernelStack;
	/* 0x0060 */ struct _XSAVE_FORMAT* StateSaveArea;
	/* 0x0068 */ struct _KSCHEDULING_GROUP* volatile SchedulingGroup;
	/* 0x0070 */ union _KWAIT_STATUS_REGISTER WaitRegister;
	/* 0x0071 */ volatile unsigned char Running;
	/* 0x0072 */ unsigned char Alerted[2];
	union
	{
		struct /* bitfield */
		{
			/* 0x0074 */ unsigned long AutoBoostActive : 1; /* bit position: 0 */
			/* 0x0074 */ unsigned long ReadyTransition : 1; /* bit position: 1 */
			/* 0x0074 */ unsigned long WaitNext : 1; /* bit position: 2 */
			/* 0x0074 */ unsigned long SystemAffinityActive : 1; /* bit position: 3 */
			/* 0x0074 */ unsigned long Alertable : 1; /* bit position: 4 */
			/* 0x0074 */ unsigned long UserStackWalkActive : 1; /* bit position: 5 */
			/* 0x0074 */ unsigned long ApcInterruptRequest : 1; /* bit position: 6 */
			/* 0x0074 */ unsigned long QuantumEndMigrate : 1; /* bit position: 7 */
			/* 0x0074 */ unsigned long UmsDirectedSwitchEnable : 1; /* bit position: 8 */
			/* 0x0074 */ unsigned long TimerActive : 1; /* bit position: 9 */
			/* 0x0074 */ unsigned long SystemThread : 1; /* bit position: 10 */
			/* 0x0074 */ unsigned long ProcessDetachActive : 1; /* bit position: 11 */
			/* 0x0074 */ unsigned long CalloutActive : 1; /* bit position: 12 */
			/* 0x0074 */ unsigned long ScbReadyQueue : 1; /* bit position: 13 */
			/* 0x0074 */ unsigned long ApcQueueable : 1; /* bit position: 14 */
			/* 0x0074 */ unsigned long ReservedStackInUse : 1; /* bit position: 15 */
			/* 0x0074 */ unsigned long UmsPerformingSyscall : 1; /* bit position: 16 */
			/* 0x0074 */ unsigned long TimerSuspended : 1; /* bit position: 17 */
			/* 0x0074 */ unsigned long SuspendedWaitMode : 1; /* bit position: 18 */
			/* 0x0074 */ unsigned long SuspendSchedulerApcWait : 1; /* bit position: 19 */
			/* 0x0074 */ unsigned long CetUserShadowStack : 1; /* bit position: 20 */
			/* 0x0074 */ unsigned long BypassProcessFreeze : 1; /* bit position: 21 */
			/* 0x0074 */ unsigned long CetKernelShadowStack : 1; /* bit position: 22 */
			/* 0x0074 */ unsigned long Reserved : 9; /* bit position: 23 */
		}; /* bitfield */
		/* 0x0074 */ long MiscFlags;
	}; /* size: 0x0004 */
} KTHREAD_META, * PKTHREAD_META; /* size: 0x0430 */