#ifndef NTAPI_DEFS_H
#define NTAPI_DEFS_H

#include <windows.h>

#define STATUS_SUCCESS 0x00000000
#define PS_INHERIT_HANDLES 0x00000004
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef VOID (NTAPI* pfRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI* pfNtCreateProcessEx) (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN BOOLEAN InJob
);

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS (NTAPI* pfNtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS (NTAPI* pfNtCreateFile)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
    );

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation                 = 1,
    FileFullDirectoryInformation             = 2,
    FileBothDirectoryInformation             = 3,
    FileBasicInformation                     = 4,
    FileStandardInformation                  = 5,
    FileInternalInformation                  = 6,
    FileEaInformation                        = 7,
    FileAccessInformation                    = 8,
    FileNameInformation                      = 9,
    FileRenameInformation                    = 10,
    FileLinkInformation                      = 11,
    FileNamesInformation                     = 12,
    FileDispositionInformation               = 13,
    FilePositionInformation                  = 14,
    FileFullEaInformation                    = 15,
    FileModeInformation                      = 16,
    FileAlignmentInformation                 = 17,
    FileAllInformation                       = 18,
    FileAllocationInformation                = 19,
    FileEndOfFileInformation                 = 20,
    FileAlternateNameInformation             = 21,
    FileStreamInformation                    = 22,
    FilePipeInformation                      = 23,
    FilePipeLocalInformation                 = 24,
    FilePipeRemoteInformation                = 25,
    FileMailslotQueryInformation             = 26,
    FileMailslotSetInformation               = 27,
    FileCompressionInformation               = 28,
    FileObjectIdInformation                  = 29,
    FileCompletionInformation                = 30,
    FileMoveClusterInformation               = 31,
    FileQuotaInformation                     = 32,
    FileReparsePointInformation              = 33,
    FileNetworkOpenInformation               = 34,
    FileAttributeTagInformation              = 35,
    FileTrackingInformation                  = 36,
    FileIdBothDirectoryInformation           = 37,
    FileIdFullDirectoryInformation           = 38,
    FileValidDataLengthInformation           = 39,
    FileShortNameInformation                 = 40,
    FileIoCompletionNotificationInformation  = 41,
    FileIoStatusBlockRangeInformation        = 42,
    FileIoPriorityHintInformation            = 43,
    FileSfioReserveInformation               = 44,
    FileSfioVolumeInformation                = 45,
    FileHardLinkInformation                  = 46,
    FileProcessIdsUsingFileInformation       = 47,
    FileNormalizedNameInformation            = 48,
    FileNetworkPhysicalNameInformation       = 49,
    FileIdGlobalTxDirectoryInformation       = 50,
    FileIsRemoteDeviceInformation            = 51,
    FileUnusedInformation                    = 52,
    FileNumaNodeInformation                  = 53,
    FileStandardLinkInformation              = 54,
    FileRemoteProtocolInformation            = 55,
    FileRenameInformationBypassAccessCheck   = 56,
    FileLinkInformationBypassAccessCheck     = 57,
    FileVolumeNameInformation                = 58,
    FileIdInformation                        = 59,
    FileIdExtdDirectoryInformation           = 60,
    FileReplaceCompletionInformation         = 61,
    FileHardLinkFullIdInformation            = 62,
    FileIdExtdBothDirectoryInformation       = 63,
    FileDispositionInformationEx             = 64,
    FileRenameInformationEx                  = 65,
    FileRenameInformationExBypassAccessCheck = 66,
    FileDesiredStorageClassInformation       = 67,
    FileStatInformation                      = 68,
    FileMemoryPartitionInformation           = 69,
    FileStatLxInformation                    = 70,
    FileCaseSensitiveInformation             = 71,
    FileLinkInformationEx                    = 72,
    FileLinkInformationExBypassAccessCheck   = 73,
    FileStorageReserveIdInformation          = 74,
    FileCaseSensitiveInformationForceAccessCheck = 75,
    FileKnownFolderInformation               = 76,
    FileMaximumInformation                   = 77
} FILE_INFORMATION_CLASS;


typedef NTSTATUS (NTAPI* pfNtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

typedef VOID (NTAPI* PIO_APC_ROUTINE)(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
);

typedef NTSTATUS (NTAPI* pfNtWriteFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    );

typedef NTSTATUS (NTAPI* pfNtCreateSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    );

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;


typedef NTSTATUS (NTAPI* pfNtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation                   = 0,  // Returns PROCESS_BASIC_INFORMATION
    ProcessQuotaLimits                        = 1,
    ProcessIoCounters                         = 2,
    ProcessVmCounters                         = 3,
    ProcessTimes                              = 4,
    ProcessBasePriority                       = 5,
    ProcessRaisePriority                      = 6,
    ProcessDebugPort                          = 7,
    ProcessExceptionPort                      = 8,
    ProcessAccessToken                        = 9,
    ProcessLdtInformation                     = 10,
    ProcessLdtSize                            = 11,
    ProcessDefaultHardErrorMode               = 12,
    ProcessIoPortHandlers                     = 13, // kernel-mode only
    ProcessPooledUsageAndLimits               = 14,
    ProcessWorkingSetWatch                    = 15,
    ProcessUserModeIOPL                       = 16,
    ProcessEnableAlignmentFaultFixup          = 17,
    ProcessPriorityClass                      = 18,
    ProcessWx86Information                    = 19,
    ProcessHandleCount                        = 20,
    ProcessAffinityMask                       = 21,
    ProcessPriorityBoost                      = 22,
    ProcessDeviceMap                          = 23,
    ProcessSessionInformation                 = 24,
    ProcessForegroundInformation              = 25,
    ProcessWow64Information                   = 26, // returns WOW64 PEB
    ProcessImageFileName                      = 27, // returns UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled              = 28,
    ProcessBreakOnTermination                 = 29,
    ProcessDebugObjectHandle                  = 30,
    ProcessDebugFlags                         = 31,
    ProcessHandleTracing                      = 32,
    ProcessIoPriority                         = 33,
    ProcessExecuteFlags                       = 34,
    ProcessTlsInformation                     = 35,
    ProcessCookie                             = 36,
    ProcessImageInformation                   = 37,
    ProcessCycleTime                          = 38,
    ProcessPagePriority                       = 39,
    ProcessInstrumentationCallback            = 40,
    ProcessThreadStackAllocation              = 41,
    ProcessWorkingSetWatchEx                  = 42,
    ProcessImageFileNameWin32                 = 43,
    ProcessImageFileMapping                  = 44,
    ProcessAffinityUpdateMode                 = 45,
    ProcessMemoryAllocationMode               = 46,
    ProcessGroupInformation                   = 47,
    ProcessTokenVirtualizationEnabled         = 48,
    ProcessConsoleHostProcess                 = 49,
    ProcessWindowInformation                  = 50,
    ProcessHandleInformation                  = 51,
    ProcessMitigationPolicy                   = 52,
    ProcessDynamicFunctionTableInformation    = 53,
    ProcessHandleCheckingMode                 = 54,
    ProcessKeepAliveCount                     = 55,
    ProcessRevokeFileHandles                  = 56,
    ProcessWorkingSetControl                  = 57,
    ProcessHandleTable                        = 58,
    ProcessCheckStackExtentsMode              = 59,
    ProcessCommandLineInformation             = 60, // returns UNICODE_STRING
    ProcessProtectionInformation              = 61,
    ProcessMemoryExhaustion                   = 62,
    ProcessFaultInformation                   = 63,
    ProcessTelemetryIdInformation             = 64,
    ProcessCommitReleaseInformation           = 65,
    ProcessDefaultCpuSetsInformation          = 66,
    ProcessAllowedCpuSetsInformation          = 67,
    ProcessSubsystemProcess                   = 68,
    ProcessJobMemoryInformation               = 69,
    ProcessInPrivate                          = 70,
    ProcessRaiseUMExceptionOnInvalidHandle    = 71,
    ProcessIumChallengeResponse               = 72,
    ProcessChildProcessInformation            = 73,
    ProcessHighGraphicsPriorityInformation    = 74,
    ProcessSubsystemInformation               = 75,
    ProcessEnergyValues                       = 76,
    ProcessPowerThrottlingState               = 77,
    ProcessReserved3Information               = 78,
    ProcessWin32kSyscallFilterInformation     = 79,
    ProcessDisableSystemAllowedCpuSets        = 80,
    ProcessWakeInformation                    = 81,
    ProcessEnergyTrackingState                = 82,
    ProcessManageWritesToExecutableMemory     = 83,
    ProcessCaptureTrustletLiveDump            = 84,
    ProcessTelemetryCoverage                  = 85,
    ProcessEnclaveInformation                 = 86,
    ProcessEnableReadWriteVmLogging           = 87,
    ProcessUptimeInformation                  = 88,
    ProcessImageSection                       = 89,
    ProcessDebugAuthInformation               = 90,
    ProcessSystemResourceManagement           = 91,
    ProcessSequenceNumber                     = 92,
    ProcessLoaderDetour                       = 93,
    ProcessSecurityDomainInformation          = 94,
    ProcessCombineSecurityDomainsInformation  = 95,
    ProcessEnableLogging                      = 96,
    ProcessLeapSecondInformation              = 97,
    ProcessFiberShadowStackAllocation         = 98,
    ProcessFreeFiberShadowStackAllocation     = 99,
    ProcessAltSystemCallInformation           = 100,
    ProcessDynamicEHContinuationTargets       = 101,
    ProcessDynamicEnforcedCetCompatibleRanges = 102,
    ProcessCreateStateChange                  = 103,
    ProcessApplyStateChange                   = 104,
    ProcessEnableOptionalXStateFeatures       = 105,
    ProcessAltPrefetchParam                   = 106,
    ProcessAssignCpuPartitions                = 107,
    ProcessPriorityClassEx                    = 108,
    MaxProcessInfoClass                       // Always last
} PROCESSINFOCLASS;


typedef NTSTATUS (NTAPI* pfNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct _LDR_ARGUMENTS {
    CONTEXT ctx;
    PVOID entryPoint;
    PVOID ldrInitializeThunk; // Address of ntdll!LdrInitializeThunk in target process
} LDR_ARGUMENTS;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

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
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef NTSTATUS (NTAPI* pfRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags // use RTL_USER_PROC_PARAMS_NORMALIZED = 0x00000001
);


typedef NTSTATUS (NTAPI* pfNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI* pfNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead OPTIONAL
);

typedef NTSTATUS (NTAPI* pfNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten OPTIONAL
);

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

#define InitializeObjectAttributes(p, n, a, r, s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
(p)->RootDirectory = r;                         \
(p)->Attributes = a;                            \
(p)->ObjectName = n;                            \
(p)->SecurityDescriptor = s;                    \
(p)->SecurityQualityOfService = NULL;           \
}

#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _LOCAL_PROC_PARAMS_BUFFER {
    PRTL_USER_PROCESS_PARAMETERS Buffer;
    PVOID RawBuffer;
    SIZE_T BufferSize;
} LOCAL_PROC_PARAMS_BUFFER, *PLOCAL_PROC_PARAMS_BUFFER;

#endif //NTAPI_DEFS_H