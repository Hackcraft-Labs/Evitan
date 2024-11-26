#pragma once

#include <Windows.h>

// Object Names
#define EVENT_NAME L"\\BaseNamedObjects\\EvitanEvent5"
//#define EVENT_NAME L"\\Sessions\\0\\BaseNamedObjects\\EvitanEvent5"
#define SECTION_NAME L"\\Sessions\\1\\BaseNamedObjects\\EvitanSharedSection5"

// Constants
#define SECURITY_WORLD_SID_SUBAUTHORITY 0x00000000L

#define ACL_SIZE (sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sizeof(SID))
#define SECURITY_DESCRIPTOR_SIZE (sizeof(SECURITY_DESCRIPTOR))

#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

#define STATUS_BUFFER_TOO_SMALL 0xC0000023

// Structure for shared memory data
typedef enum _EVITAN_COMMAND
{
    EvitanCommandOpenProcess,
    EvitanCommandOpenThread,
    EvitanCommandGetSystem,
    EvitanCommandSetThreadTokenSessionId
} EVITAN_COMMAND, * PEVITAN_COMMAND;

typedef struct _EVITAN_COMMAND_OPEN_PROCESS_SHARED_DATA 
{
    DWORD ProcessId;
    HANDLE ProcessHandle;
} EVITAN_COMMAND_OPEN_PROCESS_SHARED_DATA, * PEVITAN_COMMAND_OPEN_PROCESS_SHARED_DATA;

typedef struct _EVITAN_COMMAND_OPEN_THREAD_SHARED_DATA 
{
    DWORD ThreadId;
    HANDLE ThreadHandle;
} EVITAN_COMMAND_OPEN_THREAD_SHARED_DATA, * PEVITAN_COMMAND_OPEN_THREAD_SHARED_DATA;

typedef struct _EVITAN_COMMAND_SET_THREAD_TOKEN_SESSIONID_DATA
{
    DWORD ThreadId;
    DWORD SessionId;
} EVITAN_COMMAND_SET_THREAD_TOKEN_SESSIONID_DATA, * PEVITAN_COMMAND_SET_THREAD_TOKEN_SESSIONID_DATA;

typedef struct _SHARED_DATA 
{
    EVITAN_COMMAND Command;
    DWORD ClientProcessId;
    union 
    {
        EVITAN_COMMAND_OPEN_PROCESS_SHARED_DATA OpenProcessData;
        EVITAN_COMMAND_OPEN_THREAD_SHARED_DATA OpenThreadData;
        EVITAN_COMMAND_SET_THREAD_TOKEN_SESSIONID_DATA SetThreadTokenSessionId;
    };
} SHARED_DATA, * PSHARED_DATA;

// Extended Definitions
#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define NtCurrentProcess() (HANDLE)-1
#define STATUS_SUCCESS     ((NTSTATUS)0x00000000L)

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x1
#define PS_ATTRIBUTE_IMAGE_NAME 0x20005;

#define MAX_PRIVILEGE_ID 35

typedef enum _PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

// Extended Structures
typedef VOID (NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[ANYSIZE_ARRAY];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    PS_CREATE_STATE State;
    union {
        // PsCreateInitialState
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct {
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS 
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
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA 
{
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB 
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;

typedef enum _FULL_PROCESS_INFORMATION_CLASS 
{
    FullProcessBasicInformation,
    FullProcessQuotaLimits,
    FullProcessIoCounters,
    FullProcessVmCounters,
    FullProcessTimes,
    FullProcessBasePriority,
    FullProcessRaisePriority,
    FullProcessDebugPort,
    FullProcessExceptionPort,
    FullProcessAccessToken,
    FullProcessLdtInformation,
    FullProcessLdtSize,
    FullProcessDefaultHardErrorMode,
    FullProcessIoPortHandlers,
    FullProcessPooledUsageAndLimits,
    FullProcessWorkingSetWatch,
    FullProcessUserModeIOPL,
    FullProcessEnableAlignmentFaultFixup,
    FullProcessPriorityClass,
    FullProcessWx86Information,
    FullProcessHandleCount,
    FullProcessAffinityMask,
    FullProcessPriorityBoost,
    FullMaxProcessInfoClass
} FULL_PROCESS_INFORMATION_CLASS, * PFULL_PROCESS_INFORMATION_CLASS;

typedef enum _FULL_THREADINFOCLASS
{
    FullThreadBasicInformation,
    FullThreadTimes,
    FullThreadPriority,
    FullThreadBasePriority,
    FullThreadAffinityMask,
    FullThreadImpersonationToken,
    FullThreadDescriptorTableEntry,
    FullThreadEnableAlignmentFaultFixup,
    FullThreadEventPair,
    FullThreadQuerySetWin32StartAddress,
    FullThreadUnknown,
    FullThreadZeroTlsCell,
    FullThreadPerformanceCount,
    FullThreadAmILastThread,
    FullThreadIdealProcessor,
    FullThreadPriorityBoost,
    FullThreadSetTlsArrayAddress,
    FullThreadIsIoPending,
    FullThreadHideFromDebugger,
    FullThreadBreakOnTermination,
    FullThreadSwitchLegacyState,
    FullThreadIsTerminated,
    FullThreadLastSystemCall,
    FullThreadIoPriority,
    FullThreadCycleTime,
    FullThreadPagePriority,
    FullThreadActualBasePriority,
    FullThreadTebInformation,
    FullThreadCSwitchMon,
    FullThreadCSwitchPmu,
    FullThreadWow64Context,
    FullThreadGroupInformation,
    FullThreadUmsInformation,
    FullThreadCounterProfiling,
    FullThreadIdealProcessorEx,
    FullThreadCpuAccountingInformation,
    FullThreadSuspendCount,
    FullThreadHeterogeneousCpuPolicy,
    FullThreadContainerId,
    FullThreadNameInformation,
    FullThreadSelectedCpuSets,
    FullThreadSystemThreadInformation,
    FullThreadActualGroupAffinity,
    FullMaxThreadInfoClass
} FULL_THREADINFOCLASS, * PFULL_THREADINFOCLASS;

typedef enum _FULL_TOKEN_INFORMATION_CLASS
{
    FullTokenUser = 1,
    FullTokenGroups,
    FullTokenPrivileges,
    FullTokenOwner,
    FullTokenPrimaryGroup,
    FullTokenDefaultDacl,
    FullTokenSource,
    FullTokenType,
    FullTokenImpersonationLevel,
    FullTokenStatistics,
    FullTokenRestrictedSids,
    FullTokenSessionId,
    FullTokenGroupsAndPrivileges,
    FullTokenSessionReference,
    FullTokenSandBoxInert,
    FullTokenAuditPolicy,
    FullTokenOrigin,
    FullTokenElevationType,
    FullTokenLinkedToken,
    FullTokenElevation,
    FullTokenHasRestrictions,
    FullTokenAccessInformation,
    FullTokenVirtualizationAllowed,
    FullTokenVirtualizationEnabled,
    FullTokenIntegrityLevel,
    FullTokenUIAccess,
    FullTokenMandatoryPolicy,
    FullTokenLogonSid,
    FullTokenIsAppContainer,
    FullTokenCapabilities,
    FullTokenAppContainerSid,
    FullTokenAppContainerNumber,
    FullTokenUserClaimAttributes,
    FullTokenDeviceClaimAttributes,
    FullTokenRestrictedUserClaimAttributes,
    FullTokenRestrictedDeviceClaimAttributes,
    FullTokenDeviceGroups,
    FullTokenRestrictedDeviceGroups,
    FullTokenSecurityAttributes,
    FullTokenIsRestricted,
    FullTokenProcessTrustLevel,
    FullTokenPrivateNameSpace,
    FullTokenSingletonAttributes,
    FullTokenBnoIsolation,
    FullTokenChildProcessFlags,
    FullTokenIsLessPrivilegedAppContainer,
    FullTokenIsSandboxed,
    FullTokenIsAppSilo,
    FullTokenLoggingInformation,
    FullMaxTokenInfoClass
} FULL_TOKEN_INFORMATION_CLASS, * PFULL_TOKEN_INFORMATION_CLASS;

typedef struct _PROCESS_ACCESS_TOKEN 
{
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, * PPROCESS_ACCESS_TOKEN;

typedef struct _OBJECT_ATTRIBUTES 
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT 
{
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _EVENT_TYPE 
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef struct _IO_STATUS_BLOCK 
{
    union 
    {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Length;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    //SECTION_IMAGE_INFORMATION ImageInformation;
    BYTE reserved[64];
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

// Function prototypes (imported from ntdll)
extern NTSYSAPI NTSTATUS NTAPI RtlCreateUserProcess(
    __in PUNICODE_STRING NtImagePathName,
    __in ULONG Attributes,
    __in PVOID ProcessParameters,
    __in_opt PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    __in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    __in_opt HANDLE ParentProcess,
    __in BOOLEAN InheritHandles,
    __in_opt HANDLE DebugPort,
    __in_opt HANDLE TokenHandle,
    __out PRTL_USER_PROCESS_INFORMATION ProcessInformation);

extern NTSYSAPI NTSTATUS NTAPI RtlCreateProcessParameters(
    __deref_out PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    __in PUNICODE_STRING ImagePathName,
    __in_opt PUNICODE_STRING DllPath,
    __in_opt PUNICODE_STRING CurrentDirectory,
    __in_opt PUNICODE_STRING CommandLine,
    __in_opt PVOID Environment,
    __in_opt PUNICODE_STRING WindowTitle,
    __in_opt PUNICODE_STRING DesktopInfo,
    __in_opt PUNICODE_STRING ShellInfo,
    __in_opt PUNICODE_STRING RuntimeData
);

extern NTSYSAPI NTSTATUS NTAPI
RtlCreateProcessParametersEx(
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags
);

extern NTSYSAPI NTSTATUS NTAPI RtlDestroyProcessParameters(
    _In_ _Post_invalid_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
);

extern NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege(
    ULONG Privilege,
    BOOL Enable,
    BOOL CurrentThread,
    PBOOL PreviousStatus
);

extern NTSYSAPI LUID NTAPI RtlConvertLongToLuid(
    LONG Long
);

extern PVOID RtlAllocateHeap(
    PVOID  HeapHandle,
    ULONG  Flags,
    SIZE_T Size
);

extern BOOL RtlFreeHeap(
    PVOID HeapHandle,
    ULONG Flags,
    PVOID BaseAddress
);

extern PVOID RtlProcessHeap();

extern NTSYSAPI NTSTATUS NTAPI NtResumeThread(
    IN HANDLE ThreadHandle,
    OUT PULONG SuspendCount
);

extern NTSYSAPI NTSTATUS NTAPI NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_ PPS_ATTRIBUTE_LIST AttributeList
);



extern NTSYSAPI NTSTATUS NTAPI NtCreateEvent(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState
);

extern NTSYSAPI NTSTATUS NTAPI NtSetEvent(
    IN HANDLE EventHandle,
    OUT PLONG PreviousState OPTIONAL
);

extern NTSYSAPI NTSTATUS NTAPI NtOpenEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern NTSYSAPI NTSTATUS NTAPI NtClearEvent(
    IN HANDLE EventHandle
);

extern NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL
);

extern NTSYSAPI NTSTATUS NTAPI NtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

extern NTSYSAPI NTSTATUS NTAPI NtOpenThread(
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

extern NTSYSAPI NTSTATUS NTAPI NtAllocateLocallyUniqueId(
    OUT PLUID LocallyUniqueId
);

extern NTSYSAPI NTSTATUS NTAPI NtCreateToken(
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TOKEN_TYPE TokenType,
    PSID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER User,
    PTOKEN_GROUPS Groups,
    PTOKEN_PRIVILEGES Privileges,
    PTOKEN_OWNER Owner,
    PTOKEN_PRIMARY_GROUP PrimaryGroup,
    PTOKEN_DEFAULT_DACL DefaultDacl,
    PVOID Source
);

extern NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle
);

extern NTSYSAPI NTSTATUS NTAPI NtOpenThreadToken(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    OUT PHANDLE TokenHandle
);

extern NTSYSAPI NTSTATUS NTAPI NtDuplicateToken(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle
);

extern NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN BOOLEAN InheritHandle,
    IN ULONG Options
);

extern NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PULONG ReturnLength
);

extern NTSYSAPI NTSTATUS NTAPI NtSetInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
);

extern NTSYSAPI NTSTATUS NTAPI NtSetInformationThread(
    HANDLE ThreadHandle,
    FULL_THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

extern NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationToken(
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID TokenInformation,
    IN ULONG TokenInformationLength,
    OUT PULONG ReturnLength
);

extern NTSYSAPI NTSTATUS NTAPI NtSetInformationToken(
    HANDLE TokenHandle,
    FULL_TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength
);

extern NTSYSAPI NTSTATUS NTAPI NtSuspendProcess(
    HANDLE ProcessHandle
);

extern NTSYSAPI NTSTATUS NTAPI NtResumeProcess(
    HANDLE ProcessHandle
);

extern NTSYSAPI NTSTATUS NTAPI NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

extern NTSYSAPI NTSTATUS NTAPI NtOpenSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
);

extern NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
);

extern NTSYSAPI NTSTATUS NTAPI NtClose(
    IN HANDLE Handle
);

extern NTSYSAPI VOID NTAPI RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

extern NTSYSAPI NTSTATUS NTAPI NtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval 
);

extern NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(
    IN HANDLE ProcessHandle,
    IN NTSTATUS ExitCode
);

extern NTSYSAPI NTSTATUS NTAPI NtDrawText(_In_ PUNICODE_STRING Text);

extern NTSYSAPI NTSTATUS NTAPI NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

extern NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef
VOID
(NTAPI* PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

extern NTSYSAPI NTSTATUS NTAPI NtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,              // optional
    void*           ApcRoutine,          // optional
    PVOID            ApcContext,         // optional
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,         // optional
    PULONG           Key                 // optional
);

// Security Structure Definitions
typedef struct _CUSTOM_SECURITY_DESCRIPTOR 
{
    UCHAR Revision;
    UCHAR Sbz1;
    USHORT Control;
    PVOID Owner;
    PVOID Group;
    PVOID Sacl;
    PVOID Dacl;
} CUSTOM_SECURITY_DESCRIPTOR, *PCUSTOM_SECURITY_DESCRIPTOR;

typedef struct _CUSTOM_ACL 
{
    UCHAR AclRevision;
    UCHAR Sbz1;
    USHORT AclSize;
    USHORT AceCount;
    USHORT Sbz2;
} CUSTOM_ACL, *PCUSTOM_ACL;

typedef struct _CUSTOM_ACCESS_ALLOWED_ACE 
{
    UCHAR  AceType;
    UCHAR  AceFlags;
    USHORT AceSize;
    unsigned long Mask;
    unsigned long SidStart;
} CUSTOM_ACCESS_ALLOWED_ACE, *PCUSTOM_ACCESS_ALLOWED_ACE;

typedef struct _CUSTOM_SID 
{
    UCHAR  Revision;
    UCHAR  SubAuthorityCount;
    USHORT IdentifierAuthority;
    ULONG  SubAuthority[1];
} CUSTOM_SID, *PCUSTOM_SID;