#include <windows.h>
#include <ntsecapi.h>

#include "..\Common\Common.h"

#pragma comment(lib, "ntdll.lib")

void* MemoryCopy(void* dest, const void* src, size_t n) 
{
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;

    while (n--) {
        *d++ = *s++;
    }

    return dest;
}

#pragma optimize("", off)
void* MemorySet(void* ptr, int value, size_t num) 
{
    unsigned char* p = (unsigned char*)ptr;
    while (num--) {
        *p++ = (unsigned char)value;
    }
    return ptr;
}
#pragma optimize("", on)

char* IntegerToAscii(int value, char* str, int base) 
{
    if (base < 2 || base > 36) {
        // Unsupported base
        *str = '\0';
        return str;
    }

    char* ptr = str;
    char* end_ptr = str;
    BOOL is_negative = FALSE;

    // Handle negative numbers only if base is 10
    if (value < 0 && base == 10) {
        is_negative = TRUE;
        value = -value;
    }

    // Convert integer to string
    do {
        int remainder = value % base;
        *end_ptr++ = (remainder < 10) ? (remainder + '0') : (remainder - 10 + 'a');
    } while (value /= base);

    // Add negative sign if necessary
    if (is_negative) {
        *end_ptr++ = '-';
    }

    // Null-terminate the string
    *end_ptr = '\0';

    // Reverse the string
    char* start_ptr = str;
    end_ptr--;
    while (start_ptr < end_ptr) {
        char temp = *start_ptr;
        *start_ptr++ = *end_ptr;
        *end_ptr-- = temp;
    }

    return str;
}

char* UnsignedIntegerToAscii(unsigned int value, char* str, int base)
{
    if (base < 2 || base > 36) {
        // Unsupported base
        *str = '\0';
        return str;
    }

    char* ptr = str;
    char* end_ptr = str;

    // Convert integer to string
    do {
        int remainder = value % base;
        *end_ptr++ = (remainder < 10) ? (remainder + '0') : (remainder - 10 + 'a');
    } while (value /= base);

    // Null-terminate the string
    *end_ptr = '\0';

    // Reverse the string
    char* start_ptr = str;
    end_ptr--;
    while (start_ptr < end_ptr) {
        char temp = *start_ptr;
        *start_ptr++ = *end_ptr;
        *end_ptr-- = temp;
    }

    return str;
}

NTSTATUS WriteToFile(PCWSTR filePath, PVOID buffer, ULONG bufferSize) 
{
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle;
    NTSTATUS status;

    // Initialize the file name as a UNICODE_STRING
    RtlInitUnicodeString(&fileName, filePath);

    // Initialize object attributes
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Create or open the file
    status = NtCreateFile(&fileHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (status != STATUS_SUCCESS) {
        return status;  // Handle error
    }

    // Write the buffer to the file
    status = NtWriteFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        buffer,
        bufferSize,
        NULL,
        NULL);

    NtClose(fileHandle);
    return status;
}

void DebugLogStatus(LPCWSTR file, NTSTATUS status)
{
    char finalMessage[256];
    MemorySet(finalMessage, 0, sizeof(finalMessage));

    char msg[] = "Status: ";
    MemoryCopy(finalMessage, msg, sizeof(msg));

    char statusAscii[64];
    MemorySet(statusAscii, 0, sizeof(statusAscii));

    UnsignedIntegerToAscii(status, statusAscii, 10);
    MemoryCopy(finalMessage + sizeof(msg), statusAscii, sizeof(statusAscii));


    WriteToFile(file, finalMessage, sizeof(finalMessage));
}

HANDLE GetClientHandle(PSHARED_DATA data)
{
    HANDLE targetProcessHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)(unsigned long long)data->ClientProcessId;

    NTSTATUS status = NtOpenProcess(&targetProcessHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-open-client.txt", status);
        return INVALID_HANDLE_VALUE;
    }

    return targetProcessHandle;
}

void CommandOpenProcess(HANDLE client, PSHARED_DATA data)
{
    HANDLE targetHandleSelf;
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)(unsigned long long)data->OpenProcessData.ProcessId;

    NTSTATUS status = NtOpenProcess(&targetHandleSelf, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-open-process-open.txt", status);
        return;
    }

    status = NtDuplicateObject(NtCurrentProcess(), targetHandleSelf, client, &data->OpenProcessData.ProcessHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    if (status != STATUS_SUCCESS)
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-open-process-dup.txt", status);

    NtClose(targetHandleSelf);
    return;
}

void CommandOpenThread(HANDLE client, PSHARED_DATA data)
{
    HANDLE targetHandleSelf;
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID clientId;
    clientId.UniqueThread = (HANDLE)(unsigned long long)data->OpenThreadData.ThreadId;

    NTSTATUS status = NtOpenThread(&targetHandleSelf, THREAD_ALL_ACCESS, &objectAttributes, &clientId);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-open-thread-open.txt", status);
        return;
    }

    status = NtDuplicateObject(NtCurrentProcess(), targetHandleSelf, client, &data->OpenThreadData.ThreadHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    if (status != STATUS_SUCCESS)
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-open-thread-dup.txt", status);

    NtClose(targetHandleSelf);
    return;
}

PVOID AllocateMemory(SIZE_T size) 
{
    PVOID baseAddress = NULL;
    SIZE_T regionSize = size;
    NTSTATUS status;

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status == STATUS_SUCCESS)
        return baseAddress;
    
    return NULL;
}

void FreeMemory(PVOID baseAddress) 
{
    SIZE_T regionSize = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, MEM_RELEASE);
}

HANDLE CreateOwnTokenClone() 
{
    NTSTATUS status;
    HANDLE tokenHandle = NULL, newTokenHandle = NULL;
    TOKEN_USER* tokenUser = NULL;
    TOKEN_GROUPS* tokenGroups = NULL;
    TOKEN_PRIVILEGES* tokenPrivileges = NULL;
    TOKEN_OWNER* tokenOwner = NULL;
    TOKEN_PRIMARY_GROUP* tokenPrimaryGroup = NULL;
    TOKEN_DEFAULT_DACL* tokenDefaultDacl = NULL;
    TOKEN_SOURCE* tokenSource = NULL;
    ULONG returnLength = 0;
    OBJECT_ATTRIBUTES objectAttributes;
    LARGE_INTEGER expirationTime;

    // Open the current process token
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &tokenHandle);
    if (status != STATUS_SUCCESS) 
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-open-own.txt", status);
        goto cleanup;
    }

    // Query TOKEN_USER
    NtQueryInformationToken(tokenHandle, TokenUser, NULL, 0, &returnLength);
    tokenUser = (TOKEN_USER*)AllocateMemory(returnLength);
    status = NtQueryInformationToken(tokenHandle, TokenUser, tokenUser, returnLength, &returnLength);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-query-user.txt", status);
        goto cleanup;
    }

    // Query TOKEN_GROUPS
    NtQueryInformationToken(tokenHandle, TokenGroups, NULL, 0, &returnLength);
    tokenGroups = (TOKEN_GROUPS*)AllocateMemory(returnLength);
    status = NtQueryInformationToken(tokenHandle, TokenGroups, tokenGroups, returnLength, &returnLength);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-query-groups.txt", status);
        goto cleanup;
    }

    // Query TOKEN_PRIVILEGES
    NtQueryInformationToken(tokenHandle, TokenPrivileges, NULL, 0, &returnLength);
    tokenPrivileges = (TOKEN_PRIVILEGES*)AllocateMemory(returnLength);
    status = NtQueryInformationToken(tokenHandle, TokenPrivileges, tokenPrivileges, returnLength, &returnLength);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-query-privileges.txt", status);
        goto cleanup;
    }

    // Query TOKEN_OWNER
    NtQueryInformationToken(tokenHandle, TokenOwner, NULL, 0, &returnLength);
    tokenOwner = (TOKEN_OWNER*)AllocateMemory(returnLength);
    status = NtQueryInformationToken(tokenHandle, TokenOwner, tokenOwner, returnLength, &returnLength);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-query-owner.txt", status);
        goto cleanup;
    }

    // Query TOKEN_PRIMARY_GROUP
    NtQueryInformationToken(tokenHandle, TokenPrimaryGroup, NULL, 0, &returnLength);
    tokenPrimaryGroup = (TOKEN_PRIMARY_GROUP*)AllocateMemory(returnLength);
    status = NtQueryInformationToken(tokenHandle, TokenPrimaryGroup, tokenPrimaryGroup, returnLength, &returnLength);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-query-primary.txt", status);
        goto cleanup;
    }

    // Query TOKEN_DEFAULT_DACL
    NtQueryInformationToken(tokenHandle, TokenDefaultDacl, NULL, 0, &returnLength);
    tokenDefaultDacl = (TOKEN_DEFAULT_DACL*)AllocateMemory(returnLength);
    status = NtQueryInformationToken(tokenHandle, TokenDefaultDacl, tokenDefaultDacl, returnLength, &returnLength);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-query-dacl.txt", status);
        goto cleanup;
    }

    NtQueryInformationToken(tokenHandle, TokenSource, NULL, 0, &returnLength);
    tokenSource = (TOKEN_SOURCE*)AllocateMemory(returnLength);
    status = NtQueryInformationToken(tokenHandle, TokenSource, tokenSource, returnLength, &returnLength);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-query-source.txt", status);
        goto cleanup;
    }

    SECURITY_QUALITY_OF_SERVICE tempsqos;
    tempsqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    tempsqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    tempsqos.ImpersonationLevel = SecurityImpersonation;
    tempsqos.EffectiveOnly = FALSE;

    // Initialize the OBJECT_ATTRIBUTES structure
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, &tempsqos);

    // Create the new token
    status = NtCreateToken(&newTokenHandle, TOKEN_ALL_ACCESS, &objectAttributes, TokenPrimary, &tokenSource, &expirationTime, tokenUser, tokenGroups, tokenPrivileges, tokenOwner, tokenPrimaryGroup, tokenDefaultDacl, &tokenSource);
    if (status != STATUS_SUCCESS)
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-get-system-create-token.txt", status);

cleanup:
    if (tokenHandle) NtClose(tokenHandle);
    if (tokenUser) FreeMemory(tokenUser);
    if (tokenGroups) FreeMemory(tokenGroups);
    if (tokenPrivileges) FreeMemory(tokenPrivileges);
    if (tokenOwner) FreeMemory(tokenOwner);
    if (tokenPrimaryGroup) FreeMemory(tokenPrimaryGroup);
    if (tokenDefaultDacl) FreeMemory(tokenDefaultDacl);
    if (tokenSource) FreeMemory(tokenSource);

    return newTokenHandle;
}

void CommandSetThreadTokenSessionId(HANDLE client, PSHARED_DATA data)
{
    HANDLE targetHandleSelf;
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID clientId;
    clientId.UniqueThread = (HANDLE)(unsigned long long)data->SetThreadTokenSessionId.ThreadId;

    NTSTATUS status = NtOpenThread(&targetHandleSelf, THREAD_ALL_ACCESS, &objectAttributes, &clientId);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-set-thread-token-privilege-thread-open.txt", status);
        return;
    }

    HANDLE targetTokenHandle;
    status = NtOpenThreadToken(targetHandleSelf, TOKEN_ALL_ACCESS, TRUE, &targetTokenHandle);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-set-thread-token-privilege-token-open.txt", status);
        NtClose(targetHandleSelf);
        return;
    }

    DWORD sessionId = data->SetThreadTokenSessionId.SessionId;
    status = NtSetInformationToken(targetTokenHandle, TokenSessionId, &sessionId, sizeof(sessionId));
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-command-set-thread-token-privilege-set-token-info.txt", status);   
    }

    NtClose(targetTokenHandle);
    NtClose(targetHandleSelf);
}

void DispatchCommand(PSHARED_DATA data)
{
    HANDLE clientProcessHandle = GetClientHandle(data);

    if (clientProcessHandle != INVALID_HANDLE_VALUE)
    {
        switch (data->Command)
        {
        case EvitanCommandOpenProcess:
            CommandOpenProcess(clientProcessHandle, data);
            break;
        case EvitanCommandOpenThread:
            CommandOpenThread(clientProcessHandle, data);
            break;
        case EvitanCommandSetThreadTokenSessionId:
            CommandSetThreadTokenSessionId(clientProcessHandle, data);
            break;
        default:
            DebugLogStatus(L"\\??\\C:\\Temp\\evitan-unknown-command.txt", data->Command);
            return;
        }

        NtClose(clientProcessHandle);
    }

    data->ClientProcessId = 0;
}

void CreateDacl(PACL pDacl)
{
    SID_IDENTIFIER_AUTHORITY identifierAuthority = { 0 };
    identifierAuthority.Value[5] = 0x01; // SECURITY_WORLD_SID_AUTHORITY

    SID everyoneSid;
    MemorySet(&everyoneSid, 0, sizeof(SID));
    everyoneSid.Revision = SID_REVISION;
    everyoneSid.SubAuthorityCount = 1;
    everyoneSid.IdentifierAuthority = identifierAuthority;
    everyoneSid.SubAuthority[0] = SECURITY_WORLD_SID_SUBAUTHORITY;

    // Define DACL on the stack
    unsigned char daclBuffer[ACL_SIZE];
    MemorySet(daclBuffer, 0, ACL_SIZE);

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
    MemoryCopy(&pAce->SidStart, &everyoneSid, sizeof(SID));

    // Copy the stack-allocated DACL to the provided pointer
    MemoryCopy(pDacl, pStackDacl, ACL_SIZE);
}

void CreateBasicSecurityDescriptor(SECURITY_DESCRIPTOR* pSd, PACL pDacl)
{
    MemorySet(pSd, 0, sizeof(SECURITY_DESCRIPTOR));
    pSd->Revision = SECURITY_DESCRIPTOR_REVISION;
    pSd->Control = SE_DACL_PRESENT;
    pSd->Dacl = pDacl;
}

DWORD WaitForSharedData(HANDLE eventHandle, PSHARED_DATA sharedData)
{
    NTSTATUS status;

    // Wait for the signal that the process handle is ready
    status = NtWaitForSingleObject(eventHandle, FALSE, NULL);
    if (status != STATUS_SUCCESS) 
        return 0;

    // Return the process handle stored in shared memory
    return sharedData->ClientProcessId;
}

void EnablePrivileges()
{
    for (int i = 0; i < MAX_PRIVILEGE_ID; i++)
    {
        BOOL previousStatus;
        RtlAdjustPrivilege(i, TRUE, FALSE, &previousStatus);
    }
}

#pragma warning(push)
#pragma warning(disable : 6248)

void NTAPI NtProcessStartup(PPEB peb)
{
    // Draw the startup message
    UNICODE_STRING dbgMessage;
    RtlInitUnicodeString(&dbgMessage, L"Evitan activated");
    NtDrawText(&dbgMessage);

    EnablePrivileges();

    HANDLE eventHandle;
    HANDLE sectionHandle;
    PVOID sharedMemoryBase = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING eventName, sectionName;
    LARGE_INTEGER sectionSize;
    PSHARED_DATA sharedData;

    // Security descriptor for allowing access to user-mode processes
    SECURITY_DESCRIPTOR sd = { 0 };
    PSECURITY_DESCRIPTOR pSecurityDescriptor = &sd;

    unsigned char daclBuffer[ACL_SIZE];
    PACL pDacl = (PACL)daclBuffer;

    // Initialized the shared object access control
    CreateDacl(pDacl);
    CreateBasicSecurityDescriptor(pSecurityDescriptor, pDacl);

    RtlInitUnicodeString(&eventName, EVENT_NAME);
    InitializeObjectAttributes(&objAttr, &eventName, OBJ_CASE_INSENSITIVE, NULL, pSecurityDescriptor);

    // Sleep for a minute until the session manager initializes
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL * 60; // 1 minute delay
    NtDelayExecution(FALSE, &delay);

    // Create the sync event
    NTSTATUS status = NtCreateEvent(&eventHandle, EVENT_ALL_ACCESS, &objAttr, NotificationEvent, FALSE);
    if (status != STATUS_SUCCESS)
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-event.txt", status);
        NtTerminateProcess(NtCurrentProcess(), 1);
    }

    RtlInitUnicodeString(&sectionName, SECTION_NAME);
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, pSecurityDescriptor);

    // Set the size of the shared memory section
    sectionSize.QuadPart = sizeof(SHARED_DATA);

    // Create or open a named shared memory section
    status = NtCreateSection(
        &sectionHandle,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
        &objAttr,
        &sectionSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL
    );
    if (status != STATUS_SUCCESS) 
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-section.txt", status);
        NtClose(eventHandle);
        NtTerminateProcess(NtCurrentProcess(), 2);
    }

    // Map the section into the address space of the current process
    status = NtMapViewOfSection(
        sectionHandle,
        NtCurrentProcess(),
        &sharedMemoryBase,
        0,
        0,
        NULL,
        (PSIZE_T)&sectionSize,
        ViewShare,
        0,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) 
    {
        DebugLogStatus(L"\\??\\C:\\Temp\\evitan-map.txt", status);
        NtClose(sectionHandle);
        NtClose(eventHandle);
        NtTerminateProcess(NtCurrentProcess(), 3);
    }

    sharedData = (PSHARED_DATA)sharedMemoryBase;

    while (TRUE) 
    {
        // Wait for another process to signal and provide its process handle
        DWORD clientProcessId = WaitForSharedData(eventHandle, sharedData);
        if (clientProcessId != 0)
            DispatchCommand(sharedData);
        else
            DebugLogStatus(L"\\??\\C:\\Temp\\evitan-null-client.txt", 0);

        NtClearEvent(eventHandle);
    }

    // Cleanup
    NtUnmapViewOfSection(NtCurrentProcess(), sharedMemoryBase);
    NtClose(sectionHandle);
    NtClose(eventHandle);

    NtTerminateProcess(NtCurrentProcess(), 0);
}

#pragma warning(pop)