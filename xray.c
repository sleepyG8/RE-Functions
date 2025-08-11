#include <windows.h>
#include <stdio.h>

/*
Sleepy - xray
Compile: cl /LD .\xray.c

Inject into a process and read the context right before a function is called

*/

#define DLL "api-ms-win-core-memory-l1-1-0.dll"
#define func "VirtualProtect"

// Set a console so it prints for GUI apps
void attach_console() {
  AllocConsole();

  FILE* f;
  freopen_s(&f, "CONOUT$", "w", stdout);
  freopen_s(&f, "CONOUT$", "w", stderr);
  freopen_s(&f, "CONIN$", "r", stdin);
}

BOOL getThreads(DWORD *threadId) {
    CONTEXT context;
    HANDLE hThread;

    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        printf("Error: Unable to open thread.\n");
        return FALSE;
    }

    //SuspendThread(hThread);
    context.ContextFlags = CONTEXT_FULL | CONTEXT_AMD64;
    //setting conetext can help avoid detection
    if (GetThreadContext(hThread, &context)) {
        context.Dr6 = 0;
        context.Dr0 = 0xDEADBEEF;
        context.Dr1 = 1;
        context.Dr2 = 0xDEADBEEF;
        context.Dr3 = 0xDEADBEEF;
        SetThreadContext(hThread, &context);

        printf("\033[35m+-----------Registers-----------+\033[0m\n");
        printf("RIP: 0x%016llX\n", context.Rip);
        printf("RAX: 0x%016llX\n", context.Rax);
        printf("RBX: 0x%016llX\n", context.Rbx);
        printf("RCX: 0x%016llX\n", context.Rcx);
        printf("RDX: 0x%016llX\n", context.Rdx);
        printf("RSI: 0x%016llX\n", context.Rsi);
        printf("RDI: 0x%016llX\n", context.Rdi);
        printf("RSP: 0x%016llX\n", context.Rsp);
        printf("RBP: 0x%016llX\n", context.Rbp);
        printf("R8 : 0x%016llX\n", context.R8);
        printf("R9 : 0x%016llX\n", context.R9);
        printf("R10: 0x%016llX\n", context.R10);
        printf("R11: 0x%016llX\n", context.R11);
        printf("R12: 0x%016llX\n", context.R12);
        printf("R13: 0x%016llX\n", context.R13);
        printf("R14: 0x%016llX\n", context.R14);
        printf("R15: 0x%016llX\n", context.R15);

        printf("EFlags: 0x%08X\n", context.EFlags);

        printf("CS: 0x%04X\n", context.SegCs);
        printf("DS: 0x%04X\n", context.SegDs);
        printf("ES: 0x%04X\n", context.SegEs);
        printf("FS: 0x%04X\n", context.SegFs);
        printf("GS: 0x%04X\n", context.SegGs);
        printf("SS: 0x%04X\n", context.SegSs);


    } else {
        printf("Error: Unable to get thread context. %lu\n", GetLastError());
        return FALSE;
    }

    //ResumeThread(hThread);

    CloseHandle(hThread);

    return TRUE;
}

FARPROC funcAddr;

FARPROC myHook() {

    attach_console();
   // Getting thread context using GetCurrentThreadId() inside hooked function
   if (!getThreads(GetCurrentThreadId())) {
    printf("error %lu\n", GetLastError());
   }

   //returning function address
    return funcAddr;
}

//DLL BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
int main() {


    BYTE* baseAddress = (BYTE*)GetModuleHandle("KERNEL32.Dll");
    if (baseAddress == NULL) {
        printf("Dll error\n");
        return FALSE;
    }
    // Read DOS header
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)baseAddress;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid PE file\n");
        return FALSE;
    }

    // Read NT headers
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
       printf("Invalid NT headers\n");
        return FALSE;
    }

    // Get Optional Header
    PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

    // Check for Import Table
    if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
       printf("No imports found\n");
        return FALSE;
    }

    // Locate Import Table
    PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    while (id->Name != 0 && id->OriginalFirstThunk != 0) {
        // Imported DLL names
        char* importName = (char*)((BYTE*)baseAddress + id->Name);

        if (strcmp(importName, DLL) == 0) {

        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->FirstThunk);
            
    while (origThunk->u1.AddressOfData != NULL) {
    
    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddress + origThunk->u1.AddressOfData);
        //Edit this string and replace VirtualProtect
    if (strcmp((char*)importByName->Name, func) == 0) {

        funcAddr = (FARPROC)thunkData->u1.Function;
        printf("Function Name: %s -> Address: %p\n", importByName->Name, funcAddr);

        DWORD oldProtect; 
        VirtualProtect(&thunkData->u1.Function, sizeof(FARPROC), PAGE_READWRITE, &oldProtect); 
        // Hook
        thunkData->u1.Function = (FARPROC)myHook; 

        // into the myHook function example
        VirtualProtect(&thunkData->u1.Function, sizeof(FARPROC), oldProtect, &oldProtect);

    }

    origThunk++;
    thunkData++;

}  

}

    id++;

}

    return TRUE;
}

