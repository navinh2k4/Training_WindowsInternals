.data
    extern g_NtAllocateSyscallAddr : qword
    extern g_NtWriteSyscallAddr    : qword

.code

; Cong goi gian tiep NtAllocateVirtualMemory
NtAllocateVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 18h                              ; SSN mac dinh cua NtAllocateVirtualMemory
    jmp qword ptr [g_NtAllocateSyscallAddr]  ; Nhay gian tiep sang byte syscall xin trong ntdll
    ret
NtAllocateVirtualMemoryProc endp

; Cong goi gian tiep NtWriteVirtualMemory
NtWriteVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 3Ah                              ; SSN mac dinh cua NtWriteVirtualMemory
    jmp qword ptr [g_NtWriteSyscallAddr]     ; Nhay gian tiep sang byte syscall xin trong ntdll
    ret
NtWriteVirtualMemoryProc endp

end