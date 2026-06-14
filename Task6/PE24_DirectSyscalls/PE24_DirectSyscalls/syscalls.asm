.code

; Dinh nghia cong Syscall truc tiep cho ham NtAllocateVirtualMemory
NtAllocateVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 18h          ; Syscall Number mac dinh cua NtAllocateVirtualMemory
    syscall
    ret
NtAllocateVirtualMemoryProc endp

; Dinh nghia cong Syscall truc tiep cho ham NtWriteVirtualMemory
NtWriteVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 3Ah          ; Syscall Number mac dinh cua NtWriteVirtualMemory
    syscall
    ret
NtWriteVirtualMemoryProc endp

end