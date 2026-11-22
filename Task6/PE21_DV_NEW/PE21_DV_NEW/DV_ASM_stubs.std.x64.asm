.code

; Call NtCreateSection
NtCreateSectionProc proc
    mov r10, rcx
    mov eax, 4Ah          ; Syscall Number default of NtCreateSection downto Kernel
    syscall
    ret
NtCreateSectionProc endp

; Call NtMapViewOfSection 
NtMapViewOfSectionProc proc
    mov r10, rcx
    mov eax, 28h          ; Syscall Number default of NtMapViewOfSection downto Kernel
    syscall
    ret
NtMapViewOfSectionProc endp

; Call NtCreateThreadEx
NtCreateThreadExProc proc
    mov r10, rcx
    mov eax, 0C1h         ; Syscall Number default of NtCreateThreadEx downto Kernel
    syscall
    ret
NtCreateThreadExProc endp

end
