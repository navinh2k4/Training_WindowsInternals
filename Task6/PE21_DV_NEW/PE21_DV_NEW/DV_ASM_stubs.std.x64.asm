.code

; Cong goi truc tiep NtCreateSection
NtCreateSectionProc proc
    mov r10, rcx
    mov eax, 4Ah          ; Syscall Number Mac dinh cua NtCreateSection xuong Kernel
    syscall
    ret
NtCreateSectionProc endp

; Cong goi truc tiep NtMapViewOfSection (Da fix dong bo ten ham Flat)
NtMapViewOfSectionProc proc
    mov r10, rcx
    mov eax, 28h          ; Syscall Number Mac dinh cua NtMapViewOfSection xuong Kernel
    syscall
    ret
NtMapViewOfSectionProc endp

; Cong goi truc tiep NtCreateThreadEx
NtCreateThreadExProc proc
    mov r10, rcx
    mov eax, 0C1h         ; Syscall Number Mac dinh cua NtCreateThreadEx xuong Kernel
    syscall
    ret
NtCreateThreadExProc endp

end