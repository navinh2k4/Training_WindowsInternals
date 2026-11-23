.data
    extern g_nt_query_syscall_addr : qword

.code

nt_query_virtual_memory_indirect proc
    mov r10, rcx
    mov eax, 23h
    jmp qword ptr [g_nt_query_syscall_addr]
    ret
nt_query_virtual_memory_indirect endp

end
