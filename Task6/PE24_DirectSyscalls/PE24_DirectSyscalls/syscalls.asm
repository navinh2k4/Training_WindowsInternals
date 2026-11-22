
.code

nt_query_virtual_memory_stub proc
    mov r10, rcx
    mov eax, 23h
    syscall
    ret
nt_query_virtual_memory_stub endp

end
