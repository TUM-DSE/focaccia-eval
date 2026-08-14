.section .text
.global _start
.type _start, @function
_start:
    mov $1, %r8
    mov $0xedbf530a, %r9d
    pushq $1
    popfq
.global focaccia_trace_start
focaccia_trace_start:
    blsil %r9d, %r8d
.global focaccia_trace_stop
focaccia_trace_stop:
    pushfq
    pop %rdi
    and $0xff, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
