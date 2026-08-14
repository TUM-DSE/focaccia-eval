.section .text
.global _start
.type _start, @function
_start:
    mov %rsp, %r12
    stc
.global focaccia_trace_start
focaccia_trace_start:
    .byte 0x40, 0x9f
.global focaccia_trace_stop
focaccia_trace_stop:
    cmp %r12, %rsp
    setne %dil
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
