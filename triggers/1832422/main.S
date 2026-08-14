.section .text
.global _start
.type _start, @function
_start:
    pxor %xmm0, %xmm0
.global focaccia_trace_start
focaccia_trace_start:
    .byte 0x66, 0x0f, 0xc2, 0xc0, 0xd1
.global focaccia_trace_stop
focaccia_trace_stop:
    xor %edi, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
