.section .text
.global _start
.type _start, @function
_start:
    movabs $0xa02e698e741f5a6a, %rax
    movabs $0x0020959ddd7a0aef, %rbx
.global focaccia_trace_start
focaccia_trace_start:
    lsl %bx, %ax
.global focaccia_trace_stop
focaccia_trace_stop:
    xor %edi, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
