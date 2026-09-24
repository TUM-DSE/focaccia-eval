.section .text
.global focaccia_trigger
.type focaccia_trigger, @function
focaccia_trigger:
    # XMM0 and RAX are caller-saved; no callee-saved register is modified.
    pxor %xmm0, %xmm0
.global focaccia_trace_start
focaccia_trace_start:
    .byte 0x66, 0x0f, 0xc2, 0xc0, 0xd1
.global focaccia_trace_stop
focaccia_trace_stop:
    xor %eax, %eax
    ret
.size focaccia_trigger, .-focaccia_trigger

.section .note.GNU-stack,"",@progbits
