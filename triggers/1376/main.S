.section .text
.global focaccia_trigger
.type focaccia_trigger, @function
focaccia_trigger:
    # RBX is callee-saved; preserve it while retaining the original LSL inputs.
    push %rbx
    movabs $0xa02e698e741f5a6a, %rax
    movabs $0x0020959ddd7a0aef, %rbx
.global focaccia_trace_start
focaccia_trace_start:
    lsl %bx, %ax
.global focaccia_trace_stop
focaccia_trace_stop:
    xor %eax, %eax
    pop %rbx
    ret
.size focaccia_trigger, .-focaccia_trigger

.section .note.GNU-stack,"",@progbits
