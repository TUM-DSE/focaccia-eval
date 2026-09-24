.section .text
.global focaccia_trigger
.type focaccia_trigger, @function
focaccia_trigger:
    # Only caller-saved registers are modified; RSP is balanced before return.
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
    pop %rax
    and $0xff, %eax
    ret
.size focaccia_trigger, .-focaccia_trigger

.section .note.GNU-stack,"",@progbits
