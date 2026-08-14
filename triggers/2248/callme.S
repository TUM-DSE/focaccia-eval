.section .text
.global callme
.type callme, %function
callme:
.global focaccia_trace_start
focaccia_trace_start:
    cmp x2, x3
    cset x12, lt
    and w11, w12, #0xff
    cmp w11, #0
    csetm x14, ne
    lsr x13, x14, x4
.global focaccia_expected_mismatch
focaccia_expected_mismatch:
    sxtb x0, w13
.global focaccia_trace_stop
focaccia_trace_stop:
    ret
.size callme, .-callme

.section .note.GNU-stack,"",%progbits
