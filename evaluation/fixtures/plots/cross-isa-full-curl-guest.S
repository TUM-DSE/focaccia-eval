.text
.globl _start
_start:
    mov $1, %r8d
    mov $0xffffffff, %r9d
.globl focaccia_injection_curl_2175
focaccia_injection_curl_2175:
    blsi %r9d, %r8d
.globl focaccia_trace_stop_curl
focaccia_trace_stop_curl:
    nop
    hlt
