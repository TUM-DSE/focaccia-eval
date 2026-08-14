#include <stdint.h>

int main(void) {
    uint64_t result;

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "movabsq $0x017b3693f77fb6e9, %%rax\n\t"
        "movabsq $0x8f635a775ad3b9b4, %%rbx\n\t"
        "movabsq $0xb717b75da9983018, %%rcx\n\t"
        "bextrl %%ecx, %%ebx, %%eax\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n"
        : "=a"(result)
        :
        : "rbx", "rcx", "cc");

    return result == 0x5aU ? 0 : 72;
}
