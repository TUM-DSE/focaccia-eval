#include <stdint.h>

int main(void) {
    uint64_t result;
    unsigned char carry;

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "movabsq $0x065b2e276ad27c67, %%rax\n\t"
        "movabsq $0x62f34955226b2b5d, %%rbx\n\t"
        "cmpl $0, %%eax\n\t"
        "blsmskl %%ebx, %%eax\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n\t"
        "setc %[carry]\n"
        : "=a"(result), [carry] "=m"(carry)
        :
        : "rbx", "cc");

    return result == 1 && carry == 0 ? 0 : 71;
}
