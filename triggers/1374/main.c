#include <stdint.h>

int main(void) {
    const uint64_t source = 0x80000000ffffffffULL;
    const uint64_t index = 0x0b1aa9da2fe33fe3ULL;
    uint64_t result;
    unsigned char sign;

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "bzhiq %[index], %[source], %[result]\n\t"
        "sets %[sign]\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n"
        : [result] "=r"(result), [sign] "=qm"(sign)
        : [source] "r"(source), [index] "r"(index)
        : "cc");

    return result == source && sign == 1 ? 0 : 1;
}
