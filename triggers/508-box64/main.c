#include <stdint.h>

int main(void) {
    uint32_t destination = 0x12345678U;
    uint64_t accumulator = 0x1234567812345678UL;
    uint32_t replacement = 0x77777777U;

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "cmpxchgl %[replacement], %[destination]\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n"
        : [destination] "+c"(destination), [accumulator] "+a"(accumulator)
        : [replacement] "d"(replacement)
        : "cc");

    return 0;
}
