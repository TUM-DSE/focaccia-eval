#include <stdint.h>

int main(void) {
    int memory = 0x12345678;
    unsigned long accumulator = 0x1234567812345678UL;
    int replacement = 0x77777777;

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "cmpxchgl %[replacement], %[memory]\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n"
        : [memory] "+m"(memory), [accumulator] "+a"(accumulator)
        : [replacement] "r"(replacement)
        : "cc", "memory");

    return accumulator == 0x1234567812345678UL && memory == replacement ? 0 : 1;
}
