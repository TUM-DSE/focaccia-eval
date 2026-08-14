#include <stdint.h>

int main(void) {
    int8_t memory = 3;
    const int8_t input = -1;
    uint32_t old_value;

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "ldsmaxb %w[input], %w[old_value], [%[address]]\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n"
        : [old_value] "=&r"(old_value), [memory] "+m"(memory)
        : [input] "r"((int32_t)input), [address] "r"(&memory)
        : "memory", "cc");

    return old_value == 3 && memory == 3 ? 0 : 1;
}
