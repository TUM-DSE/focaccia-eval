#include <stdint.h>

int main(void) {
    const int64_t value = INT64_C(0x11111111deadbeef);
    int64_t result;
    const int64_t *one_past = &value + 1;

    __asm__ volatile(
        "mov x1, %[address]\n\t"
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "ldapur x0, [x1, #-8]\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n\t"
        "mov %[result], x0\n\t"
        : [result] "=r"(result)
        : [address] "r"(one_past)
        : "x0", "x1", "memory");

    return result == value ? 0 : 1;
}
