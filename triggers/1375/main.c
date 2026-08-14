#include <stdint.h>

int main(void) {
    const uint32_t left[4] __attribute__((aligned(16))) = {
        0xffffffffU,
        0x00000000U,
        0x7fffffffU,
        0x00000000U,
    };
    const uint32_t right[4] __attribute__((aligned(16))) = {
        0x7fffffffU,
        0x7fffffffU,
        0xaa46af1aU,
        0x2e711de7U,
    };
    uint32_t result[4] __attribute__((aligned(16)));

    __asm__ volatile(
        "movdqu (%[left]), %%xmm1\n\t"
        "movdqu (%[right]), %%xmm2\n\t"
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "addsubps %%xmm2, %%xmm1\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n\t"
        "movdqu %%xmm1, (%[result])\n\t"
        :
        : [left] "r"(left), [right] "r"(right), [result] "r"(result)
        : "xmm1", "xmm2", "memory", "cc");

    return result[0] == 0xffffffffU ? 0 : 1;
}
