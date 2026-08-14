#include <stdint.h>
#include <string.h>

int main(void) {
    const uint8_t source[32] __attribute__((aligned(32))) = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    uint8_t destination[32] __attribute__((aligned(32))) = {0};

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "vmovdqu (%[source]), %%ymm0\n\t"
        "vmovdqu %%ymm0, (%[destination])\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n\t"
        "vzeroupper\n\t"
        :
        : [source] "r"(source), [destination] "r"(destination)
        : "ymm0", "memory");

    return memcmp(source, destination, sizeof(source)) == 0 ? 0 : 1;
}
